"""Isolated database tests; DNS/scanning are controlled substitutes, never real targets."""
import os
import sys
import unittest
import uuid
from pathlib import Path
from datetime import timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'api'), str(ROOT/'shared'), str(ROOT/'worker')]
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///:memory:'
os.environ['REDIS_URL'] = 'redis://127.0.0.1:6379/0'
with patch('sqlalchemy.ext.asyncio.create_async_engine', return_value=MagicMock()):
    from app.main import app
    from worker import main as worker
from app.database import get_db
from app.auth import token_digest
from app import scheduler
from app.routes import scans
from shared.models import Base, Domain, User, AuthSession, Scan, ScanStatus, ScanSchedule
from shared.time_utils import database_utc

class ScheduleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine('sqlite+aiosqlite:///:memory:')
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self.now = database_utc()
        async with self.sessions() as db:
            user = User(username='schedule-owner', password_hash='unused')
            other = User(username='other', password_hash='unused')
            db.add_all([user, other]); await db.flush()
            self.owner = user.id
            domain = Domain(name='owned.example', owner_id=user.id, verified=True, verification_token='test')
            db.add(domain); await db.flush(); self.domain = domain.id
            for token, account in [('A'*43, user), ('B'*43, other)]:
                db.add(AuthSession(token_hash=token_digest(token), user_id=account.id,
                                   expires_at=self.now+timedelta(hours=1)))
            await db.commit()
        async def database():
            async with self.sessions() as db: yield db
        app.dependency_overrides[get_db] = database
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test')
        self.headers = {'Authorization': 'Bearer '+'A'*43}
        self.path = '/schedules/'+str(self.domain)

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await self.client.aclose(); await self.engine.dispose()

    async def due(self):
        async with self.sessions() as db:
            db.add(ScanSchedule(domain_id=self.domain, owner_id=self.owner, enabled=True,
                interval_minutes=60, next_run_at=self.now-timedelta(hours=4)))
            await db.commit()

    async def count(self):
        async with self.sessions() as db:
            return await db.scalar(select(func.count()).select_from(Scan))

    async def test_auth_scope_validation_and_disable(self):
        body = {'enabled': True, 'interval_minutes': 60}
        for method in ['get', 'put']:
            kwargs = {'json': body} if method == 'put' else {}
            self.assertEqual((await getattr(self.client, method)(self.path, **kwargs)).status_code, 401)
            self.assertEqual((await getattr(self.client, method)(self.path,
                headers={'Authorization':'Bearer '+'B'*43}, **kwargs)).status_code, 404)
        for value in [0, 59, 43201, 60.5, '60']:
            self.assertEqual((await self.client.put(self.path, headers=self.headers,
                json=dict(body, interval_minutes=value))).status_code, 422)
        response = await self.client.put(self.path, headers=self.headers, json=body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()['next_run_at'].endswith(('Z', '+00:00')))
        self.assertEqual((await self.client.get(self.path, headers=self.headers)).status_code, 200)
        await self.client.put(self.path, headers=self.headers, json=dict(body, enabled=False))
        with patch.object(scheduler, 'ownership_matches', AsyncMock()) as dns:
            await scheduler.dispatch_due(self.sessions, self.now+timedelta(days=1))
            dns.assert_not_awaited()
        self.assertEqual(await self.count(), 0)

    async def test_due_retry_coalescing_and_manual_duplicate(self):
        await self.due()
        with patch.object(scheduler, 'ownership_matches', AsyncMock(return_value=True)):
            await scheduler.dispatch_due(self.sessions, self.now)
            await scheduler.dispatch_due(self.sessions, self.now)
        self.assertEqual(await self.count(), 1)
        with patch.object(scans, 'ownership_matches', AsyncMock(return_value=True)), patch.object(scans.redis_client, 'rpush', AsyncMock()) as redis:
            response = await self.client.post('/scans/'+str(self.domain), headers=self.headers)
            self.assertEqual(response.status_code, 200)
            redis.assert_not_awaited()
        with patch.object(scheduler, 'ownership_matches', AsyncMock(return_value=True)):
            await scheduler.dispatch_due(self.sessions, self.now+timedelta(hours=2))
        self.assertEqual(await self.count(), 1)
        async with self.sessions() as db:
            s = await db.get(ScanSchedule, self.domain)
            self.assertEqual(s.last_outcome, 'skipped: scan already active')

    async def test_dns_failure_retries_and_revocation_disables(self):
        await self.due()
        with patch.object(scheduler, 'ownership_matches', AsyncMock(side_effect=TimeoutError)):
            await scheduler.dispatch_due(self.sessions, self.now)
        self.assertEqual(await self.count(), 0)
        async with self.sessions() as db:
            s = await db.get(ScanSchedule, self.domain)
            self.assertEqual(s.next_run_at, self.now+timedelta(minutes=5))
        with patch.object(scheduler, 'ownership_matches', AsyncMock(return_value=False)):
            await scheduler.dispatch_due(self.sessions, self.now+timedelta(minutes=5))
        async with self.sessions() as db:
            self.assertFalse((await db.get(ScanSchedule, self.domain)).enabled)
            self.assertFalse((await db.get(Domain, self.domain)).verified)
        self.assertEqual(await self.count(), 0)

    async def test_unassigned_inactive_unverified_and_changed_owner_rejected(self):
        await self.due()
        for case in ['unassigned', 'inactive', 'unverified', 'changed']:
            async with self.sessions() as db:
                d = await db.get(Domain, self.domain); u = await db.get(User, self.owner)
                s = await db.get(ScanSchedule, self.domain)
                d.owner_id = self.owner; d.verified = True; u.active = True
                s.enabled = True; s.next_run_at = self.now
                if case == 'unassigned': d.owner_id = None
                if case == 'inactive': u.active = False
                if case == 'unverified': d.verified = False
                if case == 'changed': s.owner_id = uuid.uuid4()
                else: s.owner_id = self.owner
                await db.commit()
            with patch.object(scheduler, 'ownership_matches', AsyncMock()) as dns:
                await scheduler.dispatch_due(self.sessions, self.now)
                dns.assert_not_awaited()
            self.assertEqual(await self.count(), 0)

    async def test_worker_recovery_and_history_without_redis(self):
        await self.due()
        with patch.object(scheduler, 'ownership_matches', AsyncMock(return_value=True)):
            await scheduler.dispatch_due(self.sessions, self.now)
        results = dict(subdomains=['owned.example'], open_ports={}, socket_findings={}, tls_findings={}, resolved_addresses={}, warnings=[])
        with patch.object(worker, 'SessionLocal', self.sessions), patch.object(worker, 'ownership_matches', AsyncMock(return_value=True)), patch.object(worker, 'run_pipeline', AsyncMock(return_value=results)), patch.object(worker, 'send_alert', AsyncMock()):
            await worker.recover_pending()
        response = await self.client.get('/scans/domain/'+str(self.domain), headers=self.headers)
        self.assertEqual(response.json()[0]['status'], 'completed')
        self.assertIsNotNone(response.json()[0]['completed_at'])
        self.assertIn('risk', response.json()[0]['diff'])

    async def test_worker_failure_is_persisted_and_next_interval_can_run(self):
        await self.due()
        with patch.object(scheduler, 'ownership_matches', AsyncMock(return_value=True)):
            await scheduler.dispatch_due(self.sessions, self.now)
        with patch.object(worker, 'SessionLocal', self.sessions), patch.object(worker, 'ownership_matches', AsyncMock(return_value=True)), patch.object(worker, 'run_pipeline', AsyncMock(side_effect=TimeoutError('controlled timeout'))):
            await worker.recover_pending()
        response = await self.client.get('/scans/domain/'+str(self.domain), headers=self.headers)
        self.assertEqual(response.json()[0]['status'], 'failed')
        self.assertEqual(response.json()[0]['diff']['error_type'], 'TimeoutError')
        with patch.object(scheduler, 'ownership_matches', AsyncMock(return_value=True)):
            await scheduler.dispatch_due(self.sessions, self.now+timedelta(hours=1))
        self.assertEqual(await self.count(), 2)

    async def test_unverified_enable_rejected_and_invalid_target_disabled(self):
        async with self.sessions() as db:
            d = await db.get(Domain, self.domain); d.verified = False
            await db.commit()
        self.assertEqual((await self.client.put(self.path, headers=self.headers,
            json={'interval_minutes':60, 'enabled':True})).status_code, 403)
        await self.due()
        async with self.sessions() as db:
            d = await db.get(Domain, self.domain); d.verified = True; d.name = '127.0.0.1'
            await db.commit()
        with patch.object(scheduler, 'ownership_matches', AsyncMock()) as dns:
            await scheduler.dispatch_due(self.sessions, self.now)
            dns.assert_not_awaited()
        self.assertEqual(await self.count(), 0)

    async def test_rollback_keeps_occurrence_due_and_timezone_is_utc(self):
        await self.due()
        from sqlalchemy.ext.asyncio import AsyncSession
        with patch.object(scheduler, 'ownership_matches', AsyncMock(return_value=True)), patch.object(AsyncSession, 'commit', AsyncMock(side_effect=RuntimeError('controlled DB failure'))):
            with self.assertRaises(RuntimeError):
                await scheduler.dispatch_due(self.sessions, self.now)
        self.assertEqual(await self.count(), 0)
        aware = self.now.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=5, minutes=30)))
        with patch.object(scheduler, 'ownership_matches', AsyncMock(return_value=True)):
            await scheduler.dispatch_due(self.sessions, aware)
        self.assertEqual(await self.count(), 1)

    async def test_additive_migration_is_idempotent_and_creates_no_schedules(self):
        from app.migrate_schedules import migrate
        async with self.engine.begin() as conn:
            await conn.run_sync(ScanSchedule.__table__.drop)
            await conn.run_sync(migrate)
            await conn.run_sync(migrate)
        async with self.sessions() as db:
            self.assertEqual(await db.scalar(select(func.count()).select_from(ScanSchedule)), 0)
            self.assertEqual((await db.get(Domain, self.domain)).owner_id, self.owner)
