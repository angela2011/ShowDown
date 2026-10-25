"""Isolated notification tests. All Slack delivery uses mocks/MockTransport."""
import os
import sys
import unittest
from pathlib import Path
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'api'), str(ROOT/'shared'), str(ROOT/'worker')]
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///:memory:'
os.environ['REDIS_URL'] = 'redis://127.0.0.1:6379/0'
with patch('sqlalchemy.ext.asyncio.create_async_engine', return_value=MagicMock()):
    from worker import main
from worker import notifications as alerts
from worker.tasks.diff_engine import diff_scans
from shared.models import Base, Domain, User, Scan, ScanStatus, ScanNotification
from shared.time_utils import database_utc

def difference(score=40, findings=None, first=False):
    return dict(first_scan=first, new_subdomains=[], new_open_ports={},
                risk=dict(score=score, severity='medium', findings=findings or []))

class TriggerTests(unittest.TestCase):
    def risk_events(self, before, after):
        previous = {'diff': {'risk': {'score':before, 'findings':[]}}}
        return alerts.events_for('owned.example', difference(after), previous)

    def test_significant_threshold_and_high_critical_boundaries(self):
        for before, after, expected in [(20,39,False),(20,40,True),(40,59,False),(40,60,True),(69,70,True),(89,90,True),(90,70,False),(70,70,False)]:
            self.assertEqual(bool(self.risk_events(before,after)), expected)
        with patch.dict(os.environ, {'ALERT_RISK_INCREASE':'30'}):
            self.assertFalse(self.risk_events(40,60))
        with patch.dict(os.environ, {'ALERT_RISK_INCREASE':'invalid'}):
            self.assertTrue(self.risk_events(40,60))

    def test_escalated_finding_when_total_score_is_already_high(self):
        previous = {'diff':{'risk':{'score':90,'findings':[{'id':'a','score':90}]}}}
        after = difference(90,[{'id':'a','score':90},{'id':'b','score':70}])
        self.assertEqual(alerts.events_for('owned.example',after,previous)[0]['kind'],'risk')
        self.assertFalse(alerts.events_for('owned.example',after,{'diff':{'risk':after['risk']}}))

    def test_certificate_boundaries_baseline_and_stable_bucket(self):
        now = database_utc()
        expiry = now + timedelta(days=30)
        def at(days):
            snapshot = dict(domain='owned.example', subdomains=['owned.example'],
                observed_at=(expiry-timedelta(days=days)).isoformat(),
                tls_findings={'owned.example':[{'port':443,'expires':expiry.isoformat(),'reachable':True}]})
            return alerts.events_for('owned.example',diff_scans(None,snapshot),None)
        self.assertEqual(at(30.001),[])
        a, b, c, d = at(30), at(8), at(7), at(-1)
        self.assertEqual(a[0]['key'],b[0]['key'])
        self.assertNotEqual(b[0]['key'],c[0]['key'])
        self.assertEqual(c[0]['key'],at(0)[0]['key'])
        self.assertNotEqual(c[0]['key'],d[0]['key'])
        self.assertTrue(all(e['kind']=='certificate' for e in a+c+d))

    def test_legacy_alert_preserved_and_baseline_risk_suppressed(self):
        diff = difference(first=True)
        diff['new_subdomains']=['owned.example']
        self.assertFalse(alerts.events_for('owned.example', diff, None))
        diff['first_scan']=False
        self.assertIn('changes',[e['kind'] for e in alerts.events_for('owned.example',diff,{'diff':{'risk':{'score':40,'findings':[]}}})])

    def test_missing_or_unreachable_certificate_does_not_alert(self):
        snapshot = dict(domain='owned.example',tls_findings={'owned.example':[{'port':443,'reachable':False,'days_until_expiry':-2}]})
        self.assertFalse(alerts.events_for('owned.example',diff_scans(None,snapshot),None))

class SlackTests(unittest.IsolatedAsyncioTestCase):
    async def response(self, status, body='ok', headers=None, error=None):
        real_client = httpx.AsyncClient
        def handle(request):
            if error: raise error
            return httpx.Response(status, text=body, headers=headers)
        with patch.object(alerts.httpx, 'AsyncClient', side_effect=lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw)):
            return await alerts.slack_delivery('https://slack.invalid/mock-only','test')

    async def test_success_disabled_and_rejected_responses(self):
        self.assertEqual((await self.response(200))['status'],'sent')
        for code, body in [(400,'bad'),(403,'bad'),(302,'redirect'),(200,'not ok')]:
            self.assertEqual((await self.response(code,body))['status'],'failed')
        self.assertEqual((await alerts.slack_delivery('', 'test'))['status'],'disabled')

    async def test_rate_limit_server_failure_and_ambiguous_timeout(self):
        result=await self.response(429,headers={'Retry-After':'180'})
        self.assertEqual(result['delay'],180)
        self.assertEqual((await self.response(503))['status'],'retry')
        result=await self.response(200,error=httpx.ReadTimeout('sensitive URL must not be persisted'))
        self.assertEqual(result['status'],'uncertain')
        self.assertNotIn('sensitive',str(result))

class OutboxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine=create_async_engine('sqlite+aiosqlite:///:memory:')
        async with self.engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)
        self.sessions=async_sessionmaker(self.engine,expire_on_commit=False)
        self.now=database_utc()
        async with self.sessions() as db:
            user=User(username='notify-owner',password_hash='unused')
            db.add(user); await db.flush()
            domain=Domain(name='owned.example',owner_id=user.id,verified=True,verification_token='test')
            db.add(domain); await db.flush()
            self.owner=user.id; self.domain=domain.id
            await db.commit()
    async def asyncTearDown(self): await self.engine.dispose()
    async def add(self,key='same',kind='certificate'):
        async with self.sessions() as db:
            scan=Scan(domain_id=self.domain,status=ScanStatus.completed)
            db.add(scan); await db.flush()
            db.add(ScanNotification(scan_id=scan.id,domain_id=self.domain,owner_id=self.owner,
                events=[{'key':key,'kind':kind,'text':'safe test'}],created_at=self.now,next_attempt_at=self.now))
            await db.commit(); return scan.id
    async def item(self,scan_id):
        async with self.sessions() as db: return await db.get(ScanNotification,scan_id)

    async def test_duplicate_delivery_across_scans_and_restart(self):
        first=await self.add(); sender=AsyncMock(return_value={'status':'sent'})
        await alerts.deliver_pending(self.sessions,sender,self.now)
        second=await self.add()
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(hours=2))
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(hours=3))
        sender.assert_awaited_once()
        self.assertEqual((await self.item(first)).status,'sent')
        self.assertEqual((await self.item(second)).status,'suppressed')

    async def test_distinct_events_wait_for_cooldown(self):
        await self.add('one'); sender=AsyncMock(return_value={'status':'sent'})
        await alerts.deliver_pending(self.sessions,sender,self.now)
        second=await self.add('two')
        await alerts.deliver_pending(self.sessions,sender,self.now)
        self.assertEqual(sender.await_count,1)
        self.assertEqual((await self.item(second)).status,'pending')
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(hours=1))
        self.assertEqual(sender.await_count,2)

    async def test_retry_limit_and_persistent_backoff(self):
        scan_id=await self.add(); sender=AsyncMock(return_value={'status':'retry','delay':180,'error':'Slack rate limited'})
        await alerts.deliver_pending(self.sessions,sender,self.now)
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(seconds=60))
        self.assertEqual(sender.await_count,1)
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(seconds=180))
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(seconds=360))
        self.assertEqual((await self.item(scan_id)).status,'failed')
        self.assertEqual(sender.await_count,3)

    async def test_unknown_outcome_never_automatically_resends(self):
        scan_id=await self.add(); sender=AsyncMock(side_effect=RuntimeError('secret'))
        await alerts.deliver_pending(self.sessions,sender,self.now)
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(hours=2))
        sender.assert_awaited_once()
        self.assertEqual((await self.item(scan_id)).status,'uncertain')
        self.assertNotIn('secret',(await self.item(scan_id)).last_error)

    async def test_owner_change_cancels_pending_delivery(self):
        scan_id=await self.add()
        async with self.sessions() as db:
            domain=await db.get(Domain,self.domain); domain.owner_id=None; await db.commit()
        sender=AsyncMock()
        await alerts.deliver_pending(self.sessions,sender,self.now)
        sender.assert_not_awaited()
        self.assertEqual((await self.item(scan_id)).status,'cancelled')

    async def test_completed_scan_and_outbox_survive_delivery_failure(self):
        async with self.sessions() as db:
            scan=Scan(domain_id=self.domain,status=ScanStatus.queued)
            db.add(scan); await db.commit(); scan_id=scan.id
        result=dict(subdomains=['owned.example'],open_ports={'owned.example':[443]},socket_findings={},
            tls_findings={'owned.example':[{'port':443,'expires':(self.now+timedelta(days=2)).isoformat()}]},warnings=[])
        with patch.object(main,'SessionLocal',self.sessions), patch.object(main,'SLACK_WEBHOOK_URL','mock-enabled'), patch.object(main,'ownership_matches',AsyncMock(return_value=True)), patch.object(main,'run_pipeline',AsyncMock(return_value=result)), patch.object(main,'send_alert',AsyncMock(return_value={'status':'failed','error':'Slack rejected delivery (403)'})) as sender:
            await main.process_job({'scan_id':str(scan_id)})
            await main.process_job({'scan_id':str(scan_id)})
            sender.assert_awaited_once()
        async with self.sessions() as db:
            self.assertEqual((await db.get(Scan,scan_id)).status,ScanStatus.completed)
            self.assertEqual((await db.get(ScanNotification,scan_id)).status,'failed')

    async def test_notification_migration_idempotent_preserves_scans(self):
        from app.migrate_notifications import migrate
        async with self.engine.begin() as conn:
            await conn.run_sync(ScanNotification.__table__.drop)
            await conn.run_sync(migrate); await conn.run_sync(migrate)
        async with self.sessions() as db:
            self.assertEqual((await db.get(Domain,self.domain)).owner_id,self.owner)

    async def test_crash_claim_and_stale_queue_are_not_resent(self):
        claimed=await self.add('claimed'); stale=await self.add('stale')
        async with self.sessions() as db:
            item=await db.get(ScanNotification,claimed); item.status='sending'
            await db.commit()
        sender=AsyncMock()
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(days=2))
        sender.assert_not_awaited()
        self.assertEqual((await self.item(claimed)).status,'sending')
        self.assertEqual((await self.item(stale)).status,'expired')

    async def test_success_after_retry_and_message_escaping(self):
        scan_id=await self.add()
        async with self.sessions() as db:
            item=await db.get(ScanNotification,scan_id)
            item.events=[{'key':'safe','kind':'risk','text':'<@channel> & evidence'}]
            await db.commit()
        sender=AsyncMock(side_effect=[{'status':'retry'}, {'status':'sent'}])
        await alerts.deliver_pending(self.sessions,sender,self.now)
        await alerts.deliver_pending(self.sessions,sender,self.now+timedelta(seconds=60))
        self.assertEqual((await self.item(scan_id)).status,'sent')
        self.assertIn('&lt;@channel&gt; &amp; evidence',sender.call_args.args[0])
