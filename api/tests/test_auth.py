import os
import sys
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'api'),str(ROOT/'shared'),str(ROOT/'worker')]
os.environ['DATABASE_URL']='sqlite+aiosqlite:///:memory:'
os.environ['REDIS_URL']='redis://127.0.0.1:6379/0'
with patch('sqlalchemy.ext.asyncio.create_async_engine',return_value=MagicMock()):
    from app.main import app
    from worker import main as worker
from app.database import get_db
from app.auth import password_hasher, token_digest
from app.assign_owner import assign
from app.routes import scans, verify
from shared.models import Base, User, Domain, Scan, ScanStatus, AuthSession, AuthThrottle
from shared.auth_migration import migrate_auth, require_auth_schema
from shared.time_utils import database_utc
PASSWORD='correct horse battery staple 42'

class AuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine=create_async_engine('sqlite+aiosqlite:///:memory:')
        async with self.engine.begin() as conn:
            await conn.execute(text('PRAGMA foreign_keys=ON'))
            await conn.run_sync(Base.metadata.create_all)
        self.sessions=async_sessionmaker(self.engine,expire_on_commit=False)
        async def database():
            async with self.sessions() as db: yield db
        app.dependency_overrides[get_db]=database
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test')
        self.alice=await self.create_account('alice')
        self.bob=await self.create_account('bob')
        self.alice_headers={'Authorization':'Bearer '+self.alice['token']}
        self.bob_headers={'Authorization':'Bearer '+self.bob['token']}
        response=await self.client.post('/domains/',json={'name':'owned.example'},headers=self.alice_headers)
        self.assertEqual(response.status_code,200,response.text)
        self.domain_id=response.json()['id']
        async with self.sessions() as db:
            domain=await db.get(Domain,uuid.UUID(self.domain_id));domain.verified=True
            scan=Scan(domain_id=domain.id,status=ScanStatus.completed,subdomains=['owned.example'],open_ports={'owned.example':[5432]},socket_findings={},tls_findings={},diff={'risk':{'findings':[{'secret':'owner-only'}]}})
            db.add(scan);await db.commit();self.scan_id=str(scan.id)
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await self.client.aclose();await self.engine.dispose()
    async def create_account(self,name):
        response=await self.client.post('/auth/register',json={'username':name,'password':PASSWORD})
        self.assertEqual(response.status_code,201,response.text)
        user=response.json()
        response=await self.client.post('/auth/login',json={'username':name,'password':PASSWORD})
        self.assertEqual(response.status_code,200,response.text)
        user['token']=response.json()['access_token']
        return user
    def endpoints(self):
        return [('GET','/domains/',None),('POST','/domains/',{'name':'new.example'}),('GET','/domains/'+self.domain_id,None),('POST','/verify/'+self.domain_id,None),('POST','/scans/'+self.domain_id,None),('GET','/scans/'+self.scan_id,None),('GET','/scans/domain/'+self.domain_id,None)]
    async def test_all_data_endpoints_reject_anonymous_and_invalid_tokens(self):
        for headers in [{},{'Authorization':'Bearer invalid'},{'Authorization':'Basic abc'},{'Authorization':'Bearer '+'A'*43}]:
            for method,path,body in self.endpoints():
                response=await self.client.request(method,path,json=body,headers=headers)
                self.assertEqual(response.status_code,401,(path,response.text))
                self.assertEqual(response.headers['www-authenticate'],'Bearer')
        self.assertEqual((await self.client.get('/')).status_code,200)
    async def test_cross_user_cannot_read_verify_or_scan(self):
        with patch.object(verify,'ownership_matches',AsyncMock()) as dns,patch.object(scans.redis_client,'rpush',AsyncMock()) as queue:
            for method,path,body in self.endpoints()[2:]:
                response=await self.client.request(method,path,json=body,headers=self.bob_headers)
                self.assertEqual(response.status_code,404,(path,response.text))
                self.assertNotIn('owner-only',response.text)
            dns.assert_not_awaited();queue.assert_not_awaited()
        self.assertEqual((await self.client.get('/domains/',headers=self.bob_headers)).json(),[])
        self.assertEqual((await self.client.get('/domains/'+str(uuid.uuid4()),headers=self.bob_headers)).status_code,404)
    async def test_owner_can_read_findings_verify_and_queue_after_dns(self):
        self.assertEqual(len((await self.client.get('/domains/',headers=self.alice_headers)).json()),1)
        response=await self.client.get('/scans/'+self.scan_id,headers=self.alice_headers)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['diff']['risk']['findings'],[{'secret':'owner-only'}])
        self.assertEqual(len((await self.client.get('/scans/domain/'+self.domain_id,headers=self.alice_headers)).json()),1)
        with patch.object(verify,'ownership_matches',AsyncMock(return_value=True)):
            response=await self.client.post('/verify/'+self.domain_id,headers=self.alice_headers)
            self.assertEqual(response.status_code,200)
        with patch.object(scans,'ownership_matches',AsyncMock(return_value=True)),patch.object(scans.redis_client,'rpush',AsyncMock()) as queue:
            response=await self.client.post('/scans/'+self.domain_id,headers=self.alice_headers)
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(response.json()['status'],'queued');queue.assert_awaited_once()
    async def test_client_cannot_choose_owner_or_skip_dns(self):
        response=await self.client.post('/domains/',json={'name':'new.example','owner_id':self.bob['id'],'verified':True},headers=self.alice_headers)
        self.assertEqual(response.status_code,200)
        async with self.sessions() as db:
            domain=await db.get(Domain,uuid.UUID(response.json()['id']))
            self.assertEqual(str(domain.owner_id),self.alice['id']);self.assertFalse(domain.verified)
        response=await self.client.post('/scans/'+response.json()['id'],headers=self.alice_headers)
        self.assertEqual(response.status_code,403)
        with patch.object(scans,'ownership_matches',AsyncMock(return_value=False)),patch.object(scans.redis_client,'rpush',AsyncMock()) as queue:
            self.assertEqual((await self.client.post('/scans/'+self.domain_id,headers=self.alice_headers)).status_code,403)
            queue.assert_not_awaited()
    async def test_passwords_salted_hashed_and_tokens_only_hashed_at_rest(self):
        async with self.sessions() as db:
            users=(await db.execute(select(User))).scalars().all()
            hashes=[u.password_hash for u in users]
            self.assertNotEqual(hashes[0],hashes[1])
            for encoded in hashes:
                self.assertTrue(encoded.startswith('$argon2id$'))
                self.assertTrue(password_hasher.verify(encoded,PASSWORD))
            sessions=(await db.execute(select(AuthSession))).scalars().all()
            self.assertIn(token_digest(self.alice['token']),[s.token_hash for s in sessions])
            self.assertNotIn(self.alice['token'],[s.token_hash for s in sessions])
        response=await self.client.get('/auth/me',headers=self.alice_headers)
        self.assertEqual(set(response.json()),{'id','username'})
        self.assertEqual(response.headers['cache-control'],'no-store')
    async def test_wrong_credentials_generic_and_normalized_username(self):
        wrong=await self.client.post('/auth/login',json={'username':'alice','password':'wrong password long enough'})
        absent=await self.client.post('/auth/login',json={'username':'unknown','password':'wrong password long enough'})
        self.assertEqual(wrong.status_code,401);self.assertEqual(wrong.json(),absent.json())
        response=await self.client.post('/auth/login',json={'username':'ALICE','password':PASSWORD})
        self.assertEqual(response.status_code,200)
        self.assertNotEqual(response.json()['access_token'],self.alice['token'])
        duplicate=await self.client.post('/auth/register',json={'username':'ALICE','password':PASSWORD})
        self.assertEqual(duplicate.status_code,409)
    async def test_logout_expiry_and_disabled_user_revoke_access(self):
        response=await self.client.post('/auth/logout',headers=self.alice_headers)
        self.assertEqual(response.status_code,204)
        self.assertEqual((await self.client.get('/domains/',headers=self.alice_headers)).status_code,401)
        async with self.sessions() as db:
            session=await db.get(AuthSession,token_digest(self.bob['token']));session.expires_at=database_utc()-timedelta(seconds=1);await db.commit()
        self.assertEqual((await self.client.get('/domains/',headers=self.bob_headers)).status_code,401)
        response=await self.client.post('/auth/login',json={'username':'bob','password':PASSWORD});headers={'Authorization':'Bearer '+response.json()['access_token']}
        async with self.sessions() as db:
            user=await db.get(User,uuid.UUID(self.bob['id']));user.active=False;await db.commit()
        self.assertEqual((await self.client.get('/domains/',headers=headers)).status_code,401)
        self.assertEqual((await self.client.post('/auth/login',json={'username':'bob','password':PASSWORD})).status_code,401)
    async def test_throttling_is_persisted_and_ignores_spoofed_forwarded_ip(self):
        # One login was used during setup; the next 9 attempts are permitted.
        for _ in range(9):
            response=await self.client.post('/auth/login',json={'username':'alice','password':'wrong password long enough'})
            self.assertEqual(response.status_code,401)
        response=await self.client.post('/auth/login',json={'username':'alice','password':PASSWORD},headers={'X-Forwarded-For':'1.1.1.1'})
        self.assertEqual(response.status_code,429);self.assertGreater(int(response.headers['retry-after']),0)
        async with self.sessions() as db:
            self.assertTrue((await db.execute(select(AuthThrottle))).scalars().all())
    async def test_registration_rate_limit_and_password_rehash(self):
        from argon2 import PasswordHasher
        async with self.sessions() as db:
            user=await db.get(User,uuid.UUID(self.alice['id']))
            user.password_hash=PasswordHasher(time_cost=2,memory_cost=19456,parallelism=1).hash(PASSWORD)
            await db.commit()
        response=await self.client.post('/auth/login',json={'username':'alice','password':PASSWORD})
        self.assertEqual(response.status_code,200)
        async with self.sessions() as db:
            user=await db.get(User,uuid.UUID(self.alice['id']))
            self.assertFalse(password_hasher.check_needs_rehash(user.password_hash))
        # Setup registered two users; the fixed-window peer quota permits eight more.
        for i in range(8):
            response=await self.client.post('/auth/register',json={'username':f'extra{i}','password':PASSWORD})
            self.assertEqual(response.status_code,201,response.text)
        response=await self.client.post('/auth/register',json={'username':'excess','password':PASSWORD},headers={'X-Forwarded-For':'2.2.2.2'})
        self.assertEqual(response.status_code,429)
    async def test_password_length_boundaries_for_register_and_login(self):
        for length in (6, 128):
            payload = {'username': f'boundary{length}', 'password': 'x' * length}
            response = await self.client.post('/auth/register', json=payload)
            self.assertEqual(response.status_code, 201, response.text)
            response = await self.client.post('/auth/login', json=payload)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()['token_type'], 'bearer')
        for endpoint in ('/auth/register', '/auth/login'):
            for length in (5, 129):
                password = 'x' * length
                response = await self.client.post(endpoint, json={'username': 'boundary6', 'password': password})
                self.assertEqual(response.status_code, 422, response.text)
                self.assertNotIn(password, response.text)
                self.assertIn('6' if length == 5 else '128', response.json()['detail'][0]['msg'])

    async def test_validation_does_not_echo_password(self):
        for password in ['aB3!x','x'*129]:
            response=await self.client.post('/auth/register',json={'username':'valid','password':password})
            self.assertEqual(response.status_code,422)
            self.assertNotIn(password,response.text)
            self.assertTrue(all('input' not in item for item in response.json()['detail']))
        response=await self.client.post('/auth/register',json={'username':'bad user','password':PASSWORD,'active':True})
        self.assertEqual(response.status_code,422);self.assertNotIn(PASSWORD,response.text)
    async def test_legacy_data_quarantined_until_explicit_operator_assignment(self):
        async with self.sessions() as db:
            domain=Domain(name='legacy.example',verified=True,verification_token='old-token');db.add(domain);await db.commit();domain_id=domain.id
            scan=Scan(domain_id=domain_id,status=ScanStatus.completed,diff={'history':'preserved'});db.add(scan);await db.commit();scan_id=scan.id
        for headers in [self.alice_headers,self.bob_headers]:
            self.assertEqual((await self.client.get('/domains/'+str(domain_id),headers=headers)).status_code,404)
            self.assertEqual((await self.client.get('/scans/'+str(scan_id),headers=headers)).status_code,404)
        async with self.sessions() as db:
            await assign(db,domain_id,uuid.UUID(self.alice['id']))
            domain=await db.get(Domain,domain_id)
            self.assertFalse(domain.verified);self.assertNotEqual(domain.verification_token,'old-token')
            with self.assertRaises(ValueError): await assign(db,domain_id,uuid.UUID(self.bob['id']))
        self.assertEqual((await self.client.get('/scans/'+str(scan_id),headers=self.alice_headers)).json()['diff'],{'history':'preserved'})
        self.assertEqual((await self.client.get('/scans/'+str(scan_id),headers=self.bob_headers)).status_code,404)
    async def test_worker_rejects_unassigned_or_disabled_owner(self):
        for disabled in [False,True]:
            async with self.sessions() as db:
                domain=await db.get(Domain,uuid.UUID(self.domain_id))
                domain.owner_id=uuid.UUID(self.alice['id']) if disabled else None
                if disabled:
                    user=await db.get(User,domain.owner_id);user.active=False
                scan=Scan(domain_id=domain.id,status=ScanStatus.queued);db.add(scan);await db.commit();scan_id=scan.id
            with patch.object(worker,'SessionLocal',self.sessions),patch.object(worker,'run_pipeline',AsyncMock()) as pipeline,patch.object(worker,'ownership_matches',AsyncMock()) as dns:
                await worker.process_job({'scan_id':str(scan_id)})
                pipeline.assert_not_awaited();dns.assert_not_awaited()
            async with self.sessions() as db:
                self.assertEqual((await db.get(Scan,scan_id)).status,ScanStatus.failed)

class MigrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_migration_preserves_legacy_records_and_is_idempotent(self):
        engine=create_async_engine('sqlite+aiosqlite:///:memory:')
        try:
            async with engine.begin() as conn:
                await conn.execute(text('CREATE TABLE domains (id CHAR(32) PRIMARY KEY, name VARCHAR UNIQUE, verification_token VARCHAR, verified BOOLEAN, created_at DATETIME)'))
                await conn.execute(text("INSERT INTO domains VALUES ('12345678123456781234567812345678','legacy.example','original-token',1,'2026-01-01')"))
                with self.assertRaises(RuntimeError): await conn.run_sync(require_auth_schema)
                await conn.execute(text('CREATE TABLE scans (id CHAR(32) PRIMARY KEY, domain_id CHAR(32), status VARCHAR, diff JSON)'))
                await conn.execute(text("INSERT INTO scans VALUES ('87654321876543218765432187654321','12345678123456781234567812345678','completed','{}')"))
                await conn.run_sync(migrate_auth);await conn.run_sync(migrate_auth);await conn.run_sync(require_auth_schema)
                self.assertEqual((await conn.execute(text('SELECT status,diff FROM scans'))).one(),('completed','{}'))
                self.assertEqual((await conn.execute(text('SELECT COUNT(*) FROM users'))).scalar_one(),0)
                row=(await conn.execute(text('SELECT name,verification_token,verified,owner_id FROM domains'))).one()
                self.assertEqual(tuple(row),('legacy.example','original-token',1,None))
        finally:
            await engine.dispose()
