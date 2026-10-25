import os
import sys
import uuid
import unittest
import asyncio
from pathlib import Path
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'api'), str(ROOT/'shared'), str(ROOT/'worker')]
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///:memory:'
os.environ['REDIS_URL'] = 'redis://127.0.0.1:6379/0'
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
# Import without opening production DB connections or requiring asyncpg in tests.
with patch('sqlalchemy.ext.asyncio.create_async_engine', return_value=MagicMock()):
    from worker import main
    from app.routes import domains, verify, scans
from shared.models import Base, Domain, Scan, ScanStatus, User
from shared.targets import normalize_domain, in_scope, ownership_matches, public_addresses
from shared.time_utils import database_utc
from app.schemas import DomainCreate, ScanOut
from fastapi import HTTPException
from worker.tasks import tls_check, subdomain_enum, diff_engine, port_scan, socket_scan

class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = create_async_engine('sqlite+aiosqlite:///:memory:')
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self.p = patch.object(main, 'SessionLocal', self.sessions); self.p.start()
        async with self.sessions() as db:
            self.user = User(username='pipeline_user',password_hash='test-not-used-for-login',active=True)
            db.add(self.user);await db.commit()
            self.domain = Domain(name='owned.example', verification_token='asm-verify=secret', verified=True,owner_id=self.user.id)
            db.add(self.domain); await db.commit()
            self.scan = Scan(domain_id=self.domain.id, status=ScanStatus.queued)
            db.add(self.scan); await db.commit()
        self.output = dict(subdomains=['owned.example'],open_ports={'owned.example':[443]},socket_findings={},tls_findings={'owned.example':[{'port':443,'expires':'2027-01-01T00:00:00Z'}]},resolved_addresses={'owned.example':['8.8.8.8']},warnings=[])
    async def asyncTearDown(self):
        self.p.stop(); await self.engine.dispose()
    async def record(self):
        async with self.sessions() as db: return await db.get(Scan, self.scan.id)
    async def process(self, pipeline=None, ownership=True):
        with patch.object(main,'ownership_matches',AsyncMock(return_value=ownership)), patch.object(main,'run_pipeline', pipeline or AsyncMock(return_value=self.output)), patch.object(main,'send_alert',AsyncMock(side_effect=RuntimeError('notification unavailable'))):
            await main.process_job({'scan_id':str(self.scan.id),'domain':'attacker.example'})
    async def test_completed_persisted_complete_api_details_and_duplicate_delivery(self):
        async def pipeline(name):
            self.assertEqual(name,'owned.example')
            self.assertEqual((await self.record()).status,ScanStatus.running)
            return self.output
        fn=AsyncMock(side_effect=pipeline)
        await self.process(fn); await self.process(fn)
        fn.assert_awaited_once()
        async with self.sessions() as db:
            result=ScanOut.model_validate(await scans.get_scan(self.scan.id,db,self.user)).model_dump(mode='json')
            history=await scans.list_scans_for_domain(self.domain.id,db,self.user)
        self.assertEqual(len(history),1)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['diff']['resolved_addresses'],self.output['resolved_addresses'])
        self.assertEqual(result['tls_findings'],self.output['tls_findings'])
        self.assertTrue(result['completed_at'].endswith('Z'))
    async def test_stale_attempt_cannot_overwrite_newer_attempt(self):
        async def pipeline(name):
            async with self.sessions() as db:
                s=await db.get(Scan,self.scan.id)
                s.diff={'attempts':2,'lease_started':database_utc().isoformat()}
                await db.commit()
            return self.output
        await self.process(AsyncMock(side_effect=pipeline))
        record=await self.record()
        self.assertEqual(record.status,ScanStatus.running)
        self.assertEqual(record.diff['attempts'],2)
        self.assertIsNone(record.subdomains)
    async def test_result_commit_failure_rolls_back_then_persists_failure(self):
        from sqlalchemy.ext.asyncio import AsyncSession
        class FailResultCommit(AsyncSession):
            async def commit(session):
                if any(isinstance(obj,Scan) and obj.status==ScanStatus.completed for obj in session.dirty):
                    raise RuntimeError('Injected persistence failure')
                await super().commit()
        failing=async_sessionmaker(self.engine,class_=FailResultCommit,expire_on_commit=False)
        with patch.object(main,'SessionLocal',failing): await self.process()
        record=await self.record()
        self.assertEqual(record.status,ScanStatus.failed)
        self.assertEqual(record.diff['error'],'Injected persistence failure')
        self.assertIsNone(record.subdomains)
    async def test_successive_scan_risk_and_history_via_http(self):
        from fastapi import FastAPI
        from app.database import get_db
        import httpx
        # An older completed snapshot, a newer completed scan and a failed scan.
        async with self.sessions() as db:
            old=Scan(domain_id=self.domain.id,status=ScanStatus.completed,created_at=self.scan.created_at-timedelta(days=1),completed_at=self.scan.created_at-timedelta(days=1),subdomains=['owned.example'],open_ports={},socket_findings={},tls_findings={},diff={})
            future=Scan(domain_id=self.domain.id,status=ScanStatus.completed,created_at=self.scan.created_at+timedelta(days=1),open_ports={'owned.example':[5432]},subdomains=['owned.example'])
            failed=Scan(domain_id=self.domain.id,status=ScanStatus.failed,created_at=self.scan.created_at-timedelta(hours=1))
            db.add_all([old,future,failed]);await db.commit();old_id=str(old.id)
        self.output.update(open_ports={'owned.example':[5432]},socket_findings={'owned.example':[{'port':5432,'fingerprint':'postgresql'}]},tls_findings={})
        await self.process()
        app=FastAPI();app.include_router(scans.router)
        async def test_db():
            async with self.sessions() as db: yield db
        app.dependency_overrides[get_db]=test_db
        from app.auth import current_user
        app.dependency_overrides[current_user]=lambda: self.user
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as client:
            response=await client.get('/scans/'+str(self.scan.id))
            history=await client.get('/scans/domain/'+str(self.domain.id))
        self.assertEqual(response.status_code,200)
        diff=response.json()['diff']
        self.assertEqual(diff['baseline_scan_id'],old_id)
        self.assertEqual(diff['risk']['severity'],'critical')
        self.assertEqual(diff['new_open_ports'],{'owned.example':[5432]})
        self.assertTrue(any(row['id']==str(self.scan.id) and row['diff']['risk']['score']==90 for row in history.json()))
    async def test_unverified_never_runs(self):
        async with self.sessions() as db:
            d=await db.get(Domain,self.domain.id);d.verified=False;await db.commit()
        fn=AsyncMock();await self.process(fn);fn.assert_not_awaited()
        self.assertEqual((await self.record()).status,ScanStatus.failed)
    async def test_revoked_ownership_never_runs(self):
        fn=AsyncMock();await self.process(fn,False);fn.assert_not_awaited()
        self.assertEqual((await self.record()).diff['error_type'],'PermissionError')
    async def test_failure_and_timeout_persist_terminal_state(self):
        for exc in [RuntimeError('stage failed'),TimeoutError()]:
            async with self.sessions() as db:
                s=await db.get(Scan,self.scan.id);s.status=ScanStatus.queued;await db.commit()
            await self.process(AsyncMock(side_effect=exc))
            result=await self.record();self.assertEqual(result.status,ScanStatus.failed)
            self.assertIsNotNone(result.completed_at)
    async def test_real_deadline_cancels_pipeline(self):
        async def hang(name): await asyncio.sleep(10)
        with patch.object(main,'SCAN_TIMEOUT',0.01): await self.process(AsyncMock(side_effect=hang))
        self.assertEqual((await self.record()).diff['error_type'],'TimeoutError')
    async def test_active_lease_skipped_stale_lease_retried_and_bounded(self):
        async with self.sessions() as db:
            s=await db.get(Scan,self.scan.id);s.status=ScanStatus.running;s.diff={'attempts':1,'lease_started':database_utc().isoformat()};await db.commit()
        fn=AsyncMock(return_value=self.output);await self.process(fn);fn.assert_not_awaited()
        async with self.sessions() as db:
            s=await db.get(Scan,self.scan.id);s.diff={'attempts':1,'lease_started':(database_utc()-timedelta(hours=1)).isoformat()};await db.commit()
        await self.process(fn);self.assertEqual((await self.record()).diff['attempts'],2)
        async with self.sessions() as db:
            s=await db.get(Scan,self.scan.id);s.status=ScanStatus.running;s.diff={'attempts':3};await db.commit()
        await self.process(fn);self.assertEqual((await self.record()).status,ScanStatus.failed)
    async def test_enqueue_rejects_revoked_and_unavailable_dns(self):
        for check, expected in [(AsyncMock(return_value=False),403),(AsyncMock(side_effect=TimeoutError()),503)]:
            async with self.sessions() as db:
                d=await db.get(Domain,self.domain.id);d.verified=True;await db.commit()
                with patch.object(scans,'ownership_matches',check),patch.object(scans.redis_client,'rpush',AsyncMock()) as push:
                    with self.assertRaises(HTTPException) as caught: await scans.trigger_scan(self.domain.id,db,self.user)
                    self.assertEqual(caught.exception.status_code,expected);push.assert_not_awaited()
    async def test_registration_duplicate_and_verification(self):
        async with self.sessions() as db:
            registered=await domains.register_domain(DomainCreate(name='NEW.Example.'),db,self.user)
            self.assertEqual(registered.name,'new.example');self.assertFalse(registered.verified)
            with self.assertRaises(HTTPException) as caught: await domains.register_domain(DomainCreate(name='new.example'),db,self.user)
            self.assertEqual(caught.exception.status_code,409)
            with patch.object(verify,'ownership_matches',AsyncMock(return_value=True)):
                verified=await verify.verify_domain(self.domain.id,db,self.user);self.assertTrue(verified.verified)
            with patch.object(verify,'ownership_matches',AsyncMock(return_value=False)):
                with self.assertRaises(HTTPException): await verify.verify_domain(self.domain.id,db,self.user)
    async def test_redis_failure_keeps_durable_queue_and_recovery(self):
        async with self.sessions() as db:
            with patch.object(scans,'ownership_matches',AsyncMock(return_value=True)),patch.object(scans.redis_client,'rpush',AsyncMock(side_effect=ConnectionError())):
                queued=await scans.trigger_scan(self.domain.id,db,self.user)
            self.assertEqual(queued.status,ScanStatus.queued)
        with patch.object(main,'ownership_matches',AsyncMock(return_value=True)),patch.object(main,'run_pipeline',AsyncMock(return_value=self.output)),patch.object(main,'send_alert',AsyncMock()): await main.recover_pending()
        async with self.sessions() as db: self.assertEqual((await db.get(Scan,queued.id)).status,ScanStatus.completed)
    async def test_pipeline_filters_hosts_and_pins_all_active_stages(self):
        with patch.object(main,'enumerate_subdomains',AsyncMock(return_value=['owned.example','evil.example'])),patch.object(main,'public_addresses',AsyncMock(return_value=['8.8.8.8'])),patch.object(main,'port_scan_hosts',AsyncMock(return_value={'owned.example':[443]})) as ports,patch.object(main,'socket_scan_hosts',AsyncMock(return_value={})) as sockets,patch.object(main,'check_tls',AsyncMock(return_value=[{'port':443}])) as tls:
            result=await main.run_pipeline('owned.example')
        self.assertEqual(result['subdomains'],['owned.example'])
        self.assertEqual(len(result['warnings']),1)
        self.assertEqual(ports.call_args.kwargs['addresses'],{'owned.example':['8.8.8.8']})
        self.assertEqual(sockets.call_args.kwargs['addresses'],{'owned.example':['8.8.8.8']})
        tls.assert_awaited_once_with('owned.example',[443],address='8.8.8.8')

class SafetyTests(unittest.IsolatedAsyncioTestCase):
    def test_names_and_scope(self):
        self.assertEqual(normalize_domain('Example.COM.'),'example.com')
        for bad in ['http://example.com','127.0.0.1','*.example.com','example.com:80','-a.example']:
            with self.assertRaises(ValueError): normalize_domain(bad)
        self.assertTrue(in_scope('api.example.com','example.com'))
        self.assertFalse(in_scope('evilexample.com','example.com'))
    async def test_txt_exact_chunked_match(self):
        with patch('shared.targets.dns.asyncresolver.resolve',AsyncMock(return_value=[MagicMock(strings=[b'asm-verify=',b'token'])])):
            self.assertTrue(await ownership_matches('owned.example','asm-verify=token'))
            self.assertFalse(await ownership_matches('owned.example','verify=token'))
    async def test_passive_discovery_excludes_suffix_lookalikes(self):
        response=MagicMock(status_code=200)
        response.json.return_value=[{'name_value':'api.owned.example'},{'name_value':'*.owned.example'},{'name_value':'evilowned.example'}]
        client=MagicMock();client.__aenter__=AsyncMock(return_value=client);client.__aexit__=AsyncMock();client.get=AsyncMock(return_value=response)
        with patch.object(subdomain_enum.httpx,'AsyncClient',return_value=client):
            self.assertEqual(await subdomain_enum.crtsh_lookup('owned.example'),{'owned.example','api.owned.example'})
    async def test_discovery_outage_is_a_warning(self):
        client=MagicMock();client.__aenter__=AsyncMock(side_effect=TimeoutError());client.__aexit__=AsyncMock()
        warnings=[]
        with patch.object(subdomain_enum.httpx,'AsyncClient',return_value=client):
            self.assertEqual(await subdomain_enum.crtsh_lookup('owned.example',warnings),set())
        self.assertEqual(warnings[0]['stage'],'certificate_transparency')
    async def test_ipv6_only_discovery(self):
        import dns.resolver
        resolver=MagicMock();resolver.resolve=AsyncMock(side_effect=[dns.resolver.NoAnswer(),['2606:4700:4700::1111']])
        with patch.object(subdomain_enum.dns.asyncresolver,'Resolver',return_value=resolver):
            self.assertEqual(await subdomain_enum.dns_bruteforce('owned.example',['www']),{'www.owned.example'})
    async def test_private_and_mixed_dns_rejected(self):
        with patch('shared.targets.dns.asyncresolver.resolve',AsyncMock(return_value=['8.8.8.8','127.0.0.1'])):
            with self.assertRaises(ValueError): await public_addresses('owned.example')
    def test_legacy_null_and_removed_host_diff(self):
        result=diff_engine.diff_scans({'subdomains':None,'open_ports':{'old.example':[80]}},{'subdomains':[],'open_ports':{}})
        self.assertEqual(result['closed_ports'],{'old.example':[80]})
    async def test_local_port_and_service_discovery(self):
        async def handler(reader,writer):
            writer.write(b'SSH-2.0-TestServer\r\n');await writer.drain();writer.close();await writer.wait_closed()
        server=await asyncio.start_server(handler,'127.0.0.1',0)
        async with server:
            port=server.sockets[0].getsockname()[1]
            self.assertEqual(await port_scan.scan_host('127.0.0.1',[port]),[port])
            result=await socket_scan._probe_port('127.0.0.1',port)
            self.assertEqual(result['fingerprint'],'ssh')
    def test_certificate_der_metadata(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime,timezone
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,'owned.example')])
        now=datetime.now(timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=5)).sign(key,hashes.SHA256())
        sock=MagicMock();sock.__enter__.return_value=sock;sock.getpeercert.side_effect=lambda binary_form=False:cert.public_bytes(serialization.Encoding.DER) if binary_form else {}
        sock.version.return_value='TLSv1.3';sock.cipher.return_value=('cipher',None,None)
        ctx=MagicMock();ctx.wrap_socket.return_value=sock
        with patch.object(tls_check.ssl,'create_default_context',return_value=ctx),patch.object(tls_check.socket,'create_connection',return_value=MagicMock()):
            result=tls_check._inspect_cert_sync('owned.example',443,address='8.8.8.8')
        self.assertTrue(result['reachable']);self.assertIn('expires',result)
        self.assertIn('certificate_expiring_soon',result['flags'])
        self.assertFalse(result['trust_validated'])
