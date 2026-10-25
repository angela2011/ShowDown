"""All DBs are in-memory; traffic is loopback. Public-IP records below are simulations."""
import asyncio
import hashlib
import json
import os
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch
import httpx
import test_auth as auth_tests
from sqlalchemy import select, func
from shared.models import DecoyEvent, DecoyBlock, DecoyAudit, DecoySensor
from shared.honeypot import confidence, protected_ip
from shared.time_utils import database_utc
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from decoy.service import Decoy, Outbox, Reporter, observations, attributed_source


class HoneypotTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = auth_tests.AuthTests.asyncSetUp
    asyncTearDown = auth_tests.AuthTests.asyncTearDown
    create_account = auth_tests.AuthTests.create_account

    async def sensor(self):
        response = await self.client.post('/honeypots/sensors', json={'name':'controlled-test'}, headers=self.alice_headers)
        self.assertEqual(response.status_code,201,response.text)
        data=response.json()
        return data['id'], {'Authorization':'Bearer '+data['sensor_token']}

    def event(self, ip='11.22.33.44', signals=None, **kwargs):
        return dict(id=str(uuid.uuid4()),observed_at=datetime.now(timezone.utc).isoformat(),source_ip=ip,
                    source_verified=True,protocol='http',details={'bytes_received':0,'payload_sha256':hashlib.sha256(b'').hexdigest(),
                    'signals':signals if signals is not None else ['credential_probe','path_traversal','shell_pattern']},**kwargs)

    async def test_owner_and_sensor_credentials_are_separate(self):
        sid, sensor_headers=await self.sensor()
        for kind in ['events','blocks','audit']:
            path=f'/honeypots/sensors/{sid}/{kind}'
            self.assertEqual((await self.client.get(path)).status_code,401)
            self.assertEqual((await self.client.get(path,headers=self.bob_headers)).status_code,404)
            self.assertEqual((await self.client.get(path,headers=sensor_headers)).status_code,401)
        self.assertEqual((await self.client.post('/honeypots/ingest',json=self.event(),headers=self.alice_headers)).status_code,401)
        self.assertEqual((await self.client.get('/honeypots/sensors',headers=self.bob_headers)).json(),[])
        self.assertEqual((await self.client.post(f'/honeypots/sensors/{sid}/policy',json={'mode':'disabled'},headers=self.bob_headers)).status_code,404)
        self.assertEqual((await self.client.post(f'/honeypots/sensors/{sid}/revoke',headers=self.bob_headers)).status_code,404)
        listed=(await self.client.get('/honeypots/sensors',headers=self.alice_headers)).json()
        self.assertNotIn('token_hash',listed[0]);self.assertNotIn('sensor_token',listed[0])

    async def test_ingestion_scoring_idempotency_timezone_and_audit(self):
        sid, headers=await self.sensor(); event=self.event()
        first=await self.client.post('/honeypots/ingest',json=event,headers=headers)
        self.assertEqual(first.status_code,200,first.text)
        self.assertEqual(first.json()['severity'],'critical');self.assertEqual(first.json()['confidence'],100)
        self.assertTrue(first.json()['observed_at'].endswith('+00:00'))
        self.assertEqual((await self.client.post('/honeypots/ingest',json=event,headers=headers)).json()['id'],event['id'])
        async with self.sessions() as db:
            self.assertEqual(await db.scalar(select(func.count()).select_from(DecoyEvent)),1)
        rows=(await self.client.get(f'/honeypots/sensors/{sid}/audit',headers=self.alice_headers)).json()['items']
        self.assertIn('detection',[r['action'] for r in rows])
        invalid={**event,'id':str(uuid.uuid4()),'observed_at':'2026-01-01T00:00:00'}
        self.assertEqual((await self.client.post('/honeypots/ingest',json=invalid,headers=headers)).status_code,422)

    async def test_response_defaults_off_and_protects_sources(self):
        sid,headers=await self.sensor();event=self.event()
        await self.client.post('/honeypots/ingest',json=event,headers=headers)
        body={'event_id':event['id'],'confirm_ip':event['source_ip'],'reason':'Controlled test review'}
        with patch.dict(os.environ,{'HONEYPOT_RESPONSE_ENABLED':'false'}):
            self.assertEqual((await self.client.post(f'/honeypots/sensors/{sid}/blocks',json=body,headers=self.alice_headers)).status_code,409)
        with patch.dict(os.environ,{'HONEYPOT_RESPONSE_ENABLED':'true','HONEYPOT_PROTECTED_CIDRS':'11.22.33.0/24'}):
            await self.client.post(f'/honeypots/sensors/{sid}/policy',json={'mode':'manual'},headers=self.alice_headers)
            self.assertEqual((await self.client.post(f'/honeypots/sensors/{sid}/blocks',json=body,headers=self.alice_headers)).status_code,409)
        for ip in ['127.0.0.1','10.0.0.1','::1','169.254.169.254','224.0.0.1','::ffff:11.22.33.44']:
            self.assertTrue(protected_ip(ip,[]))

    async def test_simulated_manual_block_unblock_and_expiry(self):
        sid,headers=await self.sensor();event=self.event()
        await self.client.post('/honeypots/ingest',json=event,headers=headers)
        body={'event_id':event['id'],'confirm_ip':event['source_ip'],'reason':'Controlled test review','ttl_seconds':60}
        with patch.dict(os.environ,{'HONEYPOT_RESPONSE_ENABLED':'true','HONEYPOT_PROTECTED_CIDRS':'192.0.2.0/24'}):
            response=await self.client.post(f'/honeypots/sensors/{sid}/policy',json={'mode':'manual'},headers=self.alice_headers)
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual((await self.client.post(f'/honeypots/sensors/{sid}/blocks',json=body,headers=self.bob_headers)).status_code,404)
            result=await self.client.post(f'/honeypots/sensors/{sid}/blocks',json=body,headers=self.alice_headers)
            self.assertEqual(result.status_code,201,result.text);bid=result.json()['id']
            self.assertTrue((await self.client.post('/honeypots/decision',json={'source_ip':event['source_ip']},headers=headers)).json()['blocked'])
            await self.client.post(f'/honeypots/sensors/{sid}/blocks/{bid}/unblock',headers=self.alice_headers)
            self.assertFalse((await self.client.post('/honeypots/decision',json={'source_ip':event['source_ip']},headers=headers)).json()['blocked'])
            result=await self.client.post(f'/honeypots/sensors/{sid}/blocks',json=body,headers=self.alice_headers)
            async with self.sessions() as db:
                block=await db.get(DecoyBlock,uuid.UUID(result.json()['id']));block.expires_at=database_utc()-timedelta(seconds=1);await db.commit()
            self.assertFalse((await self.client.post('/honeypots/decision',json={'source_ip':event['source_ip']},headers=headers)).json()['blocked'])
        audits=(await self.client.get(f'/honeypots/sensors/{sid}/audit',headers=self.alice_headers)).json()['items']
        for action in ['block_created','block_decision','block_revoked','block_expired']:
            self.assertIn(action,[r['action'] for r in audits])

    async def test_simulated_auto_response_needs_repeated_high_confidence(self):
        sid,headers=await self.sensor()
        with patch.dict(os.environ,{'HONEYPOT_RESPONSE_ENABLED':'true','HONEYPOT_PROTECTED_CIDRS':'192.0.2.0/24'}):
            await self.client.post(f'/honeypots/sensors/{sid}/policy',json={'mode':'auto'},headers=self.alice_headers)
            for i in range(3):
                self.assertEqual((await self.client.post('/honeypots/ingest',json=self.event(),headers=headers)).status_code,200)
                value=(await self.client.post('/honeypots/decision',json={'source_ip':'11.22.33.44'},headers=headers)).json()['blocked']
                self.assertEqual(value,i==2)
        self.assertEqual((await self.client.post('/honeypots/decision',json={'source_ip':'11.22.33.44'},headers=headers)).json()['blocked'],False)

    async def test_unverified_and_old_evidence_cannot_block_and_revoke_sensor(self):
        sid,headers=await self.sensor()
        with patch.dict(os.environ,{'HONEYPOT_RESPONSE_ENABLED':'true','HONEYPOT_PROTECTED_CIDRS':'192.0.2.0/24'}):
            await self.client.post(f'/honeypots/sensors/{sid}/policy',json={'mode':'manual'},headers=self.alice_headers)
            for overrides in [{'source_verified':False},{'observed_at':(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()}]:
                event={**self.event(),**overrides}
                await self.client.post('/honeypots/ingest',json=event,headers=headers)
                body={'event_id':event['id'],'confirm_ip':event['source_ip'],'reason':'Controlled review'}
                self.assertEqual((await self.client.post(f'/honeypots/sensors/{sid}/blocks',json=body,headers=self.alice_headers)).status_code,409)
        await self.client.post(f'/honeypots/sensors/{sid}/revoke',headers=self.alice_headers)
        self.assertEqual((await self.client.post('/honeypots/ingest',json=self.event(),headers=headers)).status_code,401)

    async def test_real_loopback_http_tcp_to_api_history(self):
        sid,headers=await self.sensor()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=auth_tests.app),base_url='http://test',headers=headers) as client:
            outbox=Outbox(':memory:');reporter=Reporter(client,outbox);decoy=Decoy(reporter,outbox,'direct',timeout=.1)
            for protocol in ['http','tcp']:
                server=await asyncio.start_server(lambda r,w:decoy.handle(r,w,protocol),'127.0.0.1',0)
                try:
                    reader,writer=await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1])
                    if protocol=='tcp': self.assertIn(b'220',await reader.readline())
                    writer.write(b'GET /.env HTTP/1.1\r\nX-Forwarded-For: 11.22.33.44\r\nAuthorization: secret-test\r\n\r\n' if protocol=='http' else b'USER secret-test\r\n')
                    await writer.drain();await reader.read();writer.close();await writer.wait_closed()
                    for _ in range(20):
                        if outbox.first():break
                        await asyncio.sleep(.01)
                    self.assertEqual(outbox.first()[1]['source_ip'],'127.0.0.1')
                    self.assertNotIn('secret-test',json.dumps(outbox.first()))
                    self.assertTrue(await reporter.flush_one())
                finally:
                    server.close();await server.wait_closed()
            outbox.close()
        rows=(await self.client.get(f'/honeypots/sensors/{sid}/events?limit=1',headers=self.alice_headers)).json()
        self.assertEqual(len(rows['items']),1);self.assertEqual(rows['next_offset'],1)
        self.assertEqual(rows['items'][0]['source_ip'],'127.0.0.1')


class DecoyUnitTests(unittest.IsolatedAsyncioTestCase):
    async def test_additive_migration_is_idempotent_and_preserves_existing_tables(self):
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text, inspect
        from app.migrate_honeypots import migrate
        from shared.models import User
        engine=create_async_engine('sqlite+aiosqlite:///:memory:')
        try:
            async with engine.begin() as conn:
                await conn.run_sync(User.__table__.create)
                await conn.execute(text('CREATE TABLE preserved (value TEXT)'))
                await conn.execute(text("INSERT INTO preserved VALUES ('unchanged')"))
                await conn.run_sync(migrate);await conn.run_sync(migrate)
                self.assertEqual((await conn.execute(text('SELECT value FROM preserved'))).scalar(),'unchanged')
                tables=await conn.run_sync(lambda c:inspect(c).get_table_names())
                self.assertTrue({'decoy_sensors','decoy_events','decoy_blocks','decoy_audit'}.issubset(tables))
        finally:
            await engine.dispose()

    def test_source_attribution_requires_trusted_peer_and_rightmost_address(self):
        payload=b'GET / HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4, 11.22.33.44\r\n\r\n'
        self.assertEqual(attributed_source('10.0.0.2',payload,'azure-http',['10.0.0.0/24']),('11.22.33.44',True))
        self.assertEqual(attributed_source('127.0.0.1',payload,'azure-http',['10.0.0.0/24']),('127.0.0.1',False))
        self.assertEqual(attributed_source('127.0.0.1',payload,'direct'),('127.0.0.1',True))
        self.assertEqual(attributed_source('10.0.0.2',payload[:-2],'azure-http',['10.0.0.0/24']),('10.0.0.2',False))
        duplicate=payload.replace(b'\r\n\r\n',b'\r\nX-Forwarded-For: 2.2.2.2\r\n\r\n')
        self.assertEqual(attributed_source('10.0.0.2',duplicate,'azure-http',['10.0.0.0/24']),('10.0.0.2',False))

    async def test_gateway_prefix_and_retry_delivery(self):
        seen=[]
        async def handler(request):
            seen.append(request.url.path)
            return httpx.Response(200,json={'blocked':False})
        outbox=Outbox(':memory:');outbox.put({'id':'fixture'})
        async with httpx.AsyncClient(base_url='https://gateway.example/api',transport=httpx.MockTransport(handler)) as client:
            reporter=Reporter(client,outbox)
            await reporter.blocked('127.0.0.1');await reporter.flush_one()
        self.assertEqual(seen,['/api/honeypots/decision','/api/honeypots/ingest']);outbox.close()

    async def test_decoy_enforces_decision_and_records_idle_connections(self):
        outbox=Outbox(':memory:');reporter=AsyncMock();reporter.blocked.return_value=True
        decoy=Decoy(reporter,outbox,'direct',timeout=.05)
        server=await asyncio.start_server(lambda r,w:decoy.handle(r,w,'tcp'),'127.0.0.1',0)
        try:
            for blocked,outcome in [(True,'blocked'),(False,'timeout')]:
                reporter.blocked.return_value=blocked
                reader,writer=await asyncio.open_connection('127.0.0.1',server.sockets[0].getsockname()[1])
                data=await reader.read();writer.close();await writer.wait_closed()
                self.assertEqual(data,b'' if blocked else b'220 Service ready\r\n')
                row=outbox.first();self.assertEqual(row[1]['details']['outcome'],outcome);outbox.remove(row[0])
        finally:
            server.close();await server.wait_closed();outbox.close()

    def test_scores_and_redaction(self):
        self.assertEqual(confidence({'signals':[]},1)[1],'low')
        self.assertEqual(confidence({'signals':['credential_probe']},1)[1],'medium')
        self.assertEqual(confidence({'signals':['credential_probe','path_traversal']},1)[1],'high')
        self.assertEqual(confidence({'signals':['path_traversal','shell_pattern']},3)[1],'critical')
        raw=b'GET /admin/../../bin/sh?password=secret HTTP/1.1\r\nCookie: secret\r\n\r\n'
        data=observations(raw,'http');self.assertNotIn('secret',json.dumps(data));self.assertEqual(len(data['signals']),3)

    async def test_durable_retry_queue_and_no_stale_block_on_api_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path=str(Path(folder)/'outbox.sqlite');outbox=Outbox(path,limit=1)
            event={'id':str(uuid.uuid4())};self.assertTrue(outbox.put(event));self.assertFalse(outbox.put({'id':'extra'}));outbox.close()
            outbox=Outbox(path)
            client=AsyncMock();client.post.side_effect=httpx.ConnectError('test unavailable')
            reporter=Reporter(client,outbox);self.assertFalse(await reporter.flush_one());self.assertIsNotNone(outbox.first())
            self.assertFalse(await reporter.blocked('127.0.0.1'))
            client.post.side_effect=None;client.post.return_value=httpx.Response(200,request=httpx.Request('POST','http://test'),json={})
            self.assertTrue(await reporter.flush_one());self.assertIsNone(outbox.first());outbox.close()
