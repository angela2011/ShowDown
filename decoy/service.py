import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit
import httpx

log = logging.getLogger('showdown.decoy')


def attributed_source(peer, payload, mode, trusted_proxies=()):
    """Azure HTTP ingress supplies the RIGHTMOST XFF address, never the leftmost."""
    if mode == 'direct':
        return peer, True
    if mode != 'azure-http' or not any(ipaddress.ip_address(peer) in ipaddress.ip_network(cidr) for cidr in trusted_proxies):
        return peer, False
    if b'\r\n\r\n' not in payload:
        return peer, False
    headers = payload.split(b'\r\n\r\n', 1)[0].split(b'\r\n')[1:]
    values = [line.split(b':', 1)[1].strip() for line in headers if line.lower().startswith(b'x-forwarded-for:')]
    if len(values) != 1:
        return peer, False
    try:
        return str(ipaddress.ip_address(values[0].split(b',')[-1].strip().decode('ascii'))), True
    except (ValueError, UnicodeError):
        return peer, False


def observations(payload, protocol, outcome='observed'):
    """Retain categories and hash, never raw payloads, credentials or headers."""
    sample = payload[:4096]
    lower = unquote(sample.decode('utf-8', errors='replace')).lower()
    first = lower.splitlines()[0] if lower else ''
    parts = first.split()
    method = parts[0].upper() if protocol == 'http' and parts else 'NONE'
    method = method if method in ('GET', 'POST', 'HEAD', 'NONE') else 'OTHER'
    signals = []
    sensitive = any(marker in first for marker in ('/.env', '/wp-login', '/admin', '/login', '/.git'))
    if sensitive or first.startswith(('user ', 'pass ', 'auth ')):
        signals.append('credential_probe')
    if '../' in lower or '..\\' in lower:
        signals.append('path_traversal')
    if any(marker in lower for marker in ('/bin/sh', '/bin/bash', '${jndi:', ';wget ', ';curl ')):
        signals.append('shell_pattern')
    return {'bytes_received': len(sample), 'payload_sha256': hashlib.sha256(sample).hexdigest(),
            'signals': signals, 'method': method, 'outcome': outcome,
            'path_category': 'sensitive' if sensitive else 'other' if protocol == 'http' else 'none'}


class Outbox:
    def __init__(self, path, limit=10000):
        self.db, self.limit = sqlite3.connect(path), limit
        self.db.execute('CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        self.db.commit()

    def put(self, event):
        if self.db.execute('SELECT count(*) FROM outbox').fetchone()[0] >= self.limit:
            log.error(json.dumps({'action': 'outbox_full', 'event_id': event['id']}))
            return False
        self.db.execute('INSERT OR IGNORE INTO outbox VALUES (?,?)', (event['id'], json.dumps(event)))
        self.db.commit()
        return True

    def first(self):
        row = self.db.execute('SELECT id,body FROM outbox ORDER BY rowid LIMIT 1').fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def remove(self, identifier):
        self.db.execute('DELETE FROM outbox WHERE id=?', (identifier,))
        self.db.commit()

    def close(self):
        self.db.close()


class Reporter:
    def __init__(self, client, outbox):
        self.client, self.outbox = client, outbox

    async def blocked(self, source_ip):
        try:
            response = await self.client.post('/honeypots/decision', json={'source_ip': source_ip})
            response.raise_for_status()
            return response.json().get('blocked') is True
        except (httpx.HTTPError, ValueError, AttributeError):
            log.warning(json.dumps({'action': 'decision_unavailable', 'scope': 'decoy-only'}))
            return False  # Fail open only on the inert decoy.

    async def flush_one(self):
        row = self.outbox.first()
        if not row:
            return False
        identifier, event = row
        try:
            response = await self.client.post('/honeypots/ingest', json=event)
            response.raise_for_status()
            self.outbox.remove(identifier)
            return True
        except (httpx.HTTPError, ValueError):
            log.warning(json.dumps({'action': 'delivery_retry', 'event_id': identifier}))
            return False

    async def pump(self):
        while True:
            sent = await self.flush_one()
            await asyncio.sleep(.55 if sent else 5)


class Decoy:
    def __init__(self, reporter, outbox, source_mode='proxied', timeout=3, max_connections=32, trusted_proxies=()):
        if source_mode not in ('direct', 'proxied', 'azure-http'):
            raise ValueError('Source mode must be direct, proxied or azure-http')
        for cidr in trusted_proxies:
            ipaddress.ip_network(cidr)
        if source_mode == 'azure-http' and not trusted_proxies:
            raise ValueError('Azure source attribution requires explicit trusted ingress CIDRs')
        self.trusted_proxies = trusted_proxies
        self.reporter, self.outbox, self.source_mode = reporter, outbox, source_mode
        self.timeout, self.max_connections, self.active = timeout, max_connections, 0

    async def handle(self, reader, writer, protocol):
        if self.active >= self.max_connections:
            log.warning(json.dumps({'action': 'connection_capacity_reached'}))
            writer.close()
            return
        self.active += 1
        source = str(ipaddress.ip_address(writer.get_extra_info('peername')[0]))
        verified = self.source_mode == 'direct'
        observed = datetime.now(timezone.utc).isoformat()
        payload, outcome = b'', 'observed'
        try:
            # Direct connections ignore all forwarding headers.
            if self.source_mode == 'direct' and await self.reporter.blocked(source):
                outcome = 'blocked'
            else:
                if protocol == 'tcp':
                    writer.write(b'220 Service ready\r\n')
                    await asyncio.wait_for(writer.drain(), self.timeout)
                try:
                    payload = await asyncio.wait_for(reader.read(4096), self.timeout)
                except asyncio.TimeoutError:
                    outcome = 'timeout'
                if protocol == 'http':
                    source, verified = attributed_source(source, payload, self.source_mode, self.trusted_proxies)
                    blocked = verified and self.source_mode == 'azure-http' and await self.reporter.blocked(source)
                    if blocked:
                        outcome = 'blocked'
                    writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' if blocked else b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    await asyncio.wait_for(writer.drain(), self.timeout)
        except (OSError, asyncio.TimeoutError):
            outcome = 'read_error'
        finally:
            event = {'id': str(uuid.uuid4()), 'observed_at': observed, 'source_ip': source,
                     'source_verified': verified, 'protocol': protocol,
                     'details': observations(payload, protocol, outcome)}
            event['details']['source_port'] = writer.get_extra_info('peername')[1]
            event['details']['destination_port'] = writer.get_extra_info('sockname')[1]
            try:
                self.outbox.put(event)
            except sqlite3.Error:
                log.exception('Outbox write failed; event not persisted')
            writer.close()
            self.active -= 1
            try:
                await asyncio.wait_for(writer.wait_closed(), self.timeout)
            except (OSError, asyncio.TimeoutError):
                pass


async def main():
    bind = os.getenv('DECOY_BIND', '127.0.0.1')
    if not ipaddress.ip_address(bind).is_loopback and os.getenv('DECOY_AUTHORIZED_BIND') != 'true':
        raise ValueError('DECOY_AUTHORIZED_BIND=true required for non-loopback listeners')
    base = os.environ['DECOY_API_URL'].rstrip('/')
    parsed = urlsplit(base)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/api'):
        raise ValueError('Use an API origin, optionally /api for the existing gateway; no credentials or other paths')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')):
        raise ValueError('HTTPS required outside loopback')
    outbox = Outbox(os.getenv('DECOY_OUTBOX', 'decoy-outbox.sqlite'))
    async with httpx.AsyncClient(base_url=base, headers={'Authorization': 'Bearer '+os.environ['DECOY_SENSOR_TOKEN']}, timeout=5, follow_redirects=False, trust_env=False) as client:
        reporter = Reporter(client, outbox)
        proxies = [s.strip() for s in os.getenv('DECOY_TRUSTED_PROXY_CIDRS', '').split(',') if s.strip()]
        decoy = Decoy(reporter, outbox, os.getenv('DECOY_SOURCE_MODE', 'proxied'), trusted_proxies=proxies)
        http = await asyncio.start_server(lambda r,w: decoy.handle(r,w,'http'), bind, int(os.getenv('DECOY_HTTP_PORT','9080')), limit=4096)
        tcp = await asyncio.start_server(lambda r,w: decoy.handle(r,w,'tcp'), bind, int(os.getenv('DECOY_TCP_PORT','9021')), limit=4096)
        pump = asyncio.create_task(reporter.pump())
        try:
            async with http, tcp:
                await asyncio.gather(http.serve_forever(), tcp.serve_forever())
        finally:
            pump.cancel()
            await asyncio.gather(pump, return_exceptions=True)
            outbox.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
