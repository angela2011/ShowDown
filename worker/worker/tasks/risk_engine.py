"""Versioned, deterministic exposure rules; no CVE or exploit claims."""
import hashlib
import json
from datetime import datetime, timezone

VERSION = '1.0'
LEVELS = {'low': 20, 'medium': 40, 'high': 70, 'critical': 90}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
DATABASE_SERVICES = {'mysql', 'postgresql', 'redis', 'mongodb', 'mssql', 'elasticsearch'}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def port_number(value):
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
        return number if str(number) == str(value) and 0 < number < 65536 else None
    except (TypeError, ValueError):
        return None

def rows(snapshot, field):
    raw = snapshot.get(field) or {}
    # Old TLS lists represented the apex domain only.
    if isinstance(raw, list):
        raw = {snapshot.get('domain', '<legacy-apex>'): raw}
    if not isinstance(raw, dict):
        return []
    return [(host, row) for host, values in raw.items() if isinstance(values, list)
            for row in values if isinstance(row, dict) and port_number(row.get('port')) is not None]

def inventory(snapshot):
    snapshot = snapshot or {}
    raw = snapshot.get('subdomains') or []
    hosts = set(h for h in raw if isinstance(h, str)) if isinstance(raw, (list, dict)) else set()
    ports, services, certificates = {}, {}, {}
    for host, values in (snapshot.get('open_ports') or {}).items():
        hosts.add(host)
        for p in values if isinstance(values, list) else []:
            port = port_number(p)
            if port:
                key = canonical([host, port])
                ports[key] = {'host': host, 'port': port}
    for host, row in rows(snapshot, 'socket_findings'):
        port = port_number(row['port']); address = row.get('address') or ''
        key = canonical([host, port, address])
        services[key] = dict(host=host, port=port, address=address,
                             fingerprint=row.get('fingerprint') or 'unknown', banner=row.get('banner'),
                             flags=sorted(set(row.get('flags') or [])))
    for host, row in rows(snapshot, 'tls_findings'):
        # A failed handshake is an observation gap, not a certificate.
        if row.get('reachable') is False or not any(row.get(k) for k in ('expires','serial_number','sha256','subject')):
            continue
        port = port_number(row['port']); address = row.get('address') or ''
        key = canonical([host, port, address])
        certificates[key] = dict(host=host, port=port, address=address, **{
            k: row.get(k) for k in ('expires','issuer','subject','serial_number','sha256','protocol','cipher')})
        certificates[key]['dns_names'] = sorted(row.get('dns_names') or [])
    addresses = snapshot.get('resolved_addresses') or (snapshot.get('diff') or {}).get('resolved_addresses') or {}
    # Index observations once; avoid scanning all services for every open port.
    from collections import defaultdict
    service_hosts, certificate_hosts = defaultdict(list), defaultdict(list)
    service_ports, certificate_ports, host_ports = defaultdict(list), defaultdict(list), defaultdict(list)
    for key in sorted(services):
        row=services[key]
        service_hosts[row['host']].append(row)
        service_ports[(row['host'],row['port'])].append(row)
    for key in sorted(certificates):
        row=certificates[key]
        certificate_hosts[row['host']].append(row)
        certificate_ports[(row['host'],row['port'])].append(row)
    for row in ports.values():
        host_ports[row['host']].append(row['port'])
        row['services']=service_ports[(row['host'],row['port'])]
        row['certificates']=certificate_ports[(row['host'],row['port'])]
    assets = {host: {'host':host,'addresses':sorted(set(addresses.get(host) or [])),
                     'ports':sorted(host_ports[host]),'services':service_hosts[host],
                     'certificates':certificate_hosts[host]} for host in sorted(hosts)}
    return dict(assets=assets, ports=ports, services=services, certificates=certificates)

def severity(score):
    return 'critical' if score >= 90 else 'high' if score >= 70 else 'medium' if score >= 40 else 'low'

def score_snapshot(snapshot, new_ports=None):
    data = inventory(snapshot); found = {}
    new_ports = new_ports or {}
    def add(rule, host, port, score, title, reason, evidence, address=''):
        identity = hashlib.sha256(canonical([rule, host, port, address]).encode()).hexdigest()[:24]
        found[identity] = dict(id=identity, rule_id=rule, host=host, port=port, address=address,
            severity=severity(score), score=score, title=title, reason=reason, evidence=evidence)
    for endpoint in data['ports'].values():
        host, port = endpoint['host'], endpoint['port']
        new = port in new_ports.get(host, [])
        if new:
            add('new_exposed_port',host,port,40,'Newly exposed port',
                'This port was not detected in the previous completed scan; review intended exposure.',{'port':port})
        confirmed = [s for s in endpoint['services'] if s['fingerprint'] in DATABASE_SERVICES]
        if confirmed or port in DATABASE_PORTS:
            score = 90 if confirmed and new else 80 if confirmed else 60
            add('public_database',host,port,score,'Public database exposure',
                ('A database service banner was observed on a public endpoint.' if confirmed else
                 'An open port conventionally used by a database was observed; service identity is unconfirmed.') +
                (' This exposure is new since the previous scan.' if new else '') +
                ' Authentication and data access were not tested.',
                {'port':port,'services':sorted(set(s['fingerprint'] for s in confirmed)), 'new_exposure':new})
        if port in {23,3389,5900}:
            add('remote_access_exposure',host,port,70,'Public remote-access port',
                'This open port is conventionally used for remote access; authentication was not tested.',{'port':port})
        for service in endpoint['services']:
            flags=service['flags'];address=service['address']
            if service['fingerprint']=='http' or (service['banner'] or '').startswith('HTTP/'):
                add('insecure_http',host,port,40,'Plaintext HTTP observed',
                    'The socket probe received a plaintext HTTP response. Redirect policy and sensitive content were not evaluated.',
                    {'fingerprint':service['fingerprint'],'banner':service['banner']},address)
            for flag, score, title in [('plaintext_response_on_expected_tls_port',70,'Plaintext on expected TLS port'),('possible_version_disclosure',20,'Service version disclosure')]:
                if flag in flags:
                    add(flag,host,port,score,title,'The existing socket probe reported this observation; no exploit was attempted.',{'flag':flag,'banner':service['banner']},address)
    for host, row in rows(snapshot,'tls_findings'):
        if row.get('reachable') is False:
            continue
        port=port_number(row['port']);address=row.get('address') or ''
        if row.get('protocol') in {'TLSv1','TLSv1.1','SSLv2','SSLv3'} or 'weak_tls_protocol' in (row.get('flags') or []):
            add('weak_tls_protocol',host,port,70,'Obsolete TLS protocol observed',
                'The negotiated protocol or scanner observation indicates an obsolete TLS version.',{'protocol':row.get('protocol')},address)
        days=row.get('days_until_expiry')
        # Prefer explicit expiry evaluated at this snapshot, never at API read time.
        if row.get('expires') and snapshot.get('observed_at'):
            try:
                def utc(text):
                    d=datetime.fromisoformat(text.replace('Z','+00:00'))
                    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
                days=(utc(row['expires'])-utc(snapshot['observed_at'])).total_seconds()/86400
            except (ValueError,TypeError):
                days=None
        if isinstance(days,(int,float)) and not isinstance(days,bool) and days <= 30:
            score=80 if days < 0 else 70 if days <= 7 else 40
            add('certificate_expiry',host,port,score,'Expired TLS certificate' if days < 0 else 'TLS certificate approaching expiry',
                'Certificate expired.' if days < 0 else 'Certificate expires within 7 days.' if days <= 7 else 'Certificate expires within 30 days.',
                {'expires':row.get('expires'),'days_until_expiry':round(days,3)},address)
    findings=sorted(found.values(),key=lambda f:(-f['score'],f['id']))
    score=max((f['score'] for f in findings),default=0)
    return {'version':VERSION,'observed_at':snapshot.get('observed_at'),'score':score,'severity':severity(score) if findings else None,
            'method':'Maximum finding score (0–100); 0 means no rule matched, not proof of safety.',
            'counts':{level:sum(f['severity']==level for f in findings) for level in LEVELS},'findings':findings}
