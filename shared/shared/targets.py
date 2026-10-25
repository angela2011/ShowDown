import ipaddress
import re
import dns.asyncresolver

def normalize_domain(value):
    name = value.strip().rstrip('.').lower().encode('idna').decode('ascii')
    if len(name) > 253 or '.' not in name or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in name.split('.')):
        raise ValueError('Provide a DNS hostname, without a URL, port or wildcard')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError('IP literals are not domain names')

def in_scope(host, domain):
    return host == domain or host.endswith('.' + domain)

async def ownership_matches(domain, token):
    try:
        answers = await dns.asyncresolver.resolve('_asm-verify.' + domain, 'TXT', lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    return any(b''.join(record.strings).decode('utf-8', errors='replace') == token for record in answers)

async def public_addresses(host):
    addresses = set()
    for kind in ('A', 'AAAA'):
        try:
            answers = await dns.asyncresolver.resolve(host, kind, lifetime=5)
            addresses.update(str(a) for a in answers)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
    # Reject the entire host if a record mixes public and internal addresses.
    if any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError('Non-public target address rejected')
    return sorted(addresses)
