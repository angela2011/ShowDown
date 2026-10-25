import asyncio
import httpx
import dns.resolver
import dns.asyncresolver
from shared.targets import normalize_domain, in_scope

WORDLIST = ["www", "api", "dev", "staging", "test", "admin", "mail", "vpn", "ftp", "db", "internal"]


async def crtsh_lookup(domain: str, warnings=None) -> set[str]:
    """Passive subdomain discovery via certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found = set()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        try:
                            name = normalize_domain(name.strip().removeprefix('*.'))
                        except ValueError:
                            continue
                        if in_scope(name, domain):
                            found.add(name)
    except Exception as exc:
        if warnings is not None:
            warnings.append({"stage": "certificate_transparency", "error": type(exc).__name__})
    return found


async def dns_bruteforce(domain: str, wordlist: list[str] = WORDLIST, warnings=None) -> set[str]:
    resolver = dns.asyncresolver.Resolver()
    found = set()

    async def check(word):
        candidate = f"{word}.{domain}"
        for kind in ('A', 'AAAA'):
            try:
                await resolver.resolve(candidate, kind, lifetime=5)
                found.add(candidate)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception as exc:
                if warnings is not None:
                    warnings.append({'host': candidate, 'stage': 'discovery_dns', 'error': type(exc).__name__})

    await asyncio.gather(*(check(w) for w in wordlist))
    return found


async def enumerate_subdomains(domain: str, warnings=None) -> list[str]:
    passive, active = await asyncio.gather(crtsh_lookup(domain, warnings), dns_bruteforce(domain, warnings=warnings))
    all_found = passive | active | {domain}
    return sorted(all_found)
