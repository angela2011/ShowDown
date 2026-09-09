import asyncio
import httpx
import dns.resolver
import dns.asyncresolver

WORDLIST = ["www", "api", "dev", "staging", "test", "admin", "mail", "vpn", "ftp", "db", "internal"]


async def crtsh_lookup(domain: str) -> set[str]:
    """Passive subdomain discovery via certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found = set()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain):
                            found.add(name)
    except Exception:
        pass  # crt.sh can be flaky/rate-limited; don't fail the whole scan
    return found


async def dns_bruteforce(domain: str, wordlist: list[str] = WORDLIST) -> set[str]:
    resolver = dns.asyncresolver.Resolver()
    found = set()

    async def check(word):
        candidate = f"{word}.{domain}"
        try:
            await resolver.resolve(candidate, "A")
            found.add(candidate)
        except Exception:
            pass

    await asyncio.gather(*(check(w) for w in wordlist))
    return found


async def enumerate_subdomains(domain: str) -> list[str]:
    passive, active = await asyncio.gather(crtsh_lookup(domain), dns_bruteforce(domain))
    all_found = passive | active | {domain}
    return sorted(all_found)
