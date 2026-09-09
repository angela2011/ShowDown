import asyncio
import os

COMMON_PORTS = [int(p) for p in os.environ.get(
    "COMMON_PORTS",
    "21,22,23,25,53,80,110,143,443,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017"
).split(",")]

TIMEOUT = float(os.environ.get("PORT_SCAN_TIMEOUT_SECONDS", 2))
CONCURRENCY = int(os.environ.get("PORT_SCAN_CONCURRENCY", 200))


async def _check_port(host: str, port: int, sem: asyncio.Semaphore) -> tuple[int, bool]:
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=TIMEOUT)
            writer.close()
            await writer.wait_closed()
            return port, True
        except Exception:
            return port, False


async def scan_host(host: str, ports: list[int] = COMMON_PORTS) -> list[int]:
    """Returns the list of open ports on a single host."""
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(*(_check_port(host, p, sem) for p in ports))
    return sorted(port for port, is_open in results if is_open)


async def scan_hosts(hosts: list[str], ports: list[int] = COMMON_PORTS) -> dict[str, list[int]]:
    """Scans multiple hosts, one at a time (each host scan is itself concurrent
    across ports) to avoid overwhelming the network/target."""
    results = {}
    for host in hosts:
        results[host] = await scan_host(host, ports)
    return results
