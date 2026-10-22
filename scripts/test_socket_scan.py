"""
Run the socket_scan module directly (no API, queue or DB needed).

  python3 scripts/test_socket_scan.py                  # scans the local lab
  python3 scripts/test_socket_scan.py 203.0.113.10 22,80,443

Only point this at machines you own or are explicitly authorized to test.
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "worker"))
from worker.tasks.socket_scan import scan_open_ports  # noqa: E402

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
ports = [int(p) for p in sys.argv[2].split(",")] if len(sys.argv) > 2 else [2121, 2222, 6379, 8080, 8443, 9999]


async def main():
    results = await scan_open_ports(host, ports)
    for r in sorted(results, key=lambda r: r["port"]):
        print(f"\n[{host}:{r['port']}] fingerprint={r['fingerprint']}")
        print(f"   banner: {r['banner']!r}")
        print(f"   flags : {r['flags']}")


asyncio.run(main())
