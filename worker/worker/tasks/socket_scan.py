"""
Socket security layer.

Runs after port_scan has identified which ports are open. For each open
port, this module opens a raw socket connection and:
  1. Grabs whatever banner the service sends unprompted (many services,
     like SSH/FTP/SMTP, announce themselves immediately).
  2. If nothing is sent, tries a small set of protocol-specific probes
     (e.g. an HTTP HEAD request) to elicit a response.
  3. Fingerprints the response against known service signatures.
  4. Flags basic socket-level hygiene issues:
       - plaintext service on a port conventionally expected to be TLS
       - service banner reveals a version string (info disclosure)
       - connection accepted but never responds (possible tarpit/honeypot,
         or a misconfigured listener)

This intentionally does NOT do exploit attempts or protocol-specific
vulnerability probing — it stays at "what is listening and what does it
reveal", which is the ASM (attack surface) scope, not a pentest.
"""

import asyncio
import os

TIMEOUT = float(os.environ.get("SOCKET_SCAN_TIMEOUT_SECONDS", 3))

# Ports where we conventionally expect TLS; a plaintext response here is
# a finding worth flagging.
EXPECTED_TLS_PORTS = {443, 465, 993, 995, 8443}

# Minimal protocol probes for services that don't banner unprompted.
PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n",
    443: b"",  # plaintext probe on an HTTPS port is itself informative if it responds
}

# Very small signature set — extend as needed. Real deployments would pull
# something closer to nmap's service-probes db.
SIGNATURES = [
    ("SSH-", "ssh"),
    ("220 ", "ftp_or_smtp"),
    ("HTTP/1.", "http"),
    ("+OK", "pop3"),
    ("* OK", "imap"),
    ("MySQL", "mysql"),
    ("PostgreSQL", "postgresql"),
    ("REDIS", "redis"),
    ("-ERR", "redis_or_pop3"),
]


def _fingerprint(banner: bytes) -> str:
    text = banner.decode(errors="ignore")
    for sig, service in SIGNATURES:
        if sig in text:
            return service
    return "unknown"


async def _probe_port(host: str, port: int) -> dict:
    finding = {
        "port": port,
        "banner": None,
        "fingerprint": "unknown",
        "flags": [],
    }
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TIMEOUT)

        try:
            # First, see if the service banners unprompted.
            banner = await asyncio.wait_for(reader.read(256), timeout=1.5)
        except asyncio.TimeoutError:
            banner = b""

        if not banner and port in PROBES and PROBES[port]:
            writer.write(PROBES[port])
            await asyncio.wait_for(writer.drain(), timeout=TIMEOUT)
            try:
                banner = await asyncio.wait_for(reader.read(256), timeout=1.5)
            except asyncio.TimeoutError:
                banner = b""

        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=TIMEOUT)

        if banner:
            finding["banner"] = banner.decode(errors="ignore").strip()
            finding["fingerprint"] = _fingerprint(banner)
        else:
            finding["flags"].append("no_response_to_probe")

        if port in EXPECTED_TLS_PORTS and banner and not banner.startswith(b"\x16\x03"):
            finding["flags"].append("plaintext_response_on_expected_tls_port")

        if finding["banner"] and any(ch.isdigit() for ch in finding["banner"][:40]):
            finding["flags"].append("possible_version_disclosure")

    except Exception as e:
        finding["flags"].append(f"connection_error:{type(e).__name__}")

    finally:
        if writer is not None:
            writer.close()

    return finding


async def scan_open_ports(host: str, open_ports: list[int]) -> list[dict]:
    """Given a host and its open ports (from port_scan), run socket-level
    fingerprinting on each and return structured findings."""
    return await asyncio.gather(*(_probe_port(host, p) for p in open_ports))


async def scan_hosts(host_to_ports: dict[str, list[int]], addresses=None) -> dict[str, list[dict]]:
    results = {}
    for host, ports in host_to_ports.items():
        if ports:
            results[host] = []
            for address in (addresses[host] if addresses is not None else [host]):
                rows = await scan_open_ports(address, ports)
                results[host].extend(dict(row, address=address) for row in rows)
        else:
            results[host] = []
    return results
