import ssl
import socket
import asyncio
from datetime import datetime, timezone

TLS_PORTS = [443, 8443, 465, 993, 995]


def _inspect_cert_sync(host: str, port: int, timeout: float = 5) -> dict:
    result = {"port": port, "reachable": False}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even invalid certs, not just trust valid ones

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                result["reachable"] = True
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None

                if cert:
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (not_after - datetime.now(timezone.utc)).days
                    result["expires"] = not_after.isoformat()
                    result["days_until_expiry"] = days_left
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))

                weak_protocols = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
                result["flags"] = []
                if result.get("protocol") in weak_protocols:
                    result["flags"].append("weak_tls_protocol")
                if result.get("days_until_expiry", 999) < 14:
                    result["flags"].append("certificate_expiring_soon")

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


async def check_tls(host: str, ports: list[int] = TLS_PORTS) -> list[dict]:
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, _inspect_cert_sync, host, port) for port in ports]
    return await asyncio.gather(*tasks)
