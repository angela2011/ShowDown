import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import socket
import asyncio
from datetime import datetime, timezone

TLS_PORTS = [443, 8443, 465, 993, 995]


def _inspect_cert_sync(host: str, port: int, timeout: float = 5, address=None) -> dict:
    result = {"port": port, "address": address or host, "reachable": False, "flags": [], "trust_validated": False}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even invalid certs, not just trust valid ones

    try:
        with socket.create_connection((address or host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                result["reachable"] = True
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None

                if cert_bin:
                    parsed = x509.load_der_x509_certificate(cert_bin)
                    not_after = parsed.not_valid_after_utc
                    result['expires'] = not_after.isoformat()
                    result['days_until_expiry'] = (not_after - datetime.now(timezone.utc)).days
                    result['issuer'] = parsed.issuer.rfc4514_string()
                    result['subject'] = parsed.subject.rfc4514_string()
                    result['serial_number'] = str(parsed.serial_number)
                    result['sha256'] = parsed.fingerprint(hashes.SHA256()).hex()
                    try:
                        result['dns_names'] = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        result['dns_names'] = []

                weak_protocols = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
                result["flags"] = []
                if result.get("protocol") in weak_protocols:
                    result["flags"].append("weak_tls_protocol")
                if result.get("days_until_expiry", 999) < 14:
                    result["flags"].append("certificate_expiring_soon")

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


async def check_tls(host: str, ports: list[int] = TLS_PORTS, address=None) -> list[dict]:
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, _inspect_cert_sync, host, port, 5, address) for port in ports]
    return await asyncio.gather(*tasks)
