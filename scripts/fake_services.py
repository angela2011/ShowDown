"""
Local lab: deliberately misconfigured fake services for testing socket_scan.
Binds to 127.0.0.1 only. Run it in one terminal, run test_socket_scan.py in another.

  2121  FTP-ish   announces an old, specific version unprompted
  2222  SSH-ish   announces an outdated OpenSSH version unprompted
  6379  Redis-ish answers PING with +PONG, i.e. no authentication
  8080  HTTP      leaks its server version in headers
  8443  HTTP      PLAINTEXT service on a port where TLS is expected
  9999  silent    accepts connections, never says anything
"""
import asyncio

HTTP_REPLY = b"HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\nContent-Length: 0\r\n\r\n"


def banner_service(banner: bytes):
    async def handler(reader, writer):
        writer.write(banner)
        await writer.drain()
        await asyncio.sleep(0.5)
        writer.close()
    return handler


def http_service():
    async def handler(reader, writer):
        try:
            await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.write(HTTP_REPLY)
            await writer.drain()
        except asyncio.TimeoutError:
            pass
        writer.close()
    return handler


def redis_service():
    async def handler(reader, writer):
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            if data.upper().startswith(b"PING"):
                writer.write(b"+PONG\r\n")
                await writer.drain()
        except asyncio.TimeoutError:
            pass
        writer.close()
    return handler


def silent_service():
    async def handler(reader, writer):
        await asyncio.sleep(5)
        writer.close()
    return handler


async def main():
    specs = [
        (2121, banner_service(b"220 ProFTPD 1.3.5 Server ready.\r\n")),
        (2222, banner_service(b"SSH-2.0-OpenSSH_5.3\r\n")),
        (6379, redis_service()),
        (8080, http_service()),
        (8443, http_service()),
        (9999, silent_service()),
    ]
    servers = [await asyncio.start_server(h, "127.0.0.1", p) for p, h in specs]
    print("Fake services listening on 127.0.0.1:", [p for p, _ in specs])
    print("Ctrl+C to stop.")
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
