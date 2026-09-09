import asyncio
import os
import httpx
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select

from worker.queue_client import get_next_job
from worker.tasks.subdomain_enum import enumerate_subdomains
from worker.tasks.port_scan import scan_hosts as port_scan_hosts
from worker.tasks.socket_scan import scan_hosts as socket_scan_hosts
from worker.tasks.tls_check import check_tls
from worker.tasks.diff_engine import diff_scans, build_alert_message

# Shared ORM models (installed from the /shared package in the Dockerfile)
# so the worker writes to the exact same schema the API reads from.
from shared.models import Scan, ScanStatus, Domain  # noqa: F401

DATABASE_URL = os.environ["DATABASE_URL"]
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

engine = create_async_engine(DATABASE_URL)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def send_alert(message: str):
    if not SLACK_WEBHOOK_URL or not message:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(SLACK_WEBHOOK_URL, json={"text": message})


async def run_pipeline(domain_name: str) -> dict:
    subdomains = await enumerate_subdomains(domain_name)
    open_ports = await port_scan_hosts(subdomains)
    socket_findings = await socket_scan_hosts(open_ports)
    tls_findings = await check_tls(domain_name)

    return {
        "subdomains": subdomains,
        "open_ports": open_ports,
        "socket_findings": socket_findings,
        "tls_findings": tls_findings,
    }


async def process_job(job: dict):
    scan_id = job["scan_id"]
    domain_name = job["domain"]

    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = ScanStatus.running
        await db.commit()

        try:
            results = await run_pipeline(domain_name)

            # find the previous completed scan for this domain to diff against
            prev_result = await db.execute(
                select(Scan)
                .where(Scan.domain_id == scan.domain_id, Scan.status == ScanStatus.completed)
                .order_by(Scan.created_at.desc())
            )
            previous = prev_result.scalars().first()
            previous_snapshot = None
            if previous:
                previous_snapshot = {"subdomains": previous.subdomains, "open_ports": previous.open_ports}

            diff = diff_scans(previous_snapshot, results)

            scan.subdomains = results["subdomains"]
            scan.open_ports = results["open_ports"]
            scan.socket_findings = results["socket_findings"]
            scan.tls_findings = results["tls_findings"]
            scan.diff = diff
            scan.status = ScanStatus.completed
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()

            alert = build_alert_message(domain_name, diff)
            await send_alert(alert)

        except Exception as e:
            scan.status = ScanStatus.failed
            scan.diff = {"error": str(e)}
            await db.commit()


async def main():
    print("Worker started, polling for scan jobs...")
    while True:
        job = await get_next_job(timeout=5)
        if job:
            print(f"Processing job: {job}")
            await process_job(job)
        else:
            await asyncio.sleep(0.5)


if __name__ == "__main__":
    asyncio.run(main())
