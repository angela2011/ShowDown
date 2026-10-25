# ShowDown backend pipeline repair — 25 October 2026

Saved in the existing ShowDown checkout on branch frontend. No commit, frontend edits, database migrations, infrastructure changes, deployments or external scans were performed.

## Changes

- Existing ScanOut list/dictionary/null compatibility and naive-UTC database / explicit-UTC API timestamp handling were inspected and verified by regression tests. Existing database columns and records are unchanged.
- Domain registration validates and normalizes DNS hostnames and reports duplicate names as HTTP 409. UUID path validation is explicit.
- TXT verification uses asynchronous, bounded DNS lookups and exact matching after joining TXT chunks. Missing/mismatched ownership revokes verification; temporary DNS failures return 503 without silently treating them as success.
- Enqueue and worker both check current ownership. Worker uses the database domain, never a queue-supplied target name. Unverified targets are rejected before discovery or connection attempts.
- Discovery enforces exact apex/subdomain boundaries, supports A/AAAA, records partial discovery warnings, and rejects private/mixed public-private addresses. Active connections use pinned public IPs, retaining the DNS name for TLS SNI. Up to 1000 discovered candidates are processed.
- Open ports, per-address socket/service observations and per-host TLS observations are persisted in existing JSON fields. IP mappings are exposed at diff.resolved_addresses; partial discovery warnings at diff.warnings through existing scan-detail/history endpoints.
- Certificate DER parsing now extracts expiry, issuer, subject, serial and SANs even with CERT_NONE. TLS certificates are inspected for each discovered host's open conventional TLS ports, not only the apex. trust_validated=false explicitly indicates this is inspection, not a CA-chain/hostname trust verdict. STARTTLS and arbitrary-port TLS detection remain outside this scanner's existing scope.
- Persisted queued rows act as a durable outbox when Redis publication fails. The worker checks queued/running rows at startup and approximately every 30 seconds between jobs. Redis calls have bounded connection/read timeouts.
- Row-locked claims, running leases and attempt fencing prevent duplicate terminal processing and stale-result overwrite. Interrupted jobs are retried up to three total attempts; fresh leases are skipped. Default overall pipeline timeout is 900 seconds (SCAN_TIMEOUT_SECONDS; minimum 10). Expired leases become recoverable after timeout plus 60 seconds.
- Stage failures and deadlines produce failed records with UTC completion time and error metadata. Result commit failure rolls back before recording failure. If the database is unavailable, the persisted lease permits later recovery. Ordinary failed scans are terminal; retry by creating a fresh scan through the existing endpoint, which rechecks ownership. No automatic endless retries of failed targets.
- Notification failures do not turn completed scans into failed scans. Loop errors back off rather than stopping the worker.
- Diff handling tolerates legacy nulls and includes closed ports for removed hosts.

## Verification: 24 tests passed

Command actually run from the chat workspace:

```powershell
& './work/backend-env/Scripts/python.exe' -m unittest discover -s 'C:/Users/Saanvi Garg/OneDrive/Documents/ShowD/ShowDown/api/tests' -v
```

The isolated test environment used Python 3.13, SQLAlchemy 2.0.35, SQLite/aiosqlite and the repository's pinned cryptography dependency. SQLite was test-only; production remains PostgreSQL. Existing two worker mocks were replaced by ORM persistence tests, retaining the three schema/timezone tests.

Coverage:
- Legacy/current schema payloads, UTC conversion and unchanged naive timestamp column.
- Canonical domain registration, duplicates, exact chunked TXT matches, revoked/unavailable DNS, rejection of unverified scans.
- Queued/running/completed/failed persistence and existing API detail/history functions plus ScanOut serialization.
- Duplicate delivery, fresh/stale leases, bounded interrupted retries, stale-attempt fencing.
- Redis publish failure with durable-row recovery; injected result-commit failure and rollback; notification failure isolation.
- Enforced overall deadline and failure completion timestamps.
- Domain scope, passive suffix-lookalike exclusion, discovery warnings, IPv6-only discovery, private/mixed-IP rejection and pinned stage arguments.
- Actual local loopback TCP port and SSH banner discovery using a test-owned temporary server.
- Generated DER certificate parsing and expiry flags with mocked TLS transport.

No runtime mock scan results were added. Fixtures exist only in tests. git diff --check passed. Frontend tests/build were not rerun because no frontend files changed.

## Remaining unverified / limitations

- Actual PostgreSQL/asyncpg writes, concurrent PostgreSQL row-lock behavior, live Redis interruption/restart, container deployment and Azure integration. SQLite tests do not prove PostgreSQL locking semantics.
- Public DNS propagation, real certificate-transparency responses, public subdomain/port/service/TLS discovery, and real TLS handshake/chain behavior. No external target was scanned.
- This repository has no implemented account authentication or per-user domain ownership model. DNS proof is enforced; account-level authorization is not implemented by these changes. Existing API_SECRET_KEY configuration alone is not authentication.
- Public IP filtering deliberately excludes private/internal networks. DNS ownership is required, but operators must also have authorization for the underlying hosting infrastructure.
- Candidate discovery remains bounded by the existing wordlist and certificate-transparency service; service fingerprints are limited to existing signatures. Results are observations, not proof of exhaustive coverage. Failed entire pipelines do not publish partial successful snapshots.

## Run tests in your normal development environment

Use Python 3.12 to match the Dockerfiles and the pinned asyncpg version. From the project root:

```powershell
cd "C:\Users\Saanvi Garg\OneDrive\Documents\ShowD\ShowDown"
python -m pip install -r api/requirements.txt -r worker/requirements.txt -r api/tests/requirements.txt -e ./shared
python -m unittest discover -s api/tests -v
```

To apply the fixes to your existing configured local containers after review:

```powershell
docker compose up -d --build api worker
```

This rebuild command was not run. Preserve existing environment files and volumes. The update ZIP contains backend code/tests only, not a complete checkout or secrets. Merge it into the existing project; do not replace unrelated files.

## Saved checklist

- [x] Inspect API, queue, worker, models, schemas and all pipeline stages
- [x] Preserve existing frontend and infrastructure
- [x] Repair ownership gates, target scoping, discovery and certificate handling
- [x] Persist recoverable state, bound timeouts/retries and protect completed results
- [x] Add/run 24 regression tests and check diff formatting
- [ ] PostgreSQL/Redis concurrent integration verification
- [ ] Authorized real DNS/TLS discovery and Azure verification
