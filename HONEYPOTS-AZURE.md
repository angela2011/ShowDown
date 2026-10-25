# ShowDown passive decoy detection — Azure adaptation

## Implemented scope

The existing scanning worker, DNS authorization, login/password handling, scan risk scoring and Terraform are unchanged. The API gains `/honeypots/*` routes using the same user authentication and owner isolation as the dashboard. The existing gateway exposes these as `/api/honeypots/*`. Decoy findings are separate from scan exposure findings.

`decoy/service.py` supplies a bounded HTTP decoy and a banner-only TCP decoy in a separate process/container. It never executes commands, authenticates a visitor, serves files, connects back to visitors, or invokes scanners. Defaults bind loopback only. Non-loopback binding requires `DECOY_AUTHORIZED_BIND=true`. A separate sensor token authorizes only ingestion and block decisions for that sensor; the agent receives no database password, user bearer token or Azure credentials.

Stored observations include UTC observed/received timestamps, transport source IP, source-verification status, protocol, byte count, payload hash, bounded signal categories, confidence, severity and rule explanations. Raw request bodies, paths, authentication headers, cookies and passwords are not stored. The hash is a fingerprint, not proof of malicious intent. Data is owner-scoped and retained until an operator defines and implements a retention policy.

## Scoring and response safeguards

Confidence version 1 rules: decoy contact +10; credential-related path/verb +30; path traversal +40; shell/exploit-pattern marker +40; at least ten recent contacts from the same IP to that sensor in ten minutes +20. Total is capped at 100. Low <40, Medium 40–69, High 70–89, Critical >=90. This is explainable pattern confidence, not a calibrated probability or confirmed compromise. Health probes and ordinary connections alone are Low. A 4096-byte first sample can miss fragmented or later-stage interactions; this is deliberately not a full protocol emulator.

Responses are **off by default** globally and on every new sensor. To permit responses an operator must set `HONEYPOT_RESPONSE_ENABLED=true` and `HONEYPOT_PROTECTED_CIDRS` to actual administrator, health-monitor and other legitimate-client networks. Then the owner can set the sensor's mode to `manual` or `auto` through the API. Do not blindly copy example CIDRs as a real protection policy.

Manual blocks require an event owned by the sensor, confidence >=70, verified source attribution, evidence no older than ten minutes, exact-IP confirmation and a reason. TTL is 60–3600 seconds. Auto mode additionally requires confidence >=90, at least three contacts in ten minutes, and evidence within two minutes; TTL is five minutes. No CIDR-wide blocks are accepted. Private, loopback, reserved, multicast, protected-network and requesting-operator addresses are refused. Maximum 100 active blocks per sensor. The owner's other sensors and other users' data are not affected.

Enforcement is **application-level and decoy-only**. Direct TCP connections are closed before the banner when blocked. Azure HTTP decoys return 403 after validated ingress attribution. Every decision queries current policy and expiry; no stale block cache persists on the agent. Expired entries are never enforced even if cleanup has not run. Audit status changes to expired on the next decision/history/block request. Unblocking and disabling responses take effect on the next connection. If the API is unavailable the inert decoy fails open and logs `decision_unavailable`; this behavior never controls access to ShowDown's real application. No firewall, NSG, gateway or cloud resource is edited.

Audit rows record detection, policy changes/refusals, block creation/refusal/decision, sensor-reported enforcement, expiry, unblock and sensor revocation. API endpoints do not allow audit modification/deletion. This is not tamper-proof storage against a database administrator. Forward structured logs to existing Log Analytics and use separate retention/immutable storage if required.

## Azure differences from the synopsis

The supplied Terraform uses Azure Container Apps (public nginx gateway and internal core API/worker/Redis), Azure PostgreSQL and Log Analytics. It has no WAF or dedicated decoy environment. The original AWS WAF/SNS/CloudWatch requirements are not implemented by adding AWS resources.

This implementation replaces the first response step with decoy-local denial, deployable in a separate Azure Container App or isolated Azure VM. It does **not** claim WAF-wide protection. Native Container Apps IP restrictions support IPv4 allow or deny lists but cannot mix them, and do not provide per-rule TTL. Safely managing shared gateway restrictions would require a separate, reviewed controller and expiry reconciliation; it is deliberately not performed here. Azure Front Door/Application Gateway WAF integration and Azure Monitor notification/action groups remain future work. No SNS-equivalent notification was added.

References checked:
- https://learn.microsoft.com/en-us/azure/container-apps/ip-restrictions
- https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview

### Source-IP attribution

`DECOY_SOURCE_MODE=proxied` is the safe default: records the socket peer as unverified, ignores forwarding headers, and cannot block. `direct` is only for listeners where the TCP peer is genuinely the remote visitor (for example a controlled local test or explicitly validated direct network path). Do not use direct mode behind Azure HTTP ingress or nginx.

`azure-http` requires nonempty `DECOY_TRUSTED_PROXY_CIDRS` describing the actual trusted ingress peer network. Only complete HTTP headers arriving from that network are eligible. Exactly one X-Forwarded-For header must exist; only its rightmost address (the address supplied by Azure Container Apps) is used. User-supplied leftmost addresses are ignored. Missing, malformed, duplicate or untrusted forwarding headers remain unverified. TCP mode remains unverified behind proxies. Verify these assumptions in an authorized Azure environment before enabling responses, including preventing direct bypass of the trusted ingress. No trusted CIDRs are guessed or configured by this change.

## API contract

User bearer token required:
- `POST /honeypots/sensors` with `{"name":"owned-decoy"}`: returns sensor ID and one-time sensor token; stores only token hash. Maximum 20 sensors per user.
- `GET /honeypots/sensors`: owner list, no token/hash disclosure.
- `GET /honeypots/sensors/{id}/events`, `/blocks`, `/audit`: paginated `{items,next_offset}`, defaults 50, max 200, `offset` supported.
- `POST /honeypots/sensors/{id}/policy` with `{"mode":"disabled|manual|auto"}`.
- `POST /honeypots/sensors/{id}/blocks` with `event_id`, `confirm_ip`, `reason`, optional `ttl_seconds`.
- `POST /honeypots/sensors/{id}/blocks/{block_id}/unblock`.
- `POST /honeypots/sensors/{id}/revoke`: disables the sensor credential. Provision a replacement sensor/token to rotate it.

Sensor bearer token only:
- `POST /honeypots/ingest`: bounded observation schema in OpenAPI. UUID event IDs make retries idempotent; 120 new events/minute/sensor.
- `POST /honeypots/decision` with `source_ip`: current `{blocked,expires_at,scope}`.

Sensor tokens cannot read user histories, change policies or create manual blocks. User sessions cannot impersonate sensor ingestion. A compromised sensor token can falsify its own observations; automated responses must therefore remain restricted to that sensor, never shared infrastructure.

Dashboard: Settings → Honeypot detections & audit. Existing design and auth API client are reused. Sensor selection and paginated events/blocks/audit are read-only; operational provisioning/response is through the authenticated API. Demo mode does not fabricate decoy records or fetch live decoy data.

## Local setup (no deployment)

Use a dedicated test database. No existing local or Azure database was migrated by this work. Additive table script: `python -m app.migrate_honeypots`, with `PYTHONPATH` including `api` and `shared` and `DATABASE_URL` explicitly pointing to the intended database. Review/backup and operator approval are required before running it on production. The existing API's development `Base.metadata.create_all` also creates these new tables on restart; do not restart it against production without schema review. Existing tables and ownership are not rewritten.

1. Start the current auth-enabled API against a separate test database, keeping response flags unset.
2. Register/sign in normally, then create a sensor with the user bearer token. Store its returned sensor token securely in process environment or secret storage, not source code. The dashboard user's token must not be copied to the decoy.
3. From the repository root, install `decoy/requirements.txt` in a dedicated environment and run:

```powershell
$env:DECOY_API_URL='http://127.0.0.1:8095'
# Set DECOY_SENSOR_TOKEN securely to the one-time sensor credential.
$env:DECOY_SOURCE_MODE='direct' # loopback test only
$env:DECOY_BIND='127.0.0.1'
$env:DECOY_OUTBOX='C:/path/to/test-only/outbox.sqlite'
python -m decoy.service
```

HTTP listens on 9080 and TCP on 9021; override with `DECOY_HTTP_PORT` and `DECOY_TCP_PORT`. Use `DECOY_API_URL=https://your-authorized-gateway/api` when using nginx; raw FastAPI uses no `/api`. Redirects are not followed, external HTTP transport is refused, and proxy environment variables are not trusted by the agent. No background task is installed.

The outbox survives restarts on a persistent volume, retains events until acknowledged and retries temporary failures. Capacity is 10,000 pending events; overflow is logged and new events are dropped, never silently reported as persisted. Max 32 active connections, 4096-byte reads and three-second read/write timeouts bound the decoy. Protect the spool with filesystem permissions. Alert on overflow, delivery failures and unavailable decisions. A permanent malformed/unauthorized delivery currently requires operator intervention; do not discard the spool to hide an error.

## Azure resources/permissions still required

- Separate decoy compute/environment with least-privilege network isolation; **do not add the decoy as a core-app sidecar**. No DB access, no scanner tools, no host mounts, no managed identity with cloud-write privileges.
- Only authorized decoy ingress ports; egress restricted to the configured telemetry API and platform needs. Azure TCP external ingress may require additional network setup; no VNet or TCP exposure was added.
- A persistent volume for the outbox, a sensor token in Azure secret storage, appropriate TLS and tested trusted-ingress ranges for source attribution.
- API DB principal needs creation rights only during additive migration and normal DML on the four decoy tables afterwards.
- Container deployment/network permissions are needed only for a future operator deployment. Runtime needs **no Azure RBAC write permission** for the implemented decoy-local blocker. A future WAF/native-ingress controller would need tightly scoped read/write rights on a dedicated decoy resource, not the shared gateway.
- Existing Log Analytics can receive stdout/stderr when the decoy is attached to an appropriately configured environment. Retention, alerts, audit immutability, scale/load testing and production PostgreSQL concurrency validation remain operational work.

## Verification scope

Final results: **67 backend tests passed** (including 13 honeypot tests), **32 frontend tests passed**, and the Vite production build passed. `git diff --check` passed. All results are local; no real Azure integration test was run.

Tests use in-memory SQLite and controlled loopback sockets. Public-IP block records are synthetic test inputs only; no network call or cloud rule targets those addresses. Azure ingress/forwarding is simulated, not a real Azure integration test. No infrastructure was provisioned, no existing data reset, no real IP blocked and no scans performed.

## Changed files

- `shared/shared/models.py`: four additive decoy ORM tables.
- `shared/shared/honeypot.py`: independent explainable confidence and protected-IP rules.
- `api/app/routes/honeypots.py`: sensor credentials, owner-scoped histories, detection ingestion, policy/response/expiry/audit APIs.
- `api/app/main.py`: register the new router only.
- `api/app/migrate_honeypots.py`: operator-invoked additive table creation, tested only in memory.
- `decoy/__init__.py`, `decoy/service.py`, `decoy/requirements.txt`, `decoy/Dockerfile`: isolated runtime, durable outbox, bounded passive listeners, optional container recipe.
- `api/tests/test_honeypots.py`: loopback integration and simulated response/authorization regression tests.
- `frontend/src/HoneypotPanel.jsx`, `frontend/src/App.jsx`: existing Settings page gains read-only owner-scoped history, without changing navigation/design/demo fixtures.
- This document: Azure adaptation, setup, safeguards and remaining gaps.

No existing worker, auth/password logic, risk-scoring rules, Terraform, nginx, compose, database credentials or deployment workflows were changed. No commits/pushes/deployments were performed. Docker image build, production PostgreSQL concurrency and real Azure integration were not tested.

Test commands (from repository root with the existing Python dependencies installed):

```powershell
$env:PYTHONPATH="$PWD/api;$PWD/shared;$PWD/worker"
python -B -m unittest discover -s api/tests -v
Set-Location frontend
npm test
npm run build
```

The Python tests explicitly replace database access with in-memory SQLite; do not invoke the migration CLI as part of validation against a live database. Browser checks used Playwright/Edge with controlled API fixtures: sensor selection, event/block/audit pages, pagination, demo isolation and 390px/320px layouts passed with no JavaScript errors. Fixture browser checks are not evidence of Azure operation.
