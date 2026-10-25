# Azure-native scheduled scanning

Implements the synopsis's recurring authorized scanning requirement with an Azure
Container Apps scheduled job, replacing the AWS EventBridge scheduling role.
The existing worker still performs discovery, risk scoring and result persistence.
No discovery, honeypot, frontend, monitoring or alert implementation is changed.

## Architecture and safety

`infra/scheduling.tf` adds an opt-in Container Apps Job to the existing environment.
It runs the existing API image with `python -m app.scheduler` every five minutes UTC.
No new image, Docker Compose service or GitHub Actions publishing step is needed:
the existing API Dockerfile copies app modules, and the existing build-images
workflow already packages that image. No workflow was triggered by this change.

Authenticated owners configure one schedule per registered domain using:

- `PUT /schedules/{domain_id}` with `{"enabled":true,"interval_minutes":1440}`.
- `GET /schedules/{domain_id}` for timing, latest dispatch outcome and scan ID.
- Disable using PUT with `enabled:false` and the desired interval.

Through the existing gateway these paths start with `/api/schedules/`. Use the
normal Bearer session token. Anonymous access returns 401; another owner's domain
returns 404. No client-supplied owner IDs or arbitrary target hostnames are accepted.
Intervals are integer minutes, from 60 to 43200 (30 days). Setting a schedule
resets its next occurrence to now plus the interval; it does not scan immediately.
New installs and existing domains have no schedules until explicitly configured.
There is no scheduler admin HTTP endpoint or stored user password/session token.

The job authenticates to PostgreSQL using the existing database secret in Azure.
Azure RBAC controls who can create, edit or manually execute the job. This reuses
the project's password-based database authentication, not Entra database auth.
Restrict job configuration/secret access to trusted operators; the current shared
database credential is broader than a dedicated least-privilege scheduler role.

Each occurrence rechecks the active owner, matching schedule owner, verified flag,
hostname syntax and current DNS TXT record. Unassigned legacy targets are excluded.
Ownership mismatch disables the schedule and clears verification; DNS lookup
failure queues nothing and defers retry for five minutes. The worker independently
rechecks ownership and retains its existing public-address and hostname scope checks.

A PostgreSQL domain row lock serializes periodic and manual enqueue operations.
Queued/running scans are reused/skipped, not duplicated. The new queued Scan row and
next due time commit together. Database failure rolls back both; an Azure retry
can safely try again. Missed intervals are coalesced, never replayed as a burst.
Only the earliest 100 due targets are processed per tick; larger installations need
capacity review/batching changes, especially with a single scanning worker.

The job deliberately does not contact Redis: Redis is a localhost sidecar of the
core app and cannot be reached from another job as localhost. PostgreSQL Scan rows
already form the worker's durable outbox. Existing `recover_pending` discovers
them on its recovery cycle (nominally every 30 seconds; longer during busy scans).
`REDIS_URL` is supplied only because the reused API settings require it.
Existing worker leases, interrupted-job retries and terminal failed/completed
states apply unchanged. Failure details/results are available through the normal
owner-scoped scan-history APIs. Schedule status describes dispatch, not scan success;
follow `last_scan_id` to retrieve the actual result.

## Activation checklist (not performed by this implementation)

1. Confirm the intended database, backup policy, authentication schema and current
   API/worker versions. Do not point testing at production or assign legacy owners.
2. Package the current API image with the existing Dockerfile/workflow. Use an
   immutable `image_tag` also available to the Container Apps Job. Private GHCR
   images require registry pull credentials configured for the job, as for other
   private image consumers; no registry secret has been invented or committed here.
3. With the intended DATABASE_URL and required REDIS_URL explicitly configured,
   run `python -m app.migrate_schedules` from the API runtime. This creates only
   `scan_schedules`, idempotently, and refuses a legacy domains schema lacking
   owner_id. It does not run auth/honeypot migrations or change existing records.
   API startup's existing metadata creation also creates this new table, but use
   the explicit migration in controlled environments. No real DB migration was run.
4. Set `scheduled_scanning_enabled = true` in the intended Terraform inputs only
   after the schema and current worker are ready. Review the complete plan before
   any separately authorized apply. Default false provisions no job.
5. Ensure Microsoft.App is registered, the subscription/region supports Container
   Apps Jobs, the operator has job/environment write permissions, and the job can
   reach the existing PostgreSQL server using TLS and perform DNS resolution.
   Reuses existing environment/database/firewall; no new public ingress or AWS
   resources. No cloud resource was deployed or changed during implementation.
6. An authenticated owner enables schedules only for verified authorized targets.
   Validate actual Azure execution and resulting history using an owned test target.

The Azure resource has one replica per execution, a 1200-second timeout and two
platform retries. Database locking still handles overlaps across separate executions.
All stored timestamps use existing UTC conventions; API schedule timestamps include
an explicit UTC offset. UTC cron does not shift with daylight saving time.

## Local regression tests

From `api/`, with the existing backend test environment and dependencies installed:

```powershell
python -m unittest discover -s tests -p test_schedules.py -v
python -m unittest discover -s tests -q
```

Run from `api/` to avoid loading the repository's Docker-only root .env into API
Pydantic settings (its unrelated keys are rejected by the existing configuration).
Tests use isolated SQLite and simulated DNS/scanning, including actual ORM worker
recovery and API history. They never scan an external target. SQLite does not
exercise PostgreSQL row locks; concurrent PostgreSQL execution and real Azure job,
DNS, image-pull, RBAC and network integration remain to be verified separately.

Reference: https://learn.microsoft.com/azure/container-apps/jobs

## Verified results and changed files

Local verification: all 76 backend tests passed, including 9 scheduling regression
tests. `git diff --check` passed. Terraform validate and formatting passed in an
isolated configuration copy with AzureRM 4.81.0 and random 3.9.1. The repository's
existing lock file lacks matching Windows provider checksums; it was preserved.
No Terraform plan/apply, application-database migration, container recreation,
image publication, real DNS ownership test or real scan was performed.

Files changed/added for this feature:

- `shared/shared/models.py`: additive ScanSchedule model.
- `api/app/routes/schedules.py`: authenticated owner configuration/read endpoints.
- `api/app/main.py`: register schedule routes.
- `api/app/routes/scans.py`: serialize manual triggers with scheduled triggers.
- `api/app/scheduler.py`: bounded one-shot due-scan dispatcher.
- `api/app/migrate_schedules.py`: explicit schedule-table-only migration.
- `api/tests/test_schedules.py`: authorization, dispatch, retry, persistence tests.
- `infra/scheduling.tf`: opt-in Azure Container Apps scheduled job.
- `SCHEDULED-SCANNING-AZURE.md`: configuration, boundaries and verification notes.

Existing worker/discovery/honeypot/frontend/Docker/CI files and the pre-existing
untracked `showdown_backup.sql` were left unchanged. No commit or push was made.
