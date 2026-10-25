# Scan notifications (Slack, Azure-compatible existing delivery)

The synopsis describes alerts through SNS. This implementation keeps ShowDown's
existing Slack webhook delivery in the Azure worker; it adds no AWS resources,
Azure resources, monitoring, scheduling or honeypot features. Before this change,
`build_alert_message` only reported newly discovered subdomains/open ports, skipped
the baseline and did not check HTTP delivery results. Those change alerts remain.
The existing risk engine and TLS probes already produce the required evidence;
neither is modified.

## Triggers

- Significant risk increase: total score rises at least 20 points to 40 or above,
  or crosses High (70) or Critical (90). Also alerts on a new/escalated High or
  Critical finding even when another finding keeps the aggregate maximum unchanged.
  Comparisons use the previous completed scan's risk, reconstructing legacy scores
  using the existing risk engine if necessary. Baseline risk is not an increase.
- Certificate expiry: existing `certificate_expiry` risk findings supply evidence.
  Buckets are <=30 days, <=7 days (including zero), and expired (<0). These also
  alert on baseline scans. Each endpoint/finding, expiry date and bucket forms a
  stable identity; changing the remaining-days number alone cannot spam alerts.
  Missing/unreachable certificate observations do not generate invented evidence.
- Evaluation happens at completed scans, not on an independent daily certificate
  timer. Scheduled scans can provide fresh observations without any scheduler change.

Messages include scan ID and risk/expiry summaries. The existing scan API retains
the full evidence. At most 20 event summaries are included, with an omitted-events
count; message text is bounded and Slack mention/link control characters escaped.

## Durable delivery and limits

`scan_notifications` is an additive outbox table. One row per scan is committed
with the completed result, preventing a crash between scan completion and enqueue
from silently losing the notification. No historical scans are backfilled.

PostgreSQL domain row locks serialize delivery claims across workers. Matching
risk/change events are suppressed for 24 hours; matching certificate buckets for
30 days. Continued expired certificates can remind again after that window.
Distinct events wait for the per-domain cooldown (default one hour). They are
bundled per scan. Pending deliveries older than 24 hours expire rather than send
stale reports. Records remain for operator inspection; no retention deletion is run.

Delivery is checked for HTTP 200 with Slack's `ok` body. HTTP 429 honors Retry-After
(minimum 60 seconds, capped at seven days, beyond the 24-hour pending lifetime).
HTTP 5xx retries with backoff. Maximum three attempts, persisted across restarts.
Other responses are terminal failures. No response bodies, webhook URLs or raw
exceptions are stored in delivery errors or explicitly logged by this feature.

Transport errors/timeouts are `uncertain` and are not automatically retried, because
Slack may already have accepted the request. A process crash after a committed
`sending` claim leaves that row for operator review, also without automatic resend.
Exactly-once external delivery cannot be guaranteed: even a server returning 5xx
could theoretically accept a message. Operators should inspect the channel before
manually retrying ambiguous records. Terminal failures require operator attention;
this feature does not add a retry UI or monitoring system.

The worker recovers due notifications on its existing recovery loop, up to 100 at
a time. Timing can be delayed while scans run. Owner changes or inactive users
cancel pending messages. The existing single webhook is an installation-wide
trusted operator channel, NOT separate user destinations: do not point it at a
channel whose members are not authorized to see every participating owner's data.
Per-domain cooldown is not a global cross-domain webhook rate limiter; Slack's
429 responses provide delivery backoff during installation-wide bursts.

## Configuration and activation (not performed here)

1. An authorized operator confirms the intended database and runs
   `python -m app.migrate_notifications` from the API runtime, with its existing
   DATABASE_URL and required REDIS_URL configured. The migration creates only the
   new outbox table, checks for the authentication schema, and is idempotent. It
   does not modify existing records or execute other migrations. The API's existing
   metadata startup also creates the table, but use the explicit migration for a
   controlled rollout. Roll out the schema before a worker with Slack enabled.
2. Package the updated shared/API/worker source with existing Dockerfiles. No CI,
   Terraform or existing deployment resource changes are required or were made.
3. Set the existing `SLACK_WEBHOOK_URL` worker secret. Without it, new notifications
   are not queued and delivery recovery is paused. Existing pending records retain
   their 24-hour lifetime. Never commit a webhook or share it in logs/chat.
4. Optional worker environment variables: `ALERT_RISK_INCREASE` (default 20,
   clamped 1–100), `ALERT_COOLDOWN_SECONDS` (default 3600, clamped 60–86400).
   Invalid integer strings fall back to defaults. Existing Azure `slack_webhook_url`
   input/secret wiring can be reused. Optional overrides need an authorized operator
   to configure them in the worker environment; default behavior needs no new wiring.
5. A teammate with Slack app/channel access must approve/create the incoming
   webhook in an authorized channel. Azure access is required to configure its
   existing secret, package/roll out the worker and verify outbound HTTPS access.
   No real Slack message or Azure integration test was sent/run for this task.

## Tests

From `api/` using the existing backend test environment:

```powershell
python -m unittest discover -s tests -p test_notifications.py -v
python -m unittest discover -s tests -q
```

Tests use isolated SQLite, mocked scans/DNS and httpx MockTransport/AsyncMock Slack
delivery. They cover risk thresholds, High/Critical finding escalation, certificate
boundaries, stable bucket IDs, baseline behavior, persistent deduplication/cooldown,
backoff/exhaustion, unknown outcomes, scan-result safety, owner changes, escaping,
crash claims, stale expiry and the additive migration. PostgreSQL concurrent row
locking and actual Azure/Slack delivery still require an authorized integration test.

Changed files: `shared/shared/models.py`, `worker/worker/main.py`,
`worker/worker/notifications.py`, `api/app/migrate_notifications.py`,
`api/tests/test_notifications.py`, and this document.

Verified locally: all 92 backend tests passed, including 16 new notification tests;
`git diff --check` passed. Slack was mocked and the full test process explicitly
cleared SLACK_WEBHOOK_URL. No live database migration, deployment, commit or push
was performed. The existing untracked showdown_backup.sql was left untouched.
