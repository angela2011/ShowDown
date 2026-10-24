> **24 October update:** Section 1 bug fixes are now applied. See [SECTION1-SETUP.md](SECTION1-SETUP.md) for current setup, verification and resolved backend limitations. Earlier notes below describe the initial delivery.

# ShowDown frontend

React + Vite frontend built on the `frontend` branch. The backend, existing gateway, Azure deployment and infrastructure files have not been changed.

## Start locally

Requires Node.js 20.19+ (Node 22 LTS recommended) and npm.

```powershell
cd "C:\Users\Saanvi Garg\OneDrive\Documents\ShowD\ShowDown\frontend"
npm ci
# Optional: copy .env.example to .env only if .env does not already exist.
npm run dev
```

Open http://127.0.0.1:5173. Live mode is the default. Use **Explore demo data** to view the complete dashboard without a backend. Demo data is visibly labeled and never sent to the API. The mode is session-only; reload returns to live mode.

The default gateway is http://localhost:8080. To use an existing deployed gateway, set this in `frontend/.env` and restart Vite:

```dotenv
API_PROXY_TARGET=https://YOUR-EXISTING-GATEWAY-HOST
```

Use the gateway origin without `/api` at the end. The frontend calls `/api/...`; Vite preserves this path and the existing gateway strips `/api` before forwarding to FastAPI. Do not point this configuration at raw FastAPI without equivalent routing. No API key or credential belongs in frontend source.

## Build and test

```powershell
npm test
npm run build
npm run preview
```

`dist/` is the production output. `preview` checks the build locally; production hosting must serve `dist/` and route `/api/*` to the existing gateway/API. Vite's development proxy is not a production server. No Azure deployment or gateway files were changed and nothing has been deployed. This package does not assume or replace the current Azure architecture.

## Available workflows

- Overview: current asset and port counts, observed security flags, completed scans, asset trend, risk distribution and recent history.
- Assets: hostname search, ports, identified services and inspectable details.
- Findings: host/text search, severity filters and observation details.
- Scan history: all returned scans, statuses, timestamps and complete raw results including diff.
- Domains: registration, displayed DNS TXT records, copy and ownership verification.
- New scan: verified domains only. Polling refreshes the API every 30 seconds; manual refresh is available.
- Export snapshot: JSON containing selected scope, scans, derived inventory, findings and explicit data source.
- Settings: connection guidance, demo/live switch and implemented API capabilities.

## API contract

| Action | Method and path through gateway |
|---|---|
| List domains | GET /api/domains/ |
| Register domain | POST /api/domains/ with {name} |
| Verify DNS ownership | POST /api/verify/{domain_id} |
| Start scan | POST /api/scans/{domain_id} |
| Domain scan history | GET /api/scans/domain/{domain_id} |
| Individual scan client helper | GET /api/scans/{scan_id} |

History responses already contain all scan details, so the UI uses those records for detail dialogs. No unsupported endpoint is called.

### Existing backend response-schema issue

The supplied worker saves `subdomains` as a list of hostnames and `tls_findings` as a list of dictionaries. However, `api/app/schemas.py` declares both fields on `ScanOut` as `dict | None`. FastAPI may reject completed scan responses with response validation errors. This is a backend blocker that cannot be fixed by a browser adapter. Backend owners should align these fields with `list[str] | None` and `list[dict] | None` respectively (or an explicitly supported union if legacy rows use dictionaries), then validate existing database rows. This frontend accepts list and host-keyed dictionary forms. **No backend patch has been applied.**

No local gateway was listening on port 8080 during testing. The frontend's HTTP integration was tested with an isolated fixture API; real DNS checks, workers, PostgreSQL, Redis and Azure end-to-end operation remain unverified.

### Data meaning and limitations

Metrics use each domain's latest completed scan, avoiding duplicate counts across history. A running or failed scan does not erase its previous completed snapshot. The chart displays counts per completed scan (last 24 in selected scope), not an aggregated global time series. Counts can include the same host in overlapping registered scopes.

Findings reflect returned socket/TLS flags. Frontend severity classification: plaintext on an expected TLS port and weak TLS protocol = High; certificate expiring soon = Medium; other observed flags = Low. No current flag is classified Critical. This is a transparent display heuristic, not a backend risk score or confirmed exploit assessment. No IP addresses, CVEs, authentication, honeypot telemetry, WAF actions, or certificate metadata are fabricated when absent from the API. Raw scan details retain supplied evidence and errors.

Live errors remain visible; demo is never an automatic fallback. A failed domain-history request is called out as partial data. A complete connection failure clears displayed data instead of presenting stale values as live.

Fonts use Google Fonts (DM Sans and Space Grotesk) with local sans-serif fallbacks. Icons and charts are code-native. Reduced-motion preferences, keyboard focus, native modal focus containment, mobile navigation and scrollable data tables are supported.

## Source map

- `src/App.jsx`: shell, navigation, API state and workflows.
- `src/components.jsx`: metrics, charts, tables, badges and dialogs.
- `src/api.js`: API transport and error handling.
- `src/data.js`: latest-snapshot adapter, severity mapping and explicit demo fixtures.
- `src/styles.css`: tokens, visual system and responsive styles.
- `tests/`: adapter and HTTP contract unit tests.
- `CHECKLIST.md`: saved progress and outstanding integration work.
- `DESIGN.md`: visual reference decisions and comparison ledger.

Resume from these saved files. Do not re-scaffold or overwrite the backend or deployment configuration.

## Latest visual update

The latest version adds an animated surface radar with clickable asset dots and pause/resume, pink Critical and purple High severity accents, and prominent scan controls with API-derived queued/running status. Demo/offline states are explicitly identified. The radar sweep is decorative; it is not scan progress. Other dashboard features and backend/Azure files are unchanged.

Latest validation: all 7 tests and production build passed. Desktop radar rendering, pause/resume and asset inspection were checked in the in-app browser. This revision's mobile browser recheck was interrupted when the preview tab became unavailable.
