# ShowDown — bug fixes and visual follow-up

Updated 24 October 2026. Work is saved on the existing frontend branch, without a commit. History/date-navigation/comparison features remain deferred. The requested visual follow-up is now included: pink Critical, orange High, yellow Medium, teal-green Low; transparent sidebar scrollbar; running-scan pulse, finite new-asset highlights and completed-snapshot fades. Existing pages, layout, typography, radar and API workflows remain.

## Start the frontend

Requires Node.js 20.19+ (Node 22 LTS is suitable).

```powershell
cd "C:\Users\Saanvi Garg\OneDrive\Documents\ShowD\ShowDown\frontend"
npm ci
npm run dev
```

Use the URL printed by Vite. The usual URL is http://127.0.0.1:5173; verification used port 5175 because 5173 and 5174 were already occupied. Default API gateway: http://localhost:8080. Optional `frontend/.env`: `API_PROXY_TARGET=https://your-existing-gateway-host` (origin only, no trailing /api). Restart Vite after changing it. Do not replace existing environment files.

```powershell
npm test
npm run build
npm run preview
```

The production output is frontend/dist. Production hosting must serve these static files and route /api to the existing gateway. Nothing has been deployed to Azure.

## Apply backend fixes locally

The actual local files are already modified. The ZIP also includes the five changed/added backend implementation files and backend tests alongside the complete frontend. It is an update bundle, not a full backend checkout. If using a separate checkout, review and merge those files into that checkout rather than replacing the entire repository. No secrets, .env files, infrastructure or unrelated backend files are included.

To rebuild existing local containers with the code fixes, run from ShowDown:

```powershell
cd "C:\Users\Saanvi Garg\OneDrive\Documents\ShowD\ShowDown"
docker compose up -d --build api worker
```

This command is provided for you; it was not run during this review. It assumes your existing Docker environment and services are configured. Existing PostgreSQL volumes must be preserved. No database migration or data rewrite is required. Do not use `docker compose down -v`.

Backend tests (Python 3.12 recommended for the repository's pinned asyncpg dependency):

```powershell
python -m pip install -r api/requirements.txt -r worker/requirements.txt -e ./shared
python -m unittest discover -s api/tests -v
```

During review an isolated test environment ran the schema/worker tests with mocked database and scan operations. The system Python 3.13 could not build pinned asyncpg without Microsoft C++ build tools, so driver-backed integration was not run. Backend dependency pins were not changed.

## Fixed

- ScanOut accepts worker lists and legacy dictionaries/nulls for subdomains and TLS findings.
- Existing timezone-naive PostgreSQL timestamp columns are retained. New writes are normalized to naive UTC; API timestamps explicitly serialize as UTC. Existing rows are not rewritten.
- Worker exception handling rolls back failed transactions before recording failure.
- Manual refresh has a shared five-second cooldown, coalesced GET requests, no overlapping polling batches, bounded three-domain fan-out and Retry-After backoff for HTTP 429.
- Malformed domain/history responses are rejected. Partial responses visibly identify missing histories; metrics omit those histories. Complete failures clear live data, and demo never substitutes automatically.
- Failed scans have an explicit message with available worker error details. Refresh/loading and last synchronization are visible.
- Grid/flex children shrink correctly on mobile. Hidden table labels are constrained to their scroll container; wide tables scroll internally rather than widening the page.
- Sidebar scrolls vertically, has a transparent scrollbar, and keeps its footer reachable on short screens. Mobile navigation exposes expanded state and closes with Escape.
- Modal focus returns to its opener, including React Strict Mode. Invalid dates are rejected, timezone offsets are preserved, and demo completion times are no longer in the future.

## Verification

- Frontend: 12 tests passed; production build passed.
- Backend: 5 tests passed (list/legacy/null schema payloads, UTC conversion and column compatibility, mocked worker completion and failure).
- In-app browser: desktop, 390px and 320px overflow checks; short-screen sidebar, Escape handling and modal focus restoration.
- Separate read-only fixture API: running indicator, failed-scan message, partial histories, rate-limit message/cooldown and no silent demo fallback verified.
- Actual local API: GET /api/ returned healthy; GET /api/domains/ returned an empty list. No targets were added and no real scans were started. Running containers were not rebuilt, so this does not prove the updated backend is deployed.
- Still unverified: real PostgreSQL writes through asyncpg, DNS ownership verification, queue/worker networking and Azure end-to-end integration.

## Files changed

Backend: api/app/schemas.py; shared/shared/models.py; shared/shared/time_utils.py; worker/worker/main.py; api/tests/test_scan_contract.py.
Frontend: src/App.jsx, src/ScanVisuals.jsx, src/api.js, src/useMonitor.js, src/validation.js, src/components.jsx, src/data.js, src/styles.css; tests/api.test.js and tests/bugs.test.js. Existing data tests remain.

## Deferred

Do not begin section 2 until the user's next prompt: date filters, month/year navigation, historical snapshots and scan comparisons. The requested severity and animation follow-up is now implemented; reduced motion is respected. Missing existing APIs still block authentication, target editing/deletion, scheduling, finding actions and decoy/WAF logs; none were fabricated.

## Visual follow-up verification

12 frontend tests and production build passed again. Playwright with installed Edge was used because the Browser plugin and bundled Playwright browser were unavailable. Desktop 1440x1000 and mobile 390x844 rendered with no page errors or framework overlay. Verified High radar color RGB(249,172,104), transparent scrollbar, Pause sweep interaction, reduced-motion animation suppression and mobile scroll width 390px. No real scans were initiated. New assets are identified by the existing worker diff; animations finish after 1.6 seconds. Snapshot changes fade for 280ms without remounting controls. No historical snapshot navigation has been added.
