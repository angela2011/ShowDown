## Visual follow-up — 24 October 2026
- [x] Semantic severity palette; purple retained for brand/navigation/focus
- [x] Transparent sidebar scrollbar; scrolling preserved
- [x] Real running-scan pulse, finite new-asset highlight, completed snapshot fade
- [x] Reduced-motion support; decorative radar disclosure preserved
- [ ] Date/history navigation remains deferred

# Current delivery: section 1 only (24 October 2026)

- [x] Inspect existing frontend branch and preserve unrelated work
- [x] Fix worker-list/legacy ScanOut serialization
- [x] Normalize naive-UTC writes without a database migration
- [x] Refresh cooldown, deduplication, rate-limit and partial-response handling
- [x] Explicit loading, failure and synchronization state
- [x] Mobile overflow and scrollable sidebar fixes
- [x] Modal focus and mobile Escape handling
- [x] 12 frontend tests, 5 backend tests and production build passed
- [x] Browser checks at desktop, 390px and 320px; fixture API error states
- [x] Read-only actual API health/domain checks
- [ ] Real DNS, asyncpg/PostgreSQL and Azure end-to-end verification
- [ ] Section 2 and subsequent changes: wait for user's next prompt

History/date/comparison and redesign additions from this turn were removed before delivery. Existing backend containers were not rebuilt. See SECTION1-SETUP.md.

---
Previous checklist (historical):

# ShowDown frontend checklist

Updated 23 October 2026. Branch: frontend.
All implementation files are saved in the actual ShowDown/frontend directory. No backend, gateway, infrastructure, Azure deployment or unrelated project file was changed. Changes are saved but not committed.

## Completed
- [x] Read synopsis and inspect ZIP; compare backend sources with local project
- [x] Confirm frontend branch and preserve existing backend/deployment
- [x] Generate complete dashboard concept and define visual tokens
- [x] Build React + Vite overview, assets, findings, history, domains and settings
- [x] Add responsive layouts, accessible dialogs and reduced-motion support
- [x] Integrate supported API routes and 30-second refresh
- [x] Derive inventory from latest completed scan per domain
- [x] Add visibly labeled, opt-in demo mode with no backend mutations
- [x] Implement search, severity filter, scope, details, DNS TXT copy and export
- [x] Pass 7 unit tests (data adapter and HTTP client contracts/errors)
- [x] Pass production build; npm install audit reported zero vulnerabilities
- [x] Verify in-app browser desktop 1536x1024 and mobile 390x844
- [x] Verify asset search/details, severity filter, mobile navigation and scoped empty states
- [x] Verify fixture registration -> verification -> queued scan -> completed results
- [x] Verify export feedback and clean fixture/demo browser console
- [x] Inspect concept and final desktop/mobile screenshots with view_image
- [x] Save README and design comparison ledger
- [x] Package complete frontend ZIP with source, lockfile, tests, docs and dist

## Remaining external integration checks
- [ ] Backend owner: align ScanOut subdomains and tls_findings types with worker list payloads
- [ ] Start existing backend or configure an existing deployed gateway in frontend/.env
- [ ] Verify real DNS ownership, worker execution and completed scan responses end to end
- [ ] If desired later, configure production static hosting and /api routing; Azure is unchanged

No real network scan was started during testing. Fixture tests use isolated .example domains and an in-memory local test API. Resume from saved files; do not re-scaffold.

## Requested visual refinement
- [x] Add animated, selectable asset radar; respect reduced motion and allow pause
- [x] Apply pink Critical and purple High accents to findings, chart and radar
- [x] Highlight scan actions and show API-derived running/queued/offline/demo status
- [x] Revised production build and 7 tests passed; desktop radar, pause and asset details verified
- [ ] Recheck revised mobile controls (browser tab became unavailable during final check)
