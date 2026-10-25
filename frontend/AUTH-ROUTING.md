# Authentication routing

The browser always calls /api/auth/register and /api/auth/login. FastAPI exposes /auth/register and /auth/login. Both accept passwords of 6–128 characters.

The current localhost:8080 gateway responds to /api/openapi.json, but its running backend has no /auth/* routes. This is an older runtime, not a missing /api prefix in the frontend. Source changes alone do not update a running container. Do not send credentials to alternative endpoints as an automatic fallback.

Gateway mode (default): API_PROXY_MODE=gateway; API_PROXY_TARGET=http://localhost:8080. Vite preserves /api and nginx removes it exactly once. The gateway must target an API running the current auth-enabled source and compatible database schema.

Direct local API mode, PowerShell from frontend/:

```powershell
$env:API_PROXY_TARGET='http://127.0.0.1:8095'
$env:API_PROXY_MODE='direct'
npm run dev
```

This requires an independently started current FastAPI service on port8095, connected to the intended database. Vite removes /api in direct mode. Restart Vite after changing configuration. Do not point gateway mode at raw FastAPI or direct mode at nginx. Never change the browser API paths to bypass authentication or silently use a different database.

Inspect /openapi.json on raw FastAPI or /api/openapi.json through the gateway. Expect POST /auth/register, POST /auth/login, GET /auth/me and POST /auth/logout. Existing databases require the explicit authentication migration if domains.owner_id is missing; preserve and verify backups and ownership before operator-approved migration. No running service, database migration or deployment was changed for this routing fix.

Vite proxy settings are development/preview settings, not production infrastructure. Existing nginx configuration is unchanged.
