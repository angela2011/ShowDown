# ShowDown — Attack Surface Management

ShowDown is a self-hosted Attack Surface Management (ASM) platform that helps organizations discover, monitor, and assess their internet-facing assets. It combines domain verification, network scanning, service and TLS security checks, scan history, authentication, and honeypot-based threat detection in a web dashboard.

The project follows an authorization-first approach: scan only domains and assets you own or have explicit permission to assess.

## Features

### 1. Authentication and Dashboard
- User registration and login.
- Protected dashboard with session validation.
- Authenticated API requests using bearer tokens.
- Logout and server-side token revocation.
- Session expiration and handling of invalid or expired sessions.
- User-scoped domain access and authorization checks.

### 2. Attack Surface Discovery and Scanning
The scan pipeline includes:

1. **Subdomain discovery** — discovers subdomains using certificate-transparency data and DNS wordlists.
2. **Port scanning** — checks common TCP ports on discovered hosts.
3. **Socket security analysis** — performs banner grabbing, service fingerprinting, and basic protocol checks.
4. **TLS analysis** — examines certificate validity, expiration, supported protocols, and cipher configuration.
5. **Change detection** — compares scan results to identify new or changed findings.
6. **Results storage** — stores scan data and history in PostgreSQL.

### 3. Domain Verification and Scope Management
- Register domains for monitoring.
- Verify domain ownership using a DNS TXT record challenge.
- Queue scans and retrieve scan results.
- Restrict access to domain data based on user ownership.

Only scan authorized targets. Domain verification should remain enabled.

### 4. Honeypot-Based Threat Detection

ShowDown includes a honeypot feature designed to detect suspicious interactions with controlled decoy services.

- Isolated HTTP and TCP decoy services.
- Interaction records for investigating suspicious activity.
- Redacted detection records.
- Owner-scoped detection history.
- Explainable confidence scoring and four severity levels: Low, Medium, High, and Critical.
- Audited blocking and unblocking workflows, including expiration handling.
- Dashboard access to detections, blocks, and audit history through Settings.

**Safety defaults:** Blocking is disabled by default and is intended to be limited to the decoy environment. Honeypot activity should not be used to block unrelated users or systems automatically.

### 5. Dashboard and API
The frontend provides a public landing page, login and registration screens, and a protected dashboard.

The backend exposes API functionality for authentication, domain management, verification, scanning, and honeypot operations. Nginx acts as the API gateway, while Redis supports job queuing and the worker processes scan tasks.

## Architecture

```text
                     Browser
                        |
                  React Frontend
                        |
                   Nginx Gateway
                        |
                   FastAPI Backend
                    /    |     \
                   /     |      \
             PostgreSQL Redis   Auth
                   |      |
             Scan Results Queue
                          |
                     Scan Worker

           Dashboard / Settings
                    |
             Honeypot API
                    |
           Isolated Decoy Services
                    |
           Detection and Audit Logs
```

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, Vite, JavaScript, CSS |
| Backend API | Python, FastAPI |
| Database | PostgreSQL |
| Job queue | Redis |
| Reverse proxy | Nginx |
| Background processing | Python asyncio worker |
| Authentication | Bearer-token authentication |
| Decoy services | Python HTTP/TCP services |
| Development environment | Docker Compose |

## Project Structure

```text
ShowDown/
├── api/
│   ├── app/
│   │   ├── main.py
│   │   ├── routes/
│   │   │   └── honeypots.py
│   │   └── migrate_honeypots.py
│   └── tests/
│       └── test_honeypots.py
├── decoy/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── service.py
├── frontend/
│   └── src/
│       ├── App.jsx
│       └── HoneypotPanel.jsx
├── shared/
│   └── shared/
│       ├── models.py
│       └── honeypot.py
├── worker/
├── nginx/
├── docker-compose.yml
├── HONEYPOTS-AZURE.md
└── README.md
```

## Getting Started

### Prerequisites
- Git
- Docker Desktop with Docker Compose
- Node.js and npm, for running the frontend separately

### 1. Clone the repository

```bash
git clone https://github.com/angela2011/ShowDown.git
cd ShowDown
```

### 2. Configure environment variables

Create a local `.env` file using `.env.example` as a reference, if provided. Configure the database connection, authentication secrets, and other required environment variables.

**Do not commit `.env`, passwords, API keys, or database backups.**

### 3. Start the backend services

```bash
docker compose up --build -d
```

For an existing database created before authentication was added, run the required authentication migration before starting the updated API and worker:

```bash
docker compose run --rm --no-deps --entrypoint python api -m app.migrate_auth
```

Run any additional required schema migration for the honeypot feature before using it. Back up existing database data before applying migrations.

### 4. Run the frontend

Open a separate terminal:

```powershell
cd frontend
npm install
npm test
npm run build
npm run dev
```

Open the local URL printed by Vite, typically `http://localhost:5173`.

The development proxy is configured to use the Nginx gateway at `http://localhost:8080` by default. Keep the `/api` prefix consistent with the gateway configuration.

### 5. Check Docker services

From the project root:

```bash
docker compose ps
docker compose logs --tail 50 api
```

Confirm that the API, Nginx, PostgreSQL, Redis, and worker services are healthy before testing the complete workflow.

## Development and Testing

Frontend tests and production build:

```bash
cd frontend
npm test
npm run build
```

Backend tests can be run in the configured Python environment using the project's test dependencies:

```bash
pytest api/tests
```

Test authentication, domain ownership, scanning, honeypot detection, and audit behavior before deploying changes.

## Security Considerations

- Scan only authorized targets.
- Keep credentials and secrets out of source control.
- Use HTTPS and secure secret management in production.
- Keep decoy services isolated from application and production systems.
- Review detection and blocking audit records.
- Back up PostgreSQL before schema migrations.
- Do not enable automated blocking until its scope, expiration, and recovery behavior have been verified.
- Browser session storage is used for bearer-token sessions; it is accessible to JavaScript and is not equivalent to an HttpOnly-cookie design.

## Azure Deployment Status

The repository includes `HONEYPOTS-AZURE.md` for Azure deployment planning. The local Docker-based feature implementation does **not** by itself establish that Azure hosting, ingress, persistent production storage, secrets, or cloud blocking integration have been configured and verified.

Before production deployment, configure and test isolated decoy hosting, persistent storage, sensor secrets, ingress restrictions, monitoring, and a verified response mechanism. Do not assume that local blocking behavior automatically integrates with Azure networking or a shared gateway.

## Project Status

Implemented locally:
- Frontend authentication screens and protected dashboard routing.
- Backend authentication and user-scoped access controls.
- Domain verification and scan workflow.
- Honeypot service, detection records, confidence scoring, and audit-related workflows.
- Docker-based local development and testing.

Deployment, cloud integrations, and production security controls must be verified independently before the system is considered production-ready.
