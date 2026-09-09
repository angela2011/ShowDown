# AttackSurface Monitor

A self-hosted attack surface management tool. Continuously discovers and
monitors an organization's internet-facing footprint: subdomains, open ports,
raw socket-level service fingerprinting, and TLS/certificate health. Flags
changes over time and alerts via webhook.

## Architecture

```
Client -> Nginx (API gateway, rate limiting, TLS) -> API (FastAPI)
                                                          |
                                                     Job Queue (Redis)
                                                          |
                                                    Worker (asyncio)
                                                          |
        subdomain_enum -> port_scan -> socket_scan -> tls_check -> diff_engine
                                                          |
                                                     Postgres (results)
                                                          |
                                                  Alerts (Slack webhook)
```

## Scan pipeline

1. **subdomain_enum** — passive discovery via certificate transparency (crt.sh)
   + DNS brute force against a wordlist.
2. **port_scan** — async TCP connect scan across common ports per discovered host.
3. **socket_scan** — for each open port: raw banner grab, protocol fingerprinting,
   and basic socket-level checks (e.g. does it respond to garbage input, TLS on
   plaintext port, default credential prompts). This is the new layer sitting
   between port discovery and TLS analysis.
4. **tls_check** — cert chain validation, protocol/cipher support, expiry.
5. **diff_engine** — compares this snapshot to the previous one, flags new/changed
   findings.
6. Results stored in Postgres, diffs trigger Slack/webhook alerts.

## Local development

```bash
cp .env.example .env
docker compose up --build
```

- API: http://localhost:8080 (behind Nginx)
- Postgres: localhost:5432
- Redis: localhost:6379

## Important: scope

Only scan domains you own or have explicit permission to test. The `/verify`
endpoint implements a DNS TXT record challenge — a domain must be verified
before it can be added for scanning. Don't remove this check.

## Project layout

```
attacksurface-monitor/
├── nginx/           reverse proxy + rate limiting config
├── api/             FastAPI app: domain registration, verification, scan results
├── worker/          asyncio worker: the actual scanning pipeline
├── shared/          ORM models (installed as a pip package into both api & worker
│                    images so the two services agree on one schema)
├── scripts/         DB init SQL
└── infra/           IaC placeholder (Terraform for AWS/Azure)
```

## Scan pipeline modules (worker/worker/tasks/)

- `subdomain_enum.py` — crt.sh + DNS brute force
- `port_scan.py` — async TCP connect scan
- `socket_scan.py` — **socket security layer**: banner grabbing, protocol
  fingerprinting, plaintext-on-TLS-port detection, version disclosure flags
- `tls_check.py` — cert chain, protocol/cipher, expiry
- `diff_engine.py` — compares snapshots, builds alert text

## Next steps to extend this scaffold

1. `docker compose up --build`, then `POST /api/domains/` with `{"name": "yourdomain.com"}`.
2. Add the returned `verification_token` as a TXT record at `_asm-verify.yourdomain.com`.
3. `POST /api/verify/{domain_id}`.
4. `POST /api/scans/{domain_id}` to queue a scan; poll `GET /api/scans/{scan_id}`.
5. Swap `Base.metadata.create_all` for Alembic migrations before deploying anywhere real.
6. Add auth (API keys) to the API — there is none in this starter scaffold.
7. Wire up Terraform in `infra/` for AWS (ECS/Fargate + RDS + ElastiCache + EventBridge)
   or Azure (Container Apps + Azure DB for Postgres + Azure Cache for Redis + Timer Trigger).
