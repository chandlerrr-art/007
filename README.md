# 007

007 is a local-first, authorized application security testing platform. This first milestone provides a runnable foundation: a FastAPI service, PostgreSQL database, repeatable schema migration, synthetic seed data, and a dashboard that reads live data from the API.

## Requirements

- Docker Desktop with Docker Compose
- Ports `3000`, `8000`, and `5432` available

## Run locally

1. Copy `.env.example` to `.env`.
2. Start the services:

   ```powershell
   docker compose up --build
   ```

3. In another terminal, apply the schema and load synthetic demo records:

   ```powershell
   docker compose exec api alembic upgrade head
   docker compose exec api python -m app.seed
   ```

4. Run the scope policy unit tests:

   ```powershell
   docker compose exec api python -m unittest discover -s tests
   ```

5. Run the synthetic application behavior tests:

   ```powershell
   docker compose exec demo-app python -m unittest discover -s tests
   ```

6. Open <http://localhost:3000>. Click **New scan** to run the bounded check against the seeded localhost demo target. The API health endpoint is <http://localhost:8000/api/health> and its OpenAPI page is <http://localhost:8000/docs>.

The demo app is deliberately vulnerable only to a synthetic cross-agency booking read. The current executor refuses to run against anything except `http://demo-app:8080` with environment `local-demo`, even if another origin is added to the target allowlist. It sends at most four requests, uses a three-second timeout, disables redirects and environment proxies, and stores no response body or credentials. Reports are available from completed scan activity and at `/api/scans/{scan_id}/report`.

To demonstrate remediation, change `DEMO_FIX_IDOR=false` to `DEMO_FIX_IDOR=true` in `.env`, then recreate the fixture with `docker compose up -d --build demo-app`. Start another scan, or submit `POST /api/findings/{finding_id}/retest` in the API docs. A successful retest marks the previous finding resolved.

Target registration requires a match in `ALLOWED_TARGET_ORIGINS`; every outgoing request checks the allowlist again. The default list contains only the local demo origin. A staging origin can be recorded for inventory work, but this demo executor will refuse to scan it.

To reset the local demo database, run `docker compose down -v` and repeat the setup. This removes the local database volume.

## Current milestone

Milestones A–D now include the database-backed dashboard, target allowlisting, HAR endpoint import, endpoint snapshot comparison, scan state/stage records, one bounded access-control check against the local synthetic app, deterministic verification, redacted evidence, audit events, a JSON report, and a retest endpoint. Browser crawling, role-aware planning, additional vulnerability classes, user authentication, and CI integrations remain future work. Do not use real customer data or credentials.

## Safety principles for upcoming scan modules

Every executor must independently enforce target allowlists, request and time budgets, concurrency limits, response redaction, and health checks. Only authorized staging, localhost, or intentionally vulnerable demo targets are in scope. No destructive or denial-of-service checks are permitted. A finding must not be marked verified without deterministic evidence.
