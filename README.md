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

4. Run the backend unit, integration, orchestration, and migration tests:

   ```powershell
   docker compose exec api python -m unittest discover -s tests
   ```

5. Run the synthetic application behavior tests:

   ```powershell
   docker compose exec demo-app python -m unittest discover -s tests
   ```

6. Open <http://localhost:3000>. Click **New scan** to run the bounded check against the seeded localhost demo target. The API health endpoint is <http://localhost:8000/api/health> and its OpenAPI page is <http://localhost:8000/docs>.

Enterprise workspace authentication is disabled by default for this localhost-only demo. For a deployment, set `ENTERPRISE_AUTH_ENABLED=true` and configure a high-entropy `ENTERPRISE_AUTH_SECRET` shared only with a trusted HS256 identity gateway; do not expose the unauthenticated local-demo configuration to a network.

The backend exposes health and dashboard summaries; target registration and inventory; HAR import; scan start, status, cancellation, and JSON report; finding retest; safety status and kill switch; deploy webhooks; and the change feed. The OpenAPI page lists the request and response schemas.

The demo app is deliberately vulnerable only to a synthetic cross-agency booking read. The current executor refuses to run against anything except `http://demo-app:8080` with environment `local-demo`, even if another origin is added to the target allowlist. It sends at most four requests, uses a three-second timeout, disables redirects and environment proxies, and stores no response body or credentials. Reports are available from completed scan activity and at `/api/scans/{scan_id}/report`; current scan stage states are at `/api/scans/{scan_id}`.

To demonstrate remediation, change `DEMO_FIX_IDOR=false` to `DEMO_FIX_IDOR=true` in `.env`, then recreate the fixture with `docker compose up -d --build demo-app`. Start another scan, or submit `POST /api/findings/{finding_id}/retest` in the API docs. A successful retest marks the previous finding resolved.

Target registration requires an exact origin in `ALLOWED_TARGET_ORIGINS`; add only origins you own or are explicitly authorized to test, separated by commas, then recreate the API service. Allowlisted targets can be registered for inventory and HAR import. Active scanning remains restricted to the local synthetic demo because no executor supports other targets; every outgoing scan request is checked against the allowlist again.

To reset the local demo database, run `docker compose down -v` and repeat the setup. This removes the local database volume.

## Current milestone

Milestones A–D cover the database-backed dashboard, target allowlisting, HAR endpoint import, endpoint snapshot comparison, scan state/stage records, one bounded access-control check against the local synthetic app, deterministic verification, redacted evidence, audit events, a JSON report, and a retest endpoint.

Milestone E adds the first two phases of the [phase-wise architecture](#architecture-phase-mapping): a Phase 0 kill switch and per-endpoint rate limiter, and a Phase 1 change-detection path (a CI/CD deploy webhook plus the traffic-diff watcher already implicit in endpoint snapshotting), both surfaced on the dashboard.

- **Kill switch (Phase 0.2):** `POST /api/safety/kill-switch {"engaged": true, "reason": "..."}` halts every future scan stage instantly; `GET /api/safety/status` reads the current state. The orchestrator checks it before scope validation on every scan, so a halted engine never evaluates a target. The dashboard's "Kill switch" button in the top bar and the sidebar's SAFETY ENGINE chip reflect live state.
- **Per-endpoint rate limiter (Phase 0.2):** a token-bucket keyed by `(target, path)` in `app/safety/policy.py`, checked before every outbound request alongside the existing per-scan request budget and global scan concurrency cap.
- **CI/CD deploy listener (Phase 1.1):** `POST /api/webhooks/deploy {"target_id": 1, "release": "v1.2.3"}` records a `ChangeEvent` and, unless the kill switch is engaged, the target is unauthorized, or a scan is already running, auto-queues a bounded scan the same way a manual scan is queued (`trigger="change_detected"`).
- **Traffic-diff watcher (Phase 1.2):** every scan's inventory stage already diffs the current endpoint set against the last snapshot; when that diff is non-empty it now also writes a `ChangeEvent(source="traffic_diff")` so the change stays visible on the feed even outside a deploy.
- **Change feed:** `GET /api/changes` lists the most recent change events (source, detail, and which scan — if any — it triggered); the dashboard shows the same feed in a new "Change events" card.

Browser crawling and VLM-assisted recon, JS bundle/DNS watchers, business-logic and injection executors, the attack planner, multi-agent-debate verification, and CI pipeline integration beyond the webhook above remain future work (see the phase mapping below). Do not use real customer data or credentials.

## Architecture phase mapping

This repo is being built out against the phase-wise architecture in the hackathon planning doc. Current status per phase:

| Phase | Scope | Status |
|---|---|---|
| 0 — Scoping & safety foundations | Target allowlist, request budget, kill switch, per-endpoint rate limiter, audit log | Implemented |
| 1 — Change detection | CI/CD webhook, traffic-diff watcher | Implemented (webhook + traffic diff); JS bundle and DNS/cert watchers not yet built |
| 2 — Recon, app learning & inventory | Endpoint inventory, snapshot diffing, zombie/shadow classification | Partially implemented (HAR import + snapshot diff); no authenticated crawler, no JS static analysis |
| 3 — Attack planning | Endpoint classifier, business-flow reasoner, prioritization | Not yet implemented |
| 4 — Specialist executors | One access-control check against the demo fixture | Partially implemented; business-logic, auth/session, injection, and SSRF executors not yet built |
| 5 — Verification, triage & severity | Deterministic repeat-read verification; findings carry severity/confidence | Partially implemented; no dedup/clustering, no multi-agent debate verifier |
| 6 — Reporting, human-in-the-loop & retest | JSON report, retest endpoint | Partially implemented; no human-approval queue in the UI |
| 7 — Orchestration & control loop | Single-scan orchestrator with staged execution | Partially implemented; no event bus, single scan at a time |
| 8 — Hardening & demo prep | — | Ongoing as features land |

## Safety principles for upcoming scan modules

Every executor must independently enforce target allowlists, request and time budgets, concurrency limits, response redaction, and health checks. Only authorized staging, localhost, or intentionally vulnerable demo targets are in scope. No destructive or denial-of-service checks are permitted. A finding must not be marked verified without deterministic evidence.
