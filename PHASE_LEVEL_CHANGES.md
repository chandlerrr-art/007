# 007 Phase-Level Change Record

**Snapshot date:** 2026-10-29  
**Scope:** Current repository implementation, grouped by the architecture phases in the README.

## Status at a glance

| Phase | Area | Status |
|---|---|---|
| 0 | Scope, safety, credentials, and reviewer gates | Implemented foundations; production hardening remains |
| 1 | Change detection | Partially implemented: deploy webhook and endpoint snapshot diffs |
| 2 | Recon and inventory | Partially implemented: HAR/log ingestion and heuristic endpoint classification |
| 3 | Attack planning | Not implemented as a general planner |
| 4 | Specialist execution | Partial: one local-demo check and one narrowly scoped staging check |
| 5 | Verification and triage | Partial: deterministic demo verification and limited review workflows |
| 6 | Reporting and retest | Partial: JSON reporting, reviewer actions, and demo retest |
| 7 | Orchestration | Partial: staged, single-scan, in-process orchestration |
| 8 | Hardening and demo preparation | Ongoing |

## Phase 0: Scope and safety foundations

- Targets must match configured allowlisted origins. Staging origins are configured separately from the local demo origin in [services/api/app/safety/policy.py](services/api/app/safety/policy.py) and [services/api/app/settings.py](services/api/app/settings.py).
- The local demo executor remains restricted to the synthetic `http://demo-app:8080` target. It uses a four-request budget; the staging executor has a separate configurable budget, defaulting to ten requests.
- Outbound requests enforce target scope, a three-second timeout, disabled redirects, request budgets, health checks, and a process-wide concurrency limit of one. A token bucket rate-limits each target/path pair.
- The database-backed kill switch blocks new scans and is checked at scan-stage and outbound-request boundaries. A request already in flight cannot be recalled.
- Scan actions and outbound request decisions are audited. Response bodies and authorization headers are not persisted as scan evidence.
- Staging test credentials are stored in the credential table in encrypted form and injected at request time by [services/api/app/safety/credentials.py](services/api/app/safety/credentials.py). Configure a deployment-specific encryption key; the development default is not suitable for production.
- Risky staging tests and candidate high-severity findings have reviewer states and approve/reject API actions. The dashboard exposes the review queue.

Key implementation: [services/api/app/scans/orchestrator.py](services/api/app/scans/orchestrator.py), [services/api/app/scans/staging_executor.py](services/api/app/scans/staging_executor.py), and [services/api/app/main.py](services/api/app/main.py).

## Phase 1: Change detection

- `POST /api/webhooks/deploy` records a `ci_cd_webhook` change event. A valid, authorized target can queue a bounded scan when the kill switch is clear and the single scan slot is available.
- Release strings are constrained and free-form notes are not persisted, reducing the chance of retaining secrets in webhook details.
- The inventory stage compares endpoint snapshots. A non-empty difference creates a `traffic_diff` event linked to the scan.
- `GET /api/changes` and the dashboard change feed expose recent events.

Implementation: [services/api/app/main.py](services/api/app/main.py), [services/api/app/scans/orchestrator.py](services/api/app/scans/orchestrator.py), and [apps/web/app/ui/dashboard.tsx](apps/web/app/ui/dashboard.tsx).

**Remaining:** The webhook has no sender-signature authentication; do not expose it to untrusted networks. JavaScript bundle, DNS/certificate, and independent live-traffic watchers are not implemented. Deploy-triggered scans use in-process background tasks.

## Phase 2: Recon and inventory

- HAR import records normalized, in-scope methods and paths and can extract parameter names, locations, and observed types without retaining raw values.
- Gateway/access logs can be ingested from supported JSON and Common Log Format records. The service records timestamps, hit counts, observation windows, and optional role/status observations.
- Endpoint metadata includes inferred business flow, API version, likely owner, authentication reachability, observed data-field summaries, and recommended action.
- Classification compares discovered endpoints with an uploaded traffic window to label endpoints active, zombie, or shadow.

Implementation: [services/api/app/inventory/service.py](services/api/app/inventory/service.py), the endpoint and traffic models in [services/api/app/models.py](services/api/app/models.py), and inventory routes in [services/api/app/main.py](services/api/app/main.py).

**Remaining:** Inputs are supplied through HAR/log ingestion; there is no authenticated browser crawler or JavaScript analysis. Owner, flow, and classification values are heuristic and depend on the quality and coverage of imported data.

## Phase 3: Attack planning

There is no general endpoint-aware planner, prioritization engine, or business-flow reasoner. The orchestrator and staging executor currently use fixed, explicit scenarios rather than selecting tests from a generated plan.

## Phase 4: Specialist execution

- The local synthetic fixture supports a bounded cross-agency booking access-control check with a repeat read.
- The separate staging executor performs a limited authenticated baseline and a reviewer-gated cross-role administrative access check.
- Both paths reuse scope, rate, timeout, health, kill-switch, and audit controls; the staging path has its own request budget and credential handling.

Implementation: [services/api/app/scans/registry.py](services/api/app/scans/registry.py), [services/api/app/scans/orchestrator.py](services/api/app/scans/orchestrator.py), and [services/api/app/scans/staging_executor.py](services/api/app/scans/staging_executor.py).

**Remaining:** There are no general business-logic, authentication/session, injection, SSRF, or other specialist executors. The staging check is a narrow demonstration, not broad vulnerability coverage.

## Phase 5: Verification and triage

- The demo access-control finding is verified by repeating the minimal synthetic read; repeat findings are deduplicated and evidence summaries omit response content.
- Findings carry severity, confidence, lifecycle, and review state. Review decisions are audited.
- The staging path holds risky tests until approval and places detected high-severity findings in the review workflow.

**Remaining:** Independent verification is specific to the demo check. There is no general verifier, cross-class finding clustering, or evidence-based severity model. The staging executor's check is not a general multi-step verification system.

## Phase 6: Reporting, review, and retest

- Completed scans expose a JSON report with scan stages, findings, and redacted evidence summaries.
- Review APIs and dashboard actions support approving or rejecting risky tests and candidate findings.
- A verified demo finding can be retested; a non-reproducing result resolves the finding.

**Remaining:** Retesting is limited to the supported demo check. There is no ticketing/export integration or general human-approval workflow for every scan action.

## Phase 7: Orchestration and control loop

- Scan stages and their outcomes are persisted. The orchestrator applies scope checks, cancellation, kill-switch checks, and the single-scan concurrency limit.
- Manual and eligible deploy-triggered scans are queued through FastAPI background tasks.

**Remaining:** There is no durable job queue or event bus. Work can be lost if the API process restarts, and scans run one at a time.

## Phase 8: Hardening and demo preparation

- Docker Compose provides the API, database, web dashboard, and synthetic demo application. Migrations, seed data, tests, and setup instructions are checked in.
- Safety boundaries and supported scope are documented in the [README](README.md).

**Status:** Ongoing. Before production or shared-network use, address webhook authentication, deployment secrets, durable job execution, and broader operational monitoring.

## Verification

The latest backend test run used a one-off API container and passed **29 tests**:

```powershell
docker compose run --rm api python -m unittest discover -s tests
```

This verifies the current backend tests, including migration, safety, inventory, staging-readiness, and scan behavior. It does not certify coverage against a real staging application.