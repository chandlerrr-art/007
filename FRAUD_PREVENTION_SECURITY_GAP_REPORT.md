# 007 vs. Fraud Prevention & Security Challenge Requirements

**Assessment date:** 2026-10-29  
**Project snapshot:** Git branch `main`, commit `ac14a73`  
**Source:** *TBO Security Hackathon 2026 - Agentic Real-Time DAST Participant Pack*, supplied as `C:\Users\ftdab\Downloads\Fraud Prevention & Security.pdf` (5 pages)

## Executive summary

007 is a credible **local-first safety and orchestration prototype**. It already demonstrates a real, deterministic cross-agency booking access-control check against an intentionally vulnerable synthetic application; allowlist enforcement, bounded requests, health checks, cancellation, a kill switch, request auditing, finding deduplication, JSON reporting, and fix-and-retest are implemented.

It is **not yet the agentic real-time DAST platform described by the challenge pack**. Most of the current product is a controlled one-vulnerability demo. It does not yet discover an undocumented application, understand roles and travel business flows, plan tests by endpoint, ingest historical gateway traffic, calculate zombie/shadow status, cover the other vulnerability classes, or route findings through human review to an actual owner or ticket.

The strongest alignment today is with the challenge's safety rules and the access-control/verification/retest slice of the agent loop. The largest gaps are application learning and inventory, change-signal coverage, attack planning and specialist execution, and finding ownership/actionability. The architecture diagram is explicitly described in the PDF as suggested rather than mandatory; the zombie/shadow endpoint inventory is explicitly a secondary requirement, but it is still expected in the discovery output.

This assessment is based on repository code and documentation, not a run against the challenge staging environment. The current scanner intentionally refuses targets outside the configured local synthetic demo.

## Status key

- **Implemented:** present in code and connected to the current application flow.
- **Partial:** a limited slice exists, but it does not meet the full challenge description.
- **Not implemented:** no working project capability was found for the requirement.
- **Strong foundation:** implemented with meaningful safety controls, but still limited to the current local demo.

## Agent-loop requirement comparison

| PDF requirement | Status | What 007 has | What remains |
|---|---|---|---|
| Detect change: deploys, new/changed endpoints in traffic, new JavaScript bundles, new subdomains (pp. 1-2) | **Partial** | A deploy webhook records a change event and can queue the local demo scan. Endpoint snapshot differences also create change events. | No gateway/load-balancer log input, bundle-diff watcher, DNS/certificate watcher, or other live change feed. Deploy events are not tied to measured time-to-finding. |
| Learn the app and build an inferred inventory without an API spec (p. 1) | **Partial** | Users can import a HAR. The importer keeps normalized in-scope methods and paths while dropping headers, cookies, bodies, and query strings. The backend exposes endpoint inventory by target; the dashboard currently shows only an aggregate endpoint count. | No UI crawler, role-specific test-account sessions, parameter discovery, frontend JavaScript route analysis, undocumented-path discovery, or app knowledge graph. HAR import is supplied input, not autonomous app learning. |
| Understand endpoints, parameters, roles, and business flows (pp. 1-3) | **Not implemented** | Endpoint rows store method, path, simple classification/sensitivity, source, and last-seen timestamp. The synthetic fixture has two agency identities and booking data. | No persisted parameter model, role/permission matrix, or linked search/hold/book/pay/cancel flow. The executor uses one fixed synthetic agency identity and one booking ID. |
| Compare inventory with 30-90 days of traffic; identify zombie and shadow endpoints (pp. 1, 4-5) | **Partial / major gap** | A scan snapshots the current endpoint rows and compares them with the prior snapshot. Sample seed data includes illustrative `active` and `shadow` labels. | No historical usage window, gateway-log ingestion, automated status classification, or zombie detection. The sample labels are seeded examples, not results inferred from traffic. No per-endpoint last-real-traffic time, auth reachability, exposed-data summary, version comparison, likely owner, or decommission/restrict/update recommendation. |
| Plan targeted attacks for each endpoint (pp. 1-3) | **Not implemented** | The current orchestrator has explicit stages, but always runs the same hard-coded access-control check. | No endpoint-specific attack planner, risk/priority selection, test-plan record, or parameter/role/flow-aware test choice. |
| Execute safely and back off when the application is strained (pp. 1-2, 5) | **Strong foundation, narrow coverage** | Exact target allowlist is checked at registration and before each outgoing request; active checks only support `http://demo-app:8080` in `local-demo`. Per-scan budget is four requests, timeout is three seconds, redirects and ambient proxies are disabled, concurrency is one, and requests have a per-endpoint token-bucket limit. Preflight/postflight health checks, cancellation, and a kill switch stop work. | No load/degradation trend monitor beyond health status, adaptive backoff, or executor-specific budgets for multiple test classes. No credential vault; credentials are unnecessary in the current fixture. The challenge staging environment is not supported by an executor. |
| Verify each finding with a minimal clean proof (pp. 1-2, 5) | **Partial** | The candidate cross-agency result is repeated with a minimal request. A finding is marked verified only when both reads deterministically show the synthetic foreign-owned booking. Response bodies are not persisted. | Verification is specific to one fixture and response shape. There is no general verifier framework or finding-specific human confirmation process. |
| Triage: deduplicate, assess business severity, map to an owner (pp. 1-2) | **Partial** | Repeated access-control findings are deduplicated; records keep separate severity, confidence, business impact, verification, and lifecycle state. Retests update the original record. | Severity/impact are hard-coded for the single check. There is no business-context scoring model, owner directory or routing, cross-class clustering, false-positive workflow, or triage queue. |
| Report actionable evidence, impact, severity, owner, and suggested fix (p. 2) | **Partial** | `/api/scans/{id}/report` returns JSON with endpoint, reproduction steps, evidence summary, impact, severity, confidence, status, remediation, stages, inventory snapshot, and audit events. | The owner is always `Unassigned`; reproduction steps and remediation are fixed to the demo IDOR. No issue/ticket integration or report approval process. |
| Retest after a fix and close the finding when resolved (pp. 2, 5) | **Partial** | The UI/API can retest a verified access-control finding. A non-reproducing result resolves it; a reproduced issue returns it to open. | Only the access-control fixture has a retest executor. There is no retest policy for other classes or deploy-to-finding linkage beyond a new scan. |

## Reference architecture and inputs

| Challenge component/input | Status in 007 |
|---|---|
| Change triggers: CI/CD, gateway traffic, frontend bundle diffs, DNS/certificates (pp. 2-3) | CI/CD deploy webhook and inventory-diff events exist. The other three trigger families and their data adapters are absent. |
| Orchestrator agent that orders tests and pauses on safety alarms (pp. 2-3) | A single-process, staged orchestrator enforces the safety stop, but its execution order and test are fixed. It is not a planning agent. |
| Recon and application knowledge graph (endpoints, params, roles, flows) (pp. 2-3) | A relational endpoint table and snapshots exist; there is no graph or linked application model. |
| Inventory agent using traffic logs to classify zombie/shadow APIs (p. 2) | Snapshot delta detection exists, but not traffic-window analysis or automated zombie/shadow classification. |
| Attack planner and specialist executors (pp. 2-3) | One access-control executor exists. Planner, business-logic, authentication/session, injection, API-hygiene, data-exposure, and server-side executors are absent. |
| Safety layer and audit log (pp. 2-3) | Strong local implementation: scope, request budget, timeout, rate limiting, health checks, kill switch, cancellation, and allow/deny/result auditing. No test-credential vault is present. |
| Verifier, triage, reporter, and retest agents (pp. 2-3) | Deterministic verifier, dedupe, JSON report, and one retest loop exist as conventional code. General agents, business-owner routing, and ticket-ready external delivery do not. |
| Human reviewer for risky tests and high-severity findings (p. 2) | **Not implemented.** There is no approval queue or reviewer decision state. The dashboard kill switch is an operator control, not a review gate. |
| Staging input set: several roles across two agencies, HAR/proxy traffic, 30-90 day logs, deploys, DNS, app logs, ownership, past findings (p. 4) | The bundled fixture supplies synthetic agency A/B identities and records; manual HAR import and deploy webhooks are available. Gateway/access logs, application logs, DNS/certificate data, multiple role accounts, traffic history, ownership data, and prior-finding import are absent. The project has no configured connection to the hackathon staging environment. |

## Vulnerability coverage in the PDF

The PDF permits teams to go deep on a few classes, so missing classes do not automatically mean the prototype fails the challenge. They do limit breadth and the score potential for a submission claiming broad coverage.

| In-scope class (p. 4) | Current coverage |
|---|---|
| Access control | **Partial:** one deterministic cross-agency booking IDOR on a synthetic fixture. No invoice/traveller IDs or sub-agent/admin escalation. |
| Business logic | **Not implemented:** no fare/markup, coupon reuse, cancellation/refund, payment-step, or quantity checks. |
| Authentication and sessions | **Not implemented:** no password-reset, token/session, JWT, or step-up-auth executor. |
| Injection | **Not implemented:** no SQL/NoSQL/command/template/header injection checks. |
| API hygiene | **Not implemented as a security test:** no unauthenticated-route, mass-assignment, excessive-response, or endpoint-rate-limit assessment. The platform's own rate limiter is a safety control, not a target finding check. |
| Data exposure | **Not implemented as a target check:** the app protects stored evidence, but the scanner does not inspect responses for sensitive-data exposure. |
| Server-side risks | **Not implemented:** no SSRF, upload, or open-redirect checks. |
| Zombie and shadow APIs | **Partial, mostly illustrative:** static sample classifications exist; no detection from traffic, old routes/bundles, DNS history, or certificates, and no required endpoint-level assessment/recommendation. |

## Rules of engagement

| PDF rule (p. 5) | Assessment |
|---|---|
| Stay on approved targets and stop outside scope | **Strong:** target registration and every outgoing request are allowlist-checked; the active executor further restricts work to the local demo. |
| Use only provided test accounts and synthetic data | **Strong for the current demo:** only synthetic agency identities and records are used. **Not yet staged:** the system cannot manage or use the hackathon's provided role accounts. |
| Rate-limit; no denial-of-service or destructive tests | **Strong for the current check:** four-request budget, short timeout, one concurrent scan, endpoint rate limiter, health checks, and safe stop/cancel. |
| Minimum proof; no bulk extraction or persistent access | **Strong for the current check:** two minimal reads verify one synthetic record, and bodies/credentials are not stored. |
| Log every request for replay/review | **Strong with a replayability limitation:** allow/deny and response status are audited without secrets or bodies. The log is sufficient to understand the bounded check, but does not retain a raw request/response transcript (intentionally) or a replay bundle. |

## Position against the judging rubric

This is a qualitative comparison, not an estimated numeric score. The repository has not been evaluated against planted challenge vulnerabilities or the actual staging input set.

| Criterion | Weight | Current position |
|---|---:|---|
| Valid findings and severity | 30% | **Narrow:** one valid planted synthetic IDOR with deterministic confirmation; severity is fixed rather than assessed across business contexts. |
| Precision and noise control | 20% | **Promising within the narrow scope:** repeated confirmation and deduplication are implemented. There is not enough vulnerability breadth or benchmark data to establish overall precision/false-positive rate. |
| Safety and scope discipline | 20% | **Strongest area:** the demo scan has concrete scope, request, health, cancellation, kill-switch, and audit controls. |
| Speed after change | 10% | **Partial/unmeasured:** deploy webhook can enqueue a local scan, but there is no durable queue, latency telemetry, or measured deploy-to-verified-finding target. FastAPI in-process background work can be lost if the API process restarts. |
| Report quality and actionability | 10% | **Partial:** structured JSON is present, but owner is unassigned, report content is demo-specific, and there is no ticket integration. |
| Discovery and API inventory | 10% | **Largest functional gap:** manual HAR import and snapshot comparisons are useful groundwork, but there is no self-discovery, traffic history, or computed active/zombie/shadow status. The API's `/docs` describes 007's own API, not an inferred OpenAPI specification for a target. |

## Priority work remaining

### P0 - Make the challenge environment usable without weakening the demo boundary

1. Add a separate, explicitly configured staging-target executor. Keep the existing fixture-only executor intact; do not reuse its fixed IDOR probe against unrelated targets.
2. Add scoped test-account handling for the supplied synthetic identities and roles, with secret storage that never puts credentials in evidence or logs.
3. Add human approval states for tests designated risky and for high-severity findings before escalation.

### P1 - Build an evidence-backed inventory

1. Extend endpoint records with discovered parameters, role/access observations, business-flow links, API version, traffic observation window, last legitimate traffic, authentication requirement, and ownership.
2. Ingest the supplied synthetic HAR/proxy and gateway/access-log inputs with time bounds and privacy-preserving normalization.
3. Compute active, zombie, and shadow states from observed traffic versus discovered/documented routes. Include each endpoint's last-seen traffic, auth reachability, redacted data-exposure observation, version comparison, likely owner, and recommended action.
4. Add explicit tests for classification edge cases, stale/empty traffic windows, and input redaction.

### P2 - Expand change detection

1. Authenticate and validate deploy webhook events, then tie releases to inventory snapshots and scan timing.
2. Add controlled adapters for gateway/LB logs and synthetic frontend-bundle and DNS/certificate change signals.
3. Record trigger-to-scan and trigger-to-verified-finding latency so the speed criterion can be measured.

### P3 - Add targeted planning and specialist checks

1. Start with rule-based endpoint classification and an auditable plan that selects a check based on method, parameters, roles, sensitivity, flow, and recent change.
2. Add one safe synthetic business-logic executor next, then expand only where the provided staging fixtures support deterministic, non-destructive verification.
3. Give every executor independent scope checks, per-scan budgets, rate limits, health/cancel/kill-switch behavior, redaction, and tests.

### P4 - Make findings operationally actionable

1. Add an owner/asset directory and derive impact/severity from the affected travel workflow and data sensitivity.
2. Make report content evidence-driven per finding; distinguish verified, needs-review, open, and resolved states.
3. Add human triage and approval UI, plus a ticket/export adapter only if the event environment provides one.
4. Move background scans to a durable queue before relying on deploy-triggered speed or restarts.

## Repository evidence reviewed

The assessment checked the API routes and schemas, SQLAlchemy models and Alembic migrations, scan orchestrator and safety policy, synthetic fixture and its tests, seed data, Docker Compose configuration, dashboard client and UI, README, and backend test files. The seed explicitly labels its sample finding as illustrative and unverified; it is not a scan result. The checked-in setup and code describe only the local demo target as actively scannable.

