# 007 Project Workflow and Code Guide

This guide describes the repository as it exists now: how its services fit
together, what happens from startup through results and remediation, and where
the important files and functions live. It complements the setup instructions
in [README.md](./README.md).

## What the project is

007 is a local-first security operations application. It has a Next.js
command-center UI, a FastAPI API, PostgreSQL persistence, Redis-backed Celery
workers, and an intentionally synthetic booking application for safe local
demonstrations. It supports authorized target and API inventory management,
two scan workflows, human review, reporting, compliance mapping, ticket
integration, deploy notifications, and reviewed patch candidates.

The code has evolved beyond some of the earlier milestone wording in the
README. In particular, there are now separate staging and Phase 2 worker
paths, as well as OpenAPI and gateway-log inventory ingestion. This guide
describes current code behavior; the README remains the quick-start reference.

## System at a glance

```text
Browser
  └─ Next.js pages/components (apps/web)
       └─ HTTP /api/* requests
            └─ FastAPI routes (services/api/app/main.py)
                 ├─ SQLAlchemy models and PostgreSQL
                 ├─ inventory, scan, safety, and remediation services
                 ├─ FastAPI background task → bounded Scan orchestrator
                 └─ Redis/Celery → Phase 2 scan and patch workers

Docker Compose also starts:
  ├─ Redis broker/result backend
  ├─ PostgreSQL
  ├─ synthetic demo target (fixtures/demo-app)
  └─ dedicated Celery worker
```

The `Scan` and `VulnerabilityScan` database records represent two distinct
pipelines; their APIs, status fields, and execution mechanisms are not
interchangeable.

## End-to-end workflow

### 1. Start the stack and prepare its data

`docker-compose.yml` builds and connects the `web`, `api`, `worker`, `db`,
`redis`, and `demo-app` services. The database and Redis have health checks;
the API waits for those services and the demo target. Persistent PostgreSQL
and Redis data use named Docker volumes.

The API image installs dependencies from `pyproject.toml` and runs
`uvicorn app.main:app`. The worker image is the same API image, but its Compose
command starts Celery on the `security-scans` and `patch-generation` queues.
The web image builds Next.js as a standalone application.

Database tables are not created by the API startup path. Run
`alembic upgrade head` from the API container first. The migration environment
loads SQLAlchemy metadata from `app.models`; the ordered revisions evolve the
schema. `python -m app.seed` then inserts synthetic targets, inventory,
example scan/finding data, and an audit note. The seed exits without changing
an already-populated database.

### 2. Open the dashboard

The browser opens `apps/web/app/page.tsx`, which renders
`ExperienceGate`. The introductory/login UI is a local interface gate: it
stores a session flag in `sessionStorage` and does not authenticate a user
against the API. Real API authorization is handled separately by the
enterprise workspace token code when `ENTERPRISE_AUTH_ENABLED` is enabled.

The dashboard loads `/api/dashboard` and `/api/health`, displays targets,
findings, scans, change events, safety state, and pending review work. It also
provides controls for target registration, HAR import, OpenAPI import, scan
start/cancel, finding retests, reviewer decisions, and the kill switch.

### 3. Register a target and build endpoint inventory

`POST /api/targets` checks the target's exact HTTP(S) origin against
`ALLOWED_TARGET_ORIGINS` and `ALLOWED_STAGING_ORIGINS`. Registration is
necessary but is not a substitute for authorization to test that target.

Inventory can be collected through three inputs:

1. **HAR:** `POST /api/targets/{target_id}/har-import` normalizes observed
   paths and retains parameter names, locations, and inferred types rather
   than raw parameter values.
2. **OpenAPI/Swagger:** `POST /api/targets/{target_id}/openapi-import` accepts
   an uploaded file or a same-target specification URL. It validates supported
   OpenAPI 3.0/Swagger 2.0 documents, extracts route and parameter metadata,
   and stores no uploaded runtime traffic.
3. **Gateway/access logs:** `POST /api/targets/{target_id}/gateway-logs`
   parses supported access-log formats, updates traffic observations, and
   discovers endpoints seen in traffic.

`POST /api/targets/{target_id}/classify` and the import paths run the inventory
classifier. It compares documentation/discovery with traffic in a time window
to label routes active, zombie, or shadow; it also derives business-flow,
version, ownership, authentication-reachability, and recommended-action
metadata. Classification is evidence-based metadata, not proof that a route
is exploitable.

### 4. Run the bounded `Scan` workflow

The dashboard's **New scan** action calls `POST /api/scans`. The route checks
the kill switch, the single active scan slot, target status, allowlist, and
executor support. It creates a queued `Scan` plus an audit event, then passes
the work to FastAPI `BackgroundTasks`.

`run_scan()` in `app.scans.orchestrator` serializes this pipeline with a
one-scan semaphore and delegates to `_run_scan()`:

1. **Scope validation:** check the kill switch, configured origin, target
   authorization status, and a matching executor.
2. **Inventory snapshot:** read the target's endpoint inventory; add the
   synthetic demo route when appropriate; store an `InventorySnapshot`; and
   compare it with the preceding snapshot. A non-empty delta creates a
   `traffic_diff` `ChangeEvent`.
3. **Classification:** refresh endpoint active/zombie/shadow metadata.
4. **Executor stage:** use the built-in synthetic-demo check or the separate
   `StagingTargetExecutor` for a supported, explicitly allowlisted staging
   target. The staging path records health/authentication stages and holds its
   risky test behind reviewer approval.
5. **Completion:** persist scan status/summary and, for retests, resolve the
   original finding only when the issue is no longer reproduced. Errors,
   cancellation, and kill-switch halts become explicit final statuses.

The original demo check uses only synthetic fixture data and requires
independent deterministic confirmation before persisting a verified finding.
The demo path's request helper rechecks scope and safety before each request,
uses a short timeout, disables redirects and environment proxies, caps the
request count, and records redacted audit metadata rather than response bodies
or credentials. The staging executor has its own request budget and safety
checks. These controls are not a grant of permission to test an unapproved
system.

The dashboard polls scan status through `/api/scans/{scan_id}`. Users can
cancel a running scan, download its PDF at `/api/scans/{scan_id}/report`, and
request a retest at `/api/findings/{finding_id}/retest`.

### 5. Run the Celery `VulnerabilityScan` workflow

This is a distinct, inventory-driven Phase 2 workflow:

1. `POST /api/targets/{target_id}/scans` validates the target and kill switch,
   stores a `VulnerabilityScan` configuration/profile snapshot, and dispatches
   `app.vulnerability.tasks.run_scan_task` to Celery.
2. If enterprise auth is active, the API encrypts the authorization context
   before adding it to the broker message. The worker opens its own database
   session, verifies workspace/target ownership and required permissions, and
   prevents duplicate or stale task ownership.
3. `run_vulnerability_scan()` loads endpoint inventory, prioritizes it, and
   invokes the enabled analysis modules for the selected `quick`, `deep`, or
   `auth_matrix_only` profile. The modules cover access-control observations,
   parameter-level checks, business-flow consistency, and risk analysis of
   shadow/zombie inventory. This description intentionally stays at the
   capability level; active checks must only be run against explicitly
   authorized, allowlisted targets.
4. The worker persists discovered vulnerabilities, execution metrics, and
   finding summaries in the scan configuration snapshot, then marks the scan
   completed or failed.

`GET /api/targets/{target_id}/scans/{scan_id}` returns status, metrics, and
severity counts; `/api/targets/{target_id}/vulnerabilities` provides a
filterable vulnerability register. `ScanProgress` is the UI polling component
for this second status API. Celery task limits, JSON-only serialization,
queue routing, retry/ack behavior, and Redis settings are defined in
`app.core.celery_app` and `app.settings`.

### 6. Review findings and risky tests

`GET /api/reviews` and the dashboard expose pending `TestExecution` and
`Finding` records. Reviewer approve/reject routes persist status, notes, time,
and audit events. Approval of a finding marks it verified; rejection marks it
unverified. The staging executor will not run a gated risky test while it is
pending or rejected.

### 7. Remediate, report, and connect external systems

- **Reports:** the scan report endpoint produces a PDF from scan stages,
  snapshots, redacted evidence, findings, and audit events. Executive target
  reports can be requested as PDF, JSON, or HTML.
- **Compliance:** the compliance mapper associates supported vulnerability
  categories with OWASP API Security Top 10 and CWE identifiers, and computes
  target posture.
- **Tickets:** remediation ticket adapters create and synchronize Jira Cloud
  or GitHub Issues records when the relevant configuration is available.
- **CI/CD gates:** a completed vulnerability scan can be evaluated against
  severity/CVSS policy; the gate result is persisted as a build evaluation.
- **Webhooks:** subscriptions dispatch supported events with signed payloads.
  Delivery rejects redirects and validates configured destination URLs.
- **Patch candidates:** the patch route queues a worker task with encrypted
  source and authorization context. The patcher returns a diff candidate,
  which must be reviewed before its application can be recorded. The current
  apply endpoint records a mode/status; it does not modify a repository.

### 8. Change detection and safety controls

Deploy notifications at `POST /api/webhooks/deploy` create `ChangeEvent`
records and may queue a bounded scan when safety and target conditions allow.
Inventory snapshot comparison separately records traffic-diff changes.
`GET /api/changes` and the dashboard change card expose the feed.

The shared safety layer canonicalizes and validates origins, rechecks request
scope at execution time, enforces per-endpoint token-bucket rate limits,
checks the persisted kill switch, and redacts operational text. The demo and
staging scan helpers also enforce their own request budgets. Credential and
webhook secrets are encrypted at rest using envelope encryption when
`MASTER_KEK_SECRET` is configured; they are decrypted only when needed and
registered for redaction. Legacy credential encryption exists only to read
older stored values.

## File-by-file guide

### Repository root and deployment

| File | Responsibility |
|---|---|
| `README.md` | Setup, local demo commands, current milestone notes, and architecture summary. |
| `PROJECT_WORKFLOW.md` | This workflow, architecture, and file/function guide. |
| `pyproject.toml` | Python package metadata, Python floor, API dependencies, optional test dependency, and setuptools package discovery. |
| `.env.example` | Names and safe local defaults for Compose/API/worker configuration. Copy to ignored `.env`; do not commit secrets. |
| `.gitignore` | Excludes local environment files, virtualenvs, Python caches, Next build output, `node_modules`, and generated TypeScript build metadata. |
| `docker-compose.yml` | Defines the six-service local stack, environment wiring, health checks, ports, and persistent volumes. |
| `FRAUD_PREVENTION_SECURITY_GAP_REPORT.md` | Existing security-gap/reporting artifact; planning/reference material, not imported by the application. |
| `007-command-center-redesign.patch` | Tracked UI redesign patch artifact; not executed by the application. |
| `007_api.egg-info/*` | Python packaging metadata generated by setuptools; not application logic. |
| `.vscode/settings.json` | Workspace/editor settings. |

### API application: entry point, persistence, and models

| File | Key functions/types and responsibility |
|---|---|
| `services/api/app/main.py` | FastAPI app, Pydantic request/response types, route handlers, and orchestration glue. `normalize_har_path()` normalizes/redacts imported route paths. `health()` checks DB connectivity. `dashboard()` builds the dashboard summary. Target handlers list/register targets and endpoints. Import handlers route HAR, OpenAPI, and gateway logs into inventory services; `trigger_classification()` returns classified endpoints. Credential handlers add/list/delete scoped credentials. Review handlers build the queue and approve/reject tests or findings; `review_finding()` and `review_test()` dispatch the common decision routes. Safety/change handlers read/update kill-switch state and list changes. `deploy_webhook()` records deploy changes and conditionally queues a scan. Scan handlers start, cancel, report status for, and render PDF reports for bounded scans; `retest_finding()` creates a linked retest. Phase 2 handlers create/status/list vulnerability scans and findings. Remaining handlers create/sync tickets, return compliance and executive reports, evaluate CI gates, manage/test webhook subscriptions, return workspace context, and generate/list/status/review/apply patch candidates. `_webhook_public()` and `_patch_public()` serialize records without exposing secret material. |
| `services/api/app/db.py` | `Base` is declarative SQLAlchemy metadata; `engine` and `SessionLocal` configure persistence; `get_db()` yields a request session and, when enterprise auth is enabled, attaches organization and permission context. |
| `services/api/app/settings.py` | `Settings` maps environment values to typed settings; the module-level `settings` is the shared configuration instance. |
| `services/api/app/models.py` | SQLAlchemy records: `Organization`, `WorkspaceUser`; `Target`; `Scan`, `ScanStage`, `InventorySnapshot`; `Endpoint`, `EndpointParameter`, `EndpointRoleObservation`, `TrafficLogEntry`; `Finding`, `Evidence`, `AuditEvent`, `ChangeEvent`, `SafetyControl`, `TestExecution`; `VulnerabilityScan`, `DiscoveredVulnerability`; `RemediationTicket`, `ComplianceFramework`, `VulnerabilityComplianceMapping`, `CICDBuildEvaluation`; `CodePatch`, and `WebhookSubscription`. These represent the persisted workflow, not transient UI state. |
| `services/api/app/seed.py` | `seed()` inserts one local synthetic target, example endpoints, a completed illustrative scan, snapshot, stages, audit entry, unverified sample finding, and redacted note only when the database has no target. |
| `services/api/app/__init__.py` | Marks `app` as a Python package. |

The route handlers in `main.py` are grouped by workflow:

| Route group | Handler functions |
|---|---|
| Health and dashboard | `health()`, `dashboard()` |
| Target and endpoint inventory | `list_targets()`, `create_target()`, `list_endpoints()` |
| Inventory ingestion/classification | `import_har()`, `import_openapi()`, `import_gateway_logs_endpoint()`, `trigger_classification()` |
| Scoped credentials | `add_credential()`, `list_credentials()`, `delete_credential()` |
| Human review | `get_review_queue()`, `approve_test()`, `reject_test()`, `approve_finding()`, `reject_finding()`, `review_finding()`, `review_test()` |
| Safety and change detection | `safety_status()`, `set_kill_switch()`, `list_changes()`, `deploy_webhook()` |
| Bounded `Scan` lifecycle | `start_scan()`, `cancel_scan()`, `scan_status()`, `scan_report()`, `retest_finding()` |
| Celery `VulnerabilityScan` | `trigger_target_vulnerability_scan()`, `get_target_vulnerability_scan_status()`, `list_target_vulnerabilities()` |
| Remediation and posture | `create_vulnerability_ticket()`, `sync_remediation_ticket()`, `get_target_compliance()`, `get_executive_report()` |
| CI/CD and delivery hooks | `evaluate_cicd_gate()`, `list_webhook_subscriptions()`, `upsert_webhook_subscription()`, `test_webhook_subscription()` |
| Enterprise workspace and patch flow | `workspace_context()`, `generate_vulnerability_patch()`, `list_vulnerability_patches()`, `get_background_task_status()`, `review_patch()`, `apply_patch()` |

The request/response classes next to these handlers validate payloads and
document API shapes for health, dashboard, target, endpoint, import, review,
safety, scan, vulnerability, ticket, gate, webhook, and patch operations.

### Inventory

| File | Functions and responsibility |
|---|---|
| `services/api/app/inventory/service.py` | `normalize_endpoint_path()` removes query/fragment data and normalizes dynamic/identifying segments. `infer_business_flow()`, `infer_api_version()`, and `infer_likely_owner()` derive route metadata. `infer_type()` infers a value's shape without storing the value. `extract_parameters_from_har_entry()` retains parameter names/location/types under redaction rules. `parse_gateway_log_entry()` parses supported log records. `ingest_gateway_logs()` persists traffic, endpoint discoveries, and role observations. `classify_endpoints()` compares documented endpoints with time-windowed traffic and updates classification and recommendations. |
| `services/api/app/inventory/openapi_importer.py` | `OpenAPIImportError` is the safe validation error; `_BoundedSafeLoader` limits YAML aliases. `_walk()`/`_walk_once()` traverse a spec; `_reject_external_refs()` and `_resolve_local()` constrain references. `parse_openapi_document()` parses and validates supported JSON/YAML specifications. `_normalize_spec_path()` preserves named route parameters. `_schema_type()`, `_schema_body_parameters()`, `_request_body_parameters()`, `_parameter_schema()`, and `_operation_parameters()` extract parameter structure. `_security_schemes()`, `_operation_security()`, and `_scheme_summary()` summarize auth schemes without credential values. `iter_spec_endpoints()` yields normalized route definitions. `ingest_openapi_spec()` upserts those definitions and parameters. `fetch_openapi_spec()` retrieves a bounded same-origin spec. |
| `services/api/app/inventory/__init__.py` | Re-exports inventory importer/service functions used by API routes. |

### Safety, authorization, and encryption

| File | Functions and responsibility |
|---|---|
| `services/api/app/safety/policy.py` | `redact_operational_text()` removes secrets/identifiers from retained text. `TokenBucket.allow()`/`reset()` implement the thread-safe endpoint limiter. `origin()` canonicalizes a URL origin; `allowed_staging_origins()`/`allowed_origins()` load configured scopes; `validate_target_url()` checks the allowlist. `supports_demo_executor()`/`supports_staging_executor()` select supported target classes. `assert_request_scope()` rechecks each request; `assert_rate_limit()` applies the endpoint bucket. `get_safety_control()` reads/creates the singleton safety row; `assert_kill_switch_clear()` blocks work while halted. |
| `services/api/app/safety/credentials.py` | `register_secret_for_redaction()`/`scrub_known_secrets()` manage in-memory scrubbing. `_derive_keys()`, `_keystream()`, `encrypt_secret()`, and `decrypt_secret()` support legacy ciphertext compatibility and migration. `TestAccountCredential` models target/role-scoped test accounts. `store_credential()` writes envelope-encrypted credentials; `get_call_time_auth_headers()` decrypts and formats auth headers at request time. New values use envelope encryption. |
| `services/api/app/core/encryption.py` | `KEKProvider` defines key wrapping. `AESGCMKeyringProvider` creates/rotates a local keyring and wraps/unwraps DEKs. `EncryptedEnvelope` serializes ciphertext and wrapped-key metadata. `configure_kek_provider()` sets a provider. `EnvelopeEncryptionService.from_settings()`, `.encrypt()`, and `.decrypt()` implement per-value AES-GCM envelope encryption. `_encode()`/`_decode()` handle encoding; the module CLI supports configuration validation. |
| `services/api/app/auth/rbac.py` | `WorkspaceContext.allows()` tests permissions. `_b64()`, `issue_workspace_token()`, and `_verify_token()` implement signed workspace token handling. `resolve_workspace_context()` resolves membership and permissions. `require_permission()`/`require_session_permission()` enforce route permissions. `ensure_target_access()`/`ensure_vulnerability_access()` scope records to the workspace. `get_workspace_context()` is the FastAPI dependency. `_apply_workspace_scope()` adds tenant filtering; `_prevent_workspace_reassignment()` blocks reassignment across organizations. |
| `services/api/app/auth/__init__.py`, `services/api/app/safety/__init__.py`, `services/api/app/core/__init__.py` | Package markers for the authorization, safety, and core service modules. |

### Scan orchestration and worker tasks

| File | Functions and responsibility |
|---|---|
| `services/api/app/scans/orchestrator.py` | `_now()` returns UTC time. `_cancelled()` reads cancellation from the database; `_ensure_scan_active()` checks cancellation and kill switch. `_stage()`/`_finish_stage()` persist stage lifecycle; `_audit()` writes audit events. `_bounded_get()` enforces scope, request-count, timeout, rate limit, and redacted audit behavior for the demo scan. `_health_check()` wraps pre/postflight checks in stages. `_run_access_control_check()` runs the synthetic demo check and independent verification, then records/deduplicates evidence. `run_scan()` acquires the scan semaphore; `_run_scan()` performs scope validation, snapshot comparison, classification, executor dispatch, retest handling, and final status transitions. |
| `services/api/app/scans/registry.py` | `BaseScanExecutor` defines the executor contract. `LocalDemoExecutor.supports()`/`.run()` route the demo target to the existing check. `ExecutorRegistry.register()`, `.unregister()`, `.get()`, `.get_for_target()`, and `.list_all()` manage executor selection. The module registers demo and staging implementations. |
| `services/api/app/scans/staging_executor.py` | `_now()`, `_audit()`, `_stage()`, and `_finish_stage()` provide staged, redacted execution bookkeeping. `StagingTargetExecutor.__init__()` sets a request budget; `.supports()` checks staging scope; `._bounded_request()` enforces kill switch, budget, scope, rate limit, timeout, and audit rules; `._health_check()` records target health; `.run()` performs the staging baseline and review-gated workflow. |
| `services/api/app/vulnerability/tasks.py` | `run_scan_task()` is the Celery entry point: it validates tenant/task ownership, opens its own DB session, restores encrypted auth context, runs the vulnerability engine, and records failure states. `_mark_failed()` persists a safe failure status/message. |
| `services/api/app/core/celery_app.py` | Configures Redis as broker/backend, JSON-only task payloads, worker acknowledgment/time limits, and per-task queue routing. |
| `services/api/app/scans/__init__.py`, `services/api/app/vulnerability/__init__.py`, `services/api/app/ai/__init__.py`, `services/api/app/cicd/__init__.py` | Package markers; the vulnerability package initializer also exposes its intended module API. |

### Vulnerability analysis modules

These are capabilities wired into the Phase 2 engine. Their presence does not
expand target authorization; test only systems explicitly in scope.

| File | Functions and responsibility |
|---|---|
| `services/api/app/vulnerability/engine.py` | `_now()` returns UTC time. `run_vulnerability_scan()` loads scan/target/inventory, prioritizes endpoints, selects analysis modules by profile, records metrics/findings, and finalizes scan status. Its nested `send_request()` rechecks kill switch, scope, and rate limit and applies the request timeout. |
| `services/api/app/vulnerability/risk_analyzer.py` | `get_endpoint_priority_score()` assigns inventory priority; `prioritize_endpoints()` sorts it; `analyze_zombie_and_shadow_risks()` creates risk records from inventory classification and evidence. |
| `services/api/app/vulnerability/rbac_bola.py` | `find_path_parameter()` identifies an endpoint's path parameter; `run_rbac_and_bola_fuzzing()` evaluates access-control behavior using available inventory/role observations and the supplied bounded sender. |
| `services/api/app/vulnerability/parameter_fuzzing.py` | `generate_type_aware_payloads()` prepares parameter-shaped test inputs; `evaluate_fuzz_response()` interprets responses; `run_parameter_fuzzing()` coordinates parameter checks through the engine-provided request sender. |
| `services/api/app/vulnerability/business_flow.py` | `run_business_flow_validation()` assesses whether endpoints annotated with sensitive business-flow categories maintain expected state/sequence constraints; it can also perform passive inventory-based checks. |

### Remediation, reporting, and integrations

| File | Functions and responsibility |
|---|---|
| `services/api/app/remediation/compliance.py` | `classify()` maps a vulnerability to supported OWASP/CWE categories; `map_vulnerability()` persists mapping rows; `target_posture()` aggregates target compliance posture. |
| `services/api/app/remediation/ticketing.py` | `TicketingError` represents integration errors. `RestAdapter.request()` performs bounded REST calls; `JiraCloudAdapter` and `GitHubIssuesAdapter` implement ticket create/status operations. `adapter_for()` selects an integration. `_ticket_context()` prepares ticket data. `create_ticket()`, `sync_ticket()`, and `create_eligible_tickets()` persist and synchronize remediation records. |
| `services/api/app/remediation/reporting.py` | `executive_report()` aggregates target risk, inventory, and posture; `render_html()` renders the HTML export. |
| `services/api/app/reporting.py` | `render_scan_report_pdf()` renders scan-level stages, evidence, and findings. `render_executive_report_pdf()` renders the executive report. Each function has local paragraph/section/table formatting helpers. |
| `services/api/app/cicd/gates.py` | `evaluate_gate()` compares active findings with severity/CVSS policy and returns pass/warn/fail, summary, violations, and warnings. |
| `services/api/app/cicd/webhooks.py` | `WebhookDeliveryError` reports delivery failures. `signature_for()` signs a body; `validate_webhook_url()` checks destination safety; `_payload_for()` prepares provider-specific payloads; `_post_json()` sends without following redirects. `dispatch_subscription()` delivers one event; `dispatch_event()` selects matching subscriptions. |

### AI-assisted patch candidates

| File | Functions and responsibility |
|---|---|
| `services/api/app/ai/patcher.py` | `PatchGenerationError`, `PatchCandidate`, and `PatchInferenceProvider` define errors, output, and provider contract. `configure_patch_provider()` installs a trusted adapter. `normalize_repo_path()` rejects non-repository paths. `_sql_parameterization()`, `_authorization_guard()`, and `_integer_validation()` are narrow deterministic transformations. `_diff()` produces a unified diff. `generate_patch()` validates inputs/provider output and returns a candidate; it never edits a repository. |
| `services/api/app/ai/patcher_tasks.py` | `_result()` builds a JSON-safe, workspace-tagged result. `generate_patch_task()` validates worker context, decrypts task inputs, invokes the patcher, and persists the candidate. |

### Database migrations

`services/api/alembic.ini` points Alembic at the migration directory.
`services/api/migrations/env.py` loads model metadata and runs offline/online
migrations. `script.py.mako` is the template for new migration scripts. Every
revision implements `upgrade()` and `downgrade()`.

| Revision | Schema area added |
|---|---|
| `0001_initial.py` | Initial targets, scans, endpoints, findings, evidence, and audit schema. |
| `0002_inventory_snapshots.py` | Inventory snapshot persistence. |
| `0003_change_detection.py` | Change events and scan cancellation-related state. |
| `0004_inventory_text.py` | Expanded endpoint inventory text/metadata. |
| `0005_staging_readiness.py` | Staging readiness, test-account credentials, and review-gate records. |
| `0006_evidence_backed_inventory.py` | Traffic observations, parameters, roles, and evidence-backed inventory fields. |
| `0007_vulnerability_engine.py` | Vulnerability scan/findings and framework mapping data. |
| `0008_remediation_and_compliance.py` | Remediation tickets and compliance structures. |
| `0009_cicd_and_webhooks.py` | CI evaluation and webhook subscription data. |
| `0010_enterprise_ai_patching.py` | Workspace/organization support, code patches, and enterprise changes. |
| `0011_celery_task_tracking.py` | Background task tracking support. |
| `0012_envelope_encryption.py` | Wrapped data-encryption-key fields for protected stored values. |

### Web application

| File | Functions and responsibility |
|---|---|
| `apps/web/app/page.tsx` | `Home()` is the route entry and renders `ExperienceGate`. |
| `apps/web/app/layout.tsx` | `RootLayout()` loads global styles, page metadata, and the shared HTML shell. |
| `apps/web/app/globals.css` | Global styles and dashboard/login visual system. |
| `apps/web/app/ui/experience-gate.tsx` | `ExperienceGate()` manages the intro/login/dashboard stages. `enterWorkspace()` checks required local form fields and sets the session-only interface flag; this is not server authentication. |
| `apps/web/app/ui/dashboard.tsx` | `supportsScan()` decides whether a target has a supported UI scan option. `messageFrom()` and `responseError()` format errors; `formatDate()` formats timestamps. `Dashboard()` loads data and owns `startScan()`, `cancelScan()`, `toggleKillSwitch()`, `createTarget()`, `importHar()`, `retestFinding()`, `approveTest()`, `rejectTest()`, `approveFinding()`, and `rejectFinding()`. `Metric()` renders dashboard metric cards. |
| `apps/web/app/targets/[id]/import/page.tsx` | `responseMessage()` extracts API errors. `OpenAPIImportPage()` manages spec upload state; `chooseFile()`, `onDrop()`, and `onFileInput()` validate/select a file; `importSpec()` submits it to the API. |
| `apps/web/components/ScanProgress.tsx` | `authHeaders()` formats optional authorization; `statusStyle()` maps statuses to visual styles; `formatDuration()` formats elapsed time; `Metric()` renders scan metrics. `ScanProgress()` polls Phase 2 scan state, retries transient errors, and renders status/progress/severity. |
| `apps/web/components/PatchReview.tsx` | `authHeaders()` and `errorMessage()` prepare requests; `DiffLine()` styles unified-diff rows. `PatchReview()` coordinates asynchronous generation, polls task/patch status, supports approval, and sends simulate/record application requests. |
| `apps/web/next.config.ts` | Enables Next.js standalone output for the production container. |
| `apps/web/postcss.config.mjs`, `apps/web/tailwind.config.ts` | Tailwind/PostCSS styling configuration. |
| `apps/web/package.json`, `apps/web/package-lock.json` | Frontend scripts, dependencies, and locked dependency graph. |
| `apps/web/tsconfig.json`, `apps/web/next-env.d.ts` | TypeScript configuration and Next.js-generated type declarations. |
| `apps/web/Dockerfile` | Multi-stage Next.js dependency install, production build, and standalone runner. |

`PatchReview` and `ScanProgress` are reusable components; the current dashboard
screen does not mount every enterprise workflow. Their existence should not be
read as proof that a complete end-user flow is exposed in the navigation.

### Synthetic demo target

| File | Responsibility |
|---|---|
| `fixtures/demo-app/main.py` | Defines `/health` and the synthetic booking read route. `health()` is the liveness endpoint; `get_booking()` requires a synthetic agency identity and uses `DEMO_FIX_IDOR` to switch the fixture between vulnerable and fixed behavior. |
| `fixtures/demo-app/requirements.txt` | Fixture runtime dependencies. |
| `fixtures/demo-app/Dockerfile` | Builds the isolated Python/FastAPI fixture container. |

### Tests

Backend tests are under `services/api/tests`; the fixture's HTTP behavior tests
are under `fixtures/demo-app/tests`. The tests use `unittest` and exercise API,
database, and worker components with isolated/test database setup and mocks
where appropriate.

| Test file | Coverage focus |
|---|---|
| `test_api_integration.py` | Dashboard/report APIs, target allowlist, imports, deploy-triggered/manual scans, retests, and kill-switch behavior. |
| `test_scan_orchestration.py` | Legacy scan stages, scope/rate limits, cancellation, deterministic verification, evidence, deduplication, and retests. |
| `test_safety_policy.py` | URL scope, executor targeting, redaction, and token-bucket behavior. |
| `test_staging_readiness.py` | Executor registry, encrypted credentials, redaction, and human approval gates. |
| `test_openapi_importer.py` | OpenAPI/Swagger parsing, safe references, validation, and route ingestion. |
| `test_evidence_backed_inventory.py` | HAR/log ingestion, parameter shapes, endpoint classification, time windows, and version notes. |
| `test_vulnerability_engine.py` | Phase 2 analysis modules, profiles, and API behavior. |
| `test_celery_workers.py` | Worker success/failure, task serialization/limits, tenant context, and encrypted task data. |
| `test_remediation_phase3.py` | Compliance mapping, ticket creation/sync, and executive reporting. |
| `test_cicd_phase4.py` | Gate policies, signed webhook delivery, and subscription matching. |
| `test_enterprise_phase5.py` | Patch candidates, workspace scoping/RBAC, and review-before-apply behavior. |
| `test_envelope_encryption.py` | Envelope encryption, context binding, and key handling. |
| `test_migrations.py` | Migration revision/application behavior. |
| `fixtures/demo-app/tests/test_fixture_integration.py` | Synthetic demo behavior before/after the fixture fix and rejection of missing identity. |

## Configuration and running locally

Follow [README.md](./README.md) for the canonical Compose startup, migrations,
seed, and test commands. The important configuration groups are database and
Redis URLs; target/staging origin allowlists; the demo fix toggle; enterprise
authentication; encryption keys; worker time limits; and optional Jira/GitHub
integration settings. `.env.example` documents variable names; secrets belong
only in an ignored local environment or an external secret store.

For production-like use, enable enterprise authentication behind the trusted
identity gateway, configure high-entropy encryption material for both API and
worker, use explicit target authorization and allowlists, and review the
deployment/network posture. The login screen alone is not an access-control
boundary.

## Current boundaries and unimplemented areas

The repository includes initial implementations of inventory classification,
two scan paths, access-control and parameter analysis modules, business-flow
checks, evidence/reporting, review gates, compliance/ticket integrations,
webhooks, workspace scoping, and patch-candidate review. It is not a complete
general-purpose scanner or autonomous remediation system. Browser crawling,
VLM-assisted reconnaissance, JavaScript/DNS/certificate change watchers,
comprehensive attack planning, broad specialist executor coverage, an event
bus, multi-agent verification, and direct repository mutation are not
implemented. Use only synthetic, localhost, staging, or other explicitly
authorized targets, and preserve the existing safety checks when extending
the project.
