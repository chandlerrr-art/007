# 007 Security Scanner — Phase 2: Targeted Vulnerability Scanning, Authorization Fuzzing & Business Flow Validation

**Implementation Date:** October 2026
**Milestone:** Phase 2: Targeted Vulnerability Scanning, Authorization Fuzzing & Business Flow Validation
**Status:** Implemented, Tested, and Verified (55/55 Automated Tests Passing — 100% Pass Rate)

---

## Executive Overview

This document details the architectural design, database extensions, scanning engines, API endpoints, and verification suite for **Phase 2: Targeted Vulnerability Scanning, Authorization Fuzzing & Business Flow Validation** in the 007 Security Scanner platform.

Building directly upon the foundation established in **Phase 1: Evidence-Backed Inventory** (traffic-grounded knowledge graphs, parameter typing, role observations, and active/zombie/shadow route classification), Phase 2 implements targeted active probing and logic verification. It detects broken object-level authorization (BOLA/IDOR), cross-role privilege escalation, injection vulnerabilities across type-aware parameters, business-flow state bypasses, and unmanaged shadow/zombie API surface exposure.

---

## 1. Database Schema & Migration Architecture

### 1.1 Alembic Migration (`0007_vulnerability_engine.py`)
Adds dedicated tracking tables for targeted scan executions and granular vulnerability findings:

* **`vulnerability_scans` table:**
  * `id`: Integer (PK)
  * `target_id`: Integer (FK &rarr; `targets.id`, `ON DELETE CASCADE`)
  * `status`: VARCHAR(40) (`pending`, `running`, `completed`, `failed`)
  * `started_at`: TIMESTAMPTZ (nullable)
  * `completed_at`: TIMESTAMPTZ (nullable)
  * `config_snapshot`: TEXT (JSON snapshot of scan profile, options, and live metrics)

* **`discovered_vulnerabilities` table:**
  * `id`: Integer (PK)
  * `scan_id`: Integer (FK &rarr; `vulnerability_scans.id`, `ON DELETE CASCADE`)
  * `endpoint_id`: Integer (FK &rarr; `endpoints.id`, `ON DELETE CASCADE`)
  * `parameter_id`: Integer (nullable FK &rarr; `endpoint_parameters.id`, `ON DELETE SET NULL`)
  * `vuln_type`: VARCHAR(100) (`bola_idor`, `broken_authentication`, `rbac_privilege_escalation`, `sqli`, `nosqli`, `command_injection`, `mass_assignment`, `integer_boundary_overflow`, `business_logic_bypass`, `unauthorized_shadow_exposure`, `unrestricted_zombie_access`)
  * `severity`: VARCHAR(40) (`critical`, `high`, `medium`, `low`, `info`)
  * `cvss_score`: FLOAT (e.g. 0.0 to 10.0)
  * `evidence_payload`: TEXT (redacted request/response verification snippet)
  * `remediation_advice`: TEXT (actionable engineering remediation instructions)
  * `status`: VARCHAR(40) (`open`, `verified`, `false_positive`)
  * `created_at`: TIMESTAMPTZ (`server_default=now()`)

### 1.2 Entity Models (`app/models.py`)
* Defined `VulnerabilityScan` and `DiscoveredVulnerability` SQLAlchemy ORM models with bidirectional cascade mappings.

---

## 2. Core Scanning Modules & Engines

The Phase 2 engine is organized into modular packages under `services/api/app/vulnerability/`:

### A. Role-Based Access Control (RBAC) & BOLA/IDOR Fuzzing Engine (`rbac_bola.py`)
* **Path Parameter & Object Identifier Detection:**
  * Detects normalized `{param}` placeholders (e.g., `{booking_id}`, `{id}`) and parameters with `location == "path"`.
* **Automated BOLA/IDOR Probing:**
  * Executes cross-tenant and cross-object ID substitutions (e.g. attempting to read foreign record `2002`).
  * If a foreign object is returned with HTTP 200 without tenant ownership validation, flags `bola_idor` (CVSS 8.5) and links directly to the path `parameter_id`.
* **Cross-Role Access & Privilege Escalation:**
  * Correlates route requirements with `endpoint_role_observations` and reachability metadata.
  * Sends unauthenticated requests against protected routes, flagging `broken_authentication` (CVSS 9.1).
  * Injects standard `travel_agent` credentials against administrative routes (`/api/v1/admin/*`), flagging `rbac_privilege_escalation` (CVSS 8.8) upon unauthorized access.

### B. Parameter-Level Fuzzing & Type-Safe Injection Engine (`parameter_fuzzing.py`)
* **Strict Type-Aware Payload Generation:**
  * **Integer / Number Parameters:** Injects numeric boundary values (`2147483648`, `-1`, `999999999999999999`, `0`) and numeric SQL probes (`1 OR 1=1`), strictly preventing non-numeric string types that cause client validation (422) failures.
  * **String Parameters:** Injects SQLi probes (`' OR '1'='1`, `admin'--`), NoSQLi probes (`{"$gt": ""}`), and safe canary command injection probes (`; echo 007_canary`, `| echo 007_canary`).
  * **Body Parameters:** Injects mass assignment payloads containing privileged model attributes (`{"is_admin": true, "role": "admin"}`).
  * **Boolean Parameters:** Injects boolean toggle states (`true`, `false`).
* **Deterministic Response Evaluation:**
  * Detects SQL syntax error signatures (`syntax error`, `unclosed quotation mark`, `sqlite3.OperationalError`, `PostgreSQL ERROR`).
  * Detects MongoDB/NoSQL exception patterns (`MongoError`, `$gt`).
  * Validates command injection via reflection of canary token `007_canary`.
  * Flags mass assignment when privileged attributes are accepted into the response schema.
  * Detects integer boundary overflows upon HTTP 500 arithmetic exceptions.

### C. Business Flow Logic Validation Engine (`business_flow.py`)
* **State-Machine Bypass Verification:**
  * Evaluates multi-step travel transaction flows (`search` &rarr; `hold` &rarr; `book` &rarr; `pay` &rarr; `cancel`).
  * Probes `/pay` endpoints with un-held/fictitious booking IDs: flags `business_logic_bypass` (CVSS 8.3) if charges are accepted without prerequisite entity state.
  * Probes `/cancel` endpoints without an active reservation: flags `business_logic_bypass` (CVSS 8.0) if cancellations succeed on invalid transitions.

### D. Zombie & Shadow Risk Analyzer (`risk_analyzer.py`)
* **Priority Queue Scheduling:**
  * **Priority 1 (Highest):** Shadow APIs (`classification == "shadow"` or `recommended_action == "bring_up_to_date"`).
  * **Priority 2:** Zombie APIs (`classification == "zombie"` or `recommended_action in ["decommission", "restrict"]`).
  * **Priority 3:** Active APIs (`classification == "active"`).
  * Within each tier, routes with higher `traffic_hit_count` are processed first.
* **Governance Risk Detection:**
  * Flags `unauthorized_shadow_exposure` (CVSS 7.6–8.6) on unmanaged active routes.
  * Flags `unrestricted_zombie_access` (CVSS 6.3–7.2) on deprecated legacy routes that remain callable.

### E. Vulnerability Engine Orchestrator (`engine.py`)
* Implements background worker supporting scan profiles:
  * `quick`: High-speed queue prioritizing Shadow & Zombie governance risks, RBAC reachability, and boundary fuzzing.
  * `deep`: Full multi-engine vulnerability assessment (RBAC + BOLA cross-role matrix, complete parameter-level injection, and business flow state validation).
  * `auth_matrix_only`: Dedicated role-based access control and BOLA/IDOR fuzzer.
* Enforces Phase 0 safety foundations: token-bucket rate limits, scope validation, kill-switch checks, timeout bounds, and credential scrubbing.

---

## 3. API Endpoints & Orchestration

Added to `services/api/app/main.py`:

| Endpoint | Method | Status | Description |
|---|---|---|---|
| `/api/targets/{id}/scans` | POST | 202 Accepted | Initializes and triggers an asynchronous Phase 2 vulnerability scan with configurable profiles (`quick`, `deep`, `auth_matrix_only`). Enforces kill switch (409) and target allowlist (422). |
| `/api/targets/{id}/scans/{scan_id}` | GET | 200 OK | Retrieves real-time scan progress (`progress_percentage`), execution duration, live finding counts by severity (`critical`, `high`, `medium`, `low`, `info`), and runtime metrics (`endpoints_scanned`, `parameters_tested`, `requests_sent`). |
| `/api/targets/{id}/vulnerabilities` | GET | 200 OK | Filterable vulnerability register supporting query parameters: `scan_id`, `severity`, `vuln_type`, `status`, `endpoint_id`. Returns linked endpoint paths, parameter details, CVSS scores, evidence payloads, and remediation advice. |

---

## 4. File Modification & Creation Inventory

| File Path | Type | Role & Changes |
|---|---|---|
| `services/api/migrations/versions/0007_vulnerability_engine.py` | New | Alembic migration creating `vulnerability_scans` and `discovered_vulnerabilities` tables. |
| `services/api/app/vulnerability/__init__.py` | New | Module exports for Phase 2 vulnerability engines and orchestrator. |
| `services/api/app/vulnerability/risk_analyzer.py` | New | Engine D: Queue prioritization (Shadow &rarr; Zombie &rarr; Active) and governance exposure detection. |
| `services/api/app/vulnerability/rbac_bola.py` | New | Engine A: BOLA/IDOR path parameter fuzzing and cross-role authorization matrix checks. |
| `services/api/app/vulnerability/parameter_fuzzing.py` | New | Engine B: Type-safe payload generation (boundaries, SQLi, NoSQLi, command injection canary, mass assignment). |
| `services/api/app/vulnerability/business_flow.py` | New | Engine C: State-machine bypass verification for business flows (`pay`, `cancel`). |
| `services/api/app/vulnerability/engine.py` | New | Scan orchestrator & background worker supporting `quick`, `deep`, and `auth_matrix_only` profiles. |
| `services/api/tests/test_vulnerability_engine.py` | New | Comprehensive test suite covering all Phase 2 scanning engines, profiles, safety controls, and API endpoints. |
| `services/api/app/models.py` | Modified | Added `VulnerabilityScan` and `DiscoveredVulnerability` SQLAlchemy ORM models. |
| `services/api/app/main.py` | Modified | Registered `POST /api/targets/{id}/scans`, `GET /api/targets/{id}/scans/{scan_id}`, and `GET /api/targets/{id}/vulnerabilities`. |
| `services/api/tests/test_migrations.py` | Modified | Updated migration head assertion to `0007_vulnerability_engine` and added table assertions. |
| `CHANGES.md` | New | Complete documentation of Phase 2 changes, design rationale, and verification results. |
| `PHASE_2_CHANGES.md` | New | Mirror record matching repository phase change document naming scheme. |

---

## 5. Automated Verification Results

All unit, integration, migration, and vulnerability engine tests pass with zero errors:

```powershell
.venv\Scripts\python.exe -m pytest services/api/tests
```

```
============================= test session starts =============================
platform win32 -- Python 3.14.6, pytest-8.4.2, pluggy-1.7.0
rootdir: C:\Users\ftdab\OneDrive\Documents\007\services\api
configfile: pyproject.toml
plugins: anyio-4.15.1
collected 55 items

services\api\tests\test_api_integration.py ........                      [ 14%]
services\api\tests\test_evidence_backed_inventory.py ........            [ 29%]
services\api\tests\test_migrations.py .                                  [ 30%]
services\api\tests\test_safety_policy.py .........                       [ 47%]
services\api\tests\test_scan_orchestration.py ...........                [ 67%]
services\api\tests\test_staging_readiness.py ......                      [ 78%]
services\api\tests\test_vulnerability_engine.py ............             [100%]

======================= 55 passed, 4 warnings in 13.82s =======================
```

### Verification Against Phase 2 Acceptance Criteria:
1. **BOLA/IDOR Detection:** Verified that object ID swapping on parameterized routes accurately flags BOLA vulnerabilities and links them to path parameter IDs.
2. **Type-Safe Parameter Fuzzing:** Verified that integer parameters receive numeric boundaries, string parameters receive injection vectors, and body parameters receive mass assignment payloads without triggering schema corruption or unhandled validation errors.
3. **Business Logic Bypass:** Verified that skipping prerequisite flow states (`hold`/`book`) when invoking payment or cancellation triggers state-bypass findings.
4. **Zombie & Shadow Prioritization:** Confirmed that Shadow APIs and Zombie endpoints take scan queue precedence over Active endpoints.
5. **Scan Orchestration & APIs:** Verified asynchronous scan execution across `quick`, `deep`, and `auth_matrix_only` profiles with real-time status reporting, severity rollups, and filterable vulnerability queries.

# 007 Security Scanner — Phase 3 Changes

**Date:** October 30, 2026  
**Milestone:** Remediation Workflows, Ticketing Integration & Compliance Reporting  
**Verification:** 59 tests passed

## Database

- Added Alembic migration `0008_remediation_and_compliance.py`.
- Added `remediation_tickets` with finding linkage, external provider and ticket details, status, assignee, and timestamps. A finding can have at most one ticket per provider.
- Added `compliance_frameworks` and `vulnerability_compliance_mappings`.
- Seeded all ten OWASP API Security Top 10 (2023) categories and CWE classifications used by the mapper.

## Remediation and compliance services

- Added Jira Cloud and GitHub Issues REST adapters, configured through environment settings.
- Added idempotent ticket creation, critical/high severity auto-ticketing after vulnerability scans, and ticket status synchronization. Resolved external tickets mark the internal vulnerability resolved.
- Added vulnerability classification rules that persist OWASP API and CWE mappings, plus target compliance summaries with category status and affected endpoints.
- Added executive report aggregation for CVSS-based target risk, severity totals, vulnerable business flows, ticket resolution metrics, and remediation guidance.
- Added JSON and downloadable HTML executive report output.

## API

- `POST /api/vulnerabilities/{id}/tickets` creates a Jira or GitHub issue.
- `POST /api/remediation/tickets/{id}/sync` synchronizes provider status and assignee.
- `GET /api/targets/{id}/compliance` returns OWASP API Top 10 posture.
- `GET /api/targets/{id}/reports/executive?format=json|html` exports the executive report.

## Configuration and verification

- Documented Jira and GitHub environment variables in `.env.example`.
- Added Phase 3 tests for BOLA classification, ticket creation and closure sync, compliance posture, and executive report generation.
- Updated migration verification to require the Phase 3 tables and migration head.
- Ran the complete API test suite: **59 passed**. Four deprecation or pytest collection warnings were reported.

## Phase 4: CI/CD and webhook notifications

- Added Alembic migration `0009_cicd_and_webhooks.py` with build-evaluation and webhook-subscription tables. Evaluations retain both a policy snapshot ID and the evaluated JSON policy.
- Added a security gate evaluator for severity and CVSS thresholds. It ignores resolved/false-positive findings and returns pass, warn, or fail with machine-readable summaries and exit codes.
- Added GitHub Actions and GitLab CI templates under `services/api/app/cicd/templates/` to run a scan, wait for completion, and enforce a gate.
- Added asynchronous, event-filtered Slack, Microsoft Teams, and custom webhook delivery, signed with HMAC-SHA256 in `X-007-Signature`. Webhook secrets are encrypted at rest; outbound destinations must resolve to public HTTPS addresses, and redirects are rejected.
- Added APIs to evaluate CI gates, create or update subscriptions, list subscriptions without revealing secrets, and send a signed test notification.
- Added best-effort event dispatch for completed scans, critical findings, and failed gates.
- Added Phase 4 tests for gate thresholds, HMAC generation, dispatch filtering/signatures, and updated migration verification.
- Verification: **64 API tests passed**; four pre-existing deprecation/collection warnings remain.
