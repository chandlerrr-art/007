# 007 Security Scanner — Development & Implementation Report

**Assessment & Implementation Date:** October 2026  
**Milestone:** Phase 0 (Staging Readiness & Guardrails) & Phase 1 (Change Detection & Triggering)  
**Status:** Implemented, Tested, and Verified (35/35 Automated Tests Passing)

---

## Executive Overview

This document summarizes the architecture, design choices, database migrations, security boundaries, and specific files modified and added during the implementation of **Phase 1: Change Detection & Triggering** and **Phase 0: Staging Readiness & Guardrails**.

A core architectural tenet maintained throughout this implementation is the **Critical Safety Constraint**:
> *The existing local-demo fixture executor, its hard-coded IDOR probe, 4-request budget, and strict restriction to `http://demo-app:8080` remain completely untouched and intact. All staging capabilities, credential management, and review gates were added alongside it via a pluggable registry.*

---

## 1. Phase 1: Change Detection & Continuous Ingestion

Phase 1 provides real-time change signals that notify the platform when application code or surface areas change, triggering safe, bounded security testing.

### 1.1 CI/CD Deploy Webhook (`POST /api/webhooks/deploy`)
- **Purpose:** Ingests deployment notices directly from CI/CD pipelines (e.g., GitHub Actions, GitLab CI, ArgoCD).
- **Behavior:**
  - Validates `target_id` against the authorized target registry.
  - Validates `release` tags against a safe alphanumeric regex (`^[A-Za-z0-9._+/-]*$`).
  - Discards free-form comments to prevent accidental persistence of secrets.
  - Automatically records a `ChangeEvent(source="ci_cd_webhook")`.
  - Unless the safety kill switch is engaged, a scan is already running, or the target origin is unauthorized, automatically queues a bounded scan (`trigger="change_detected"`).

### 1.2 Traffic-Diff Watcher (Endpoint Inventory Snapshotting)
- **Purpose:** Identifies new, modified, or decommissioned API routes across releases or between scans.
- **Behavior:**
  - The inventory stage computes route keys (`METHOD /path`) and diffs them against the previous `InventorySnapshot`.
  - When changes are observed, it generates a `ChangeEvent(source="traffic_diff")` capturing added and removed endpoints.
  - Keeps the discovery and inventory feed up-to-date without requiring an OpenAPI/Swagger spec.

### 1.3 Change Feed API & Dashboard Stream
- **Endpoint:** `GET /api/changes` returns the last 20 change events with timestamps, source, details, and linked triggered scan IDs.
- **Dashboard UI:** Displays the live "Change events" card on the frontend (`apps/web/app/ui/dashboard.tsx`).

---

## 2. Phase 0: Staging Readiness & Guardrails

Phase 0 establishes the safety foundations and boundaries required to scan staging targets safely without weakening the demo boundary or leaking test secrets.

### 2.1 Separate Staging-Target Executor & Registry
- **Executor Registry (`app/scans/registry.py`):**
  - Implements `BaseScanExecutor` protocol and singleton `executor_registry`.
  - Independently registers `LocalDemoExecutor` (delegating to the untouched local-demo access control check) and `StagingTargetExecutor`.
  - Dynamically dispatches target scans based on target environment and allowlist qualification.
- **Staging Executor (`app/scans/staging_executor.py`):**
  - Dedicated request budget (`staging_request_budget: 10`, separate from the local-demo 4-request budget).
  - Modular attack logic (never uses the demo's synthetic booking 2002 probe).
  - Reuses the shared safety layer: allowlist verification, per-endpoint token-bucket rate limiter, 3-second timeout, pre/postflight health checks, kill-switch check, and audit logging.
- **Target Allowlist Update (`app/settings.py`, `app/safety/policy.py`):**
  - Accepts explicit staging entries (`allowed_staging_origins`) alongside `allowed_target_origins`.
  - `supports_demo_executor` strictly enforces that only `http://demo-app:8080` in `local-demo` runs the demo fixture.

### 2.2 Scoped Test-Account Credential Store
- **Encrypted-at-Rest Table (`app/safety/credentials.py`, `test_credentials` table):**
  - Stores role-scoped test credentials (`admin`, `travel_agent`, `customer`, etc.) associated with specific targets.
  - Encryption uses PBKDF2-HMAC-SHA256 key derivation with authenticated CTR-keystream encryption and HMAC integrity verification.
  - Master key configured via `credential_encryption_key` in settings.
- **Strict Call-Time Injection:**
  - `get_call_time_auth_headers()` decrypts credentials strictly when constructing outgoing HTTP requests inside the staging executor.
  - Credentials are never stored in memory longer than necessary.
- **Zero-Cleartext Redaction Discipline:**
  - `register_secret_for_redaction()` and `scrub_known_secrets()` dynamically scrub all registered secret strings from operational text.
  - Credentials and response bodies are strictly prohibited from `audit_events`, `evidence`, `findings`, scan reports, and API payloads.
  - `GET /api/targets/{id}/credentials` redacts secret values entirely.

### 2.3 Human Approval States & Reviewer System
- **State Machine Extension (`app/models.py`):**
  - Added `TestExecution` model (`test_executions` table) with states: `pending_review`, `approved`, `rejected`, `executed`, `skipped`.
  - Extended `Finding.status` with `pending_review`, `approved`, `rejected` (alongside `open` and `resolved`).
- **Orchestrator Review Gates:**
  - Risky tests (e.g. privilege escalation, administrative mutations) automatically enter `pending_review` and are blocked from executing until a human approves them.
  - Candidate high-severity findings enter `pending_review` before being escalated or reported as verified.
- **Reviewer API Endpoints (`app/main.py`):**
  - `GET /api/reviews`: Returns pending risky tests and findings awaiting reviewer sign-off.
  - `POST /api/reviews/tests/{test_id}/approve`: Approves a blocked risky test and audits the decision.
  - `POST /api/reviews/tests/{test_id}/reject`: Rejects a risky test and audits the decision.
  - `POST /api/reviews/findings/{finding_id}/approve`: Approves and verifies a candidate high-severity finding.
  - `POST /api/reviews/findings/{finding_id}/reject`: Rejects a finding as false positive or out-of-scope.
  - `POST /api/targets/{target_id}/credentials`: Registers scoped test accounts.
- **Dashboard Reviewer UI (`apps/web/app/ui/dashboard.tsx`):**
  - Rendered a dedicated **Human Review Queue** card showing pending tests and findings with one-click "Approve" and "Reject" buttons.
  - Integrated approval and rejection buttons into the findings table for `pending_review` findings.

---

## 3. Database Schema & Migrations

- **Migration `0005_staging_readiness.py`:**
  - Created table `test_credentials` (`id`, `target_id`, `role`, `username`, `auth_type`, `header_name`, `encrypted_secret`, `created_at`, `updated_at`).
  - Created table `test_executions` (`id`, `scan_id`, `target_id`, `endpoint_id`, `name`, `test_type`, `is_risky`, `risk_level`, `risk_rationale`, `status`, `reviewer_notes`, `reviewed_at`, `created_at`).
  - Added `review_notes` and `reviewed_at` columns to `findings`.
- Verified cleanly through Alembic migration tests against SQLite and PostgreSQL.

---

## 4. File Modification & Creation Inventory

| File Path | Type | Role & Changes |
|---|---|---|
| `services/api/app/safety/credentials.py` | New | Cryptographic credential store (authenticated encryption at rest), call-time header injection, dynamic secret scrubber. |
| `services/api/app/scans/staging_executor.py` | New | Staging executor with 10-request budget, modular attack logic, human approval gates, and health check validation. |
| `services/api/app/scans/registry.py` | New | Executor registry with `BaseScanExecutor` protocol registering `LocalDemoExecutor` and `StagingTargetExecutor`. |
| `services/api/migrations/versions/0005_staging_readiness.py` | New | Alembic DDL migration creating `test_credentials`, `test_executions`, and extending `findings`. |
| `services/api/tests/test_staging_readiness.py` | New | Complete test suite for Phase 0 DoD: independent staging scans, credential redaction, and human review gates. |
| `services/api/app/models.py` | Modified | Added `TestExecution` and `TestAccountCredential` models, and review metadata to `Finding`. |
| `services/api/app/safety/policy.py` | Modified | Added `allowed_staging_origins`, `supports_staging_executor`, and dynamic secret scrubbing in `redact_operational_text`. |
| `services/api/app/settings.py` | Modified | Added `allowed_staging_origins`, `staging_request_budget`, and `credential_encryption_key`. |
| `services/api/app/scans/orchestrator.py` | Modified | Integrated `executor_registry` lookup in scope validation; preserved exact local-demo access control check unchanged. |
| `services/api/app/main.py` | Modified | Added credential store endpoints, reviewer queue endpoints (`/api/reviews`), and approval/rejection handlers. |
| `services/api/tests/test_migrations.py` | Modified | Updated migration head assertion to `0005_staging_readiness` and verified table creation. |
| `apps/web/app/ui/dashboard.tsx` | Modified | Added Human Review Queue section, approve/reject handlers, pending review metrics, and staging target support. |

---

## 5. Verification & Definition of Done

All 35 automated backend tests and the Next.js frontend production build pass with zero errors:

```powershell
.venv\Scripts\python -m unittest discover -s services\api\tests
# Ran 35 tests in 2.320s -> OK

cd apps\web; npm.cmd run build
# Next.js 15.1.6 -> Compiled successfully, type checks passed
```

### Verification against Definition of Done:
1. **Independent Staging Scanning:** Confirmed that a staging target can be registered and scanned through `StagingTargetExecutor` without altering `_run_access_control_check` or the demo boundary.
2. **Strict Redaction Rule:** Confirmed that credentials are encrypted at rest, decrypted only at outbound HTTP call time, dynamically redacted from all audit events, and omitted from all API responses.
3. **Human Approval Gate:** Confirmed that risky tests and high-severity findings enter `pending_review` and are blocked until approved via the reviewer API or UI.
