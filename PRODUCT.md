# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Next.js 15, React 19, and TypeScript frontend; FastAPI API with PostgreSQL and Redis/Celery services.

## Users

Application security engineers and security-conscious developers validating applications they own or are explicitly authorized to test.

## Product Purpose

007 is a local-first dynamic application security testing workspace. It helps operators inventory targets, run bounded scans, review and verify findings, and coordinate human-approved remediation. Success means making authorized testing safer and findings actionable without obscuring scan state or evidence.

## Positioning

007 combines explicit target authorization, per-scan request budgets, safety controls, deterministic verification, and human review in one local-first workflow. Its current scan coverage is intentionally partial rather than a general-purpose exhaustive scanner.

## Operating Context

Operators work from a web dashboard connected to a local FastAPI service, PostgreSQL, and Redis/Celery workers. The repository includes a synthetic demo target and a separate explicitly allowlisted staging executor. Typical work proceeds from scope and safety checks to a bounded scan, finding triage and retest, and reviewed remediation.

## Capabilities and Constraints

- Dashboard summaries, health status, target registration, HAR/OpenAPI/gateway-log inventory, endpoint snapshots and change events.
- Scan start, status, cancellation, bounded staging/demo execution, PDF reports, finding review and retest, and safety status/kill switch.
- Compliance and remediation tickets, CI/CD gates and webhooks, workspace context, and reviewed patch candidates.
- Authorization is explicit: target origins must be allowlisted, and allowlisting alone does not grant permission to test. Outbound requests are rechecked against scope.
- Scans must remain bounded and non-destructive; executors enforce allowlists, request/time budgets, concurrency limits, redaction, and health checks.
- Findings require deterministic evidence to be marked verified. Patch candidates require human review; applying one is recorded by the backend and does not modify repository files.
- The product is local-first. The unauthenticated configuration is for localhost demo use only, not network deployment.
- Scan coverage is an evolving partial implementation; do not imply capabilities that are not present or fabricate results.

## Evidence on Hand

- Repository product and workflow documentation: `README.md` and `PROJECT_WORKFLOW.md`.
- A synthetic local demo target and seeded demo records; no real customer data, credentials, testimonials, or performance claims should be introduced.
- Existing backend APIs and dashboard operations in `apps/web/app/ui/dashboard.tsx`.

## Product Principles

- Make authorization and operational safety visible before scan execution.
- Keep scan progress, results, and evidence legible and attributable.
- Separate observed results from hypotheses and unverified findings.
- Preserve human control over review and remediation.
- Be candid about current scope and partial coverage.
