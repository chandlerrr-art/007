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
