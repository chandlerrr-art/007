# 007 Security Scanner — Phase 1: Evidence-Backed Inventory

**Implementation & Verification Report**  
**Milestone:** Phase 1: Evidence-Backed Inventory, Parameters, Role Observations & Traffic Classification  
**Date:** October 2026  
**Status:** Implemented, Tested, and Verified (43/43 Automated Backend Tests Passing)

---

## Executive Summary

This report documents the architectural design, database extensions, ingestion pipelines, classification algorithms, and test coverage for **Phase 1: Evidence-Backed Inventory** in the 007 vulnerability scanner.

Prior to this phase, the scanner relied on simple endpoint discovery with static or sample classifications. With this implementation, 007 now features a **traffic-grounded knowledge graph and dynamic classification engine** that:
1. Discovers and indexes request parameters (names, locations, observed types) under strict zero-cleartext redaction rules.
2. Tracks role-based access observations for test accounts.
3. Ingests HTTP Archive (HAR) captures and 30–90 day gateway/access logs (Common Log Format and JSON).
4. Derives empirical route classifications (**active**, **zombie**, and **shadow**) with version notes, business flows, team ownership, and lifecycle recommendations.

---

## 1. Database Schema & Migration Architecture

### 1.1 Alembic Migration (`0006_evidence_backed_inventory.py`)
The migration extends the core database schema by adding three dedicated relationship tables and augmenting the `endpoints` table with traffic and ownership metadata.

```
+--------------------------------------------------------------------------+
|                                endpoints                                 |
+--------------------------------------------------------------------------+
| id                     | Integer (PK)                                    |
| target_id              | Integer (FK -> targets.id, CASCADE)             |
| method                 | VARCHAR(12)                                     |
| path                   | VARCHAR(1000)                                   |
| classification         | VARCHAR(40)  ['active', 'zombie', 'shadow']     |
| sensitivity            | VARCHAR(40)                                     |
| source                 | VARCHAR(40)  ['HAR', 'traffic', 'manual']       |
| business_flow          | VARCHAR(40)  ['search','hold','book','pay',...] |
| api_version            | VARCHAR(20)  ['v1', 'v2', 'v3', ...]           |
| first_seen_traffic     | TIMESTAMPTZ (nullable)                          |
| last_seen_traffic      | TIMESTAMPTZ (nullable)                          |
| traffic_hit_count      | Integer (default: 0)                            |
| auth_required          | Boolean (default: true)                         |
| auth_reachability      | VARCHAR(80)  ['unauth','auth_only','role_restr']|
| owner                  | VARCHAR(120)                                    |
| likely_owner           | VARCHAR(120)                                    |
| version_notes          | VARCHAR(500)                                    |
| data_fields_summary    | TEXT                                            |
| recommended_action     | VARCHAR(100) ['keep_active','decommission',...]  |
+--------------------------------------------------------------------------+
       |                                   |
       | 1:N                               | 1:N
       v                                   v
+-------------------------------+   +------------------------------------+
|      endpoint_parameters      |   |    endpoint_role_observations      |
+-------------------------------+   +------------------------------------+
| id            | Integer (PK)  |   | id            | Integer (PK)       |
| endpoint_id   | Integer (FK)  |   | endpoint_id   | Integer (FK)       |
| name          | VARCHAR(160)  |   | role          | VARCHAR(80)        |
| location      | VARCHAR(40)   |   | allowed       | Boolean            |
| observed_type | VARCHAR(40)   |   | status_code   | Integer            |
| created_at    | TIMESTAMPTZ   |   | last_observed | TIMESTAMPTZ        |
+-------------------------------+   +------------------------------------+
```

### 1.2 Ingested Traffic Log Storage (`traffic_log_entries`)
Gateway and access log entries are persisted with observation-window metadata:

* `target_id`: FK to target.
* `endpoint_id`: Optional FK to matched endpoint (nullable with `ON DELETE SET NULL`).
* `method` & `path`: Normalized HTTP method and path template.
* `status_code`: Response status code (e.g., 200, 401, 403, 500).
* `timestamp`: Absolute UTC event timestamp from log entry.
* `window_days`: Configured observation window length (e.g. 30 or 90 days).
* `role`: User or role identifier extracted from log (e.g. `admin`, `travel_agent`, `customer`).
* `source`: Ingestion source identifier (default: `gateway_access_log`).

---

## 2. Ingestion Adapters & Redaction Rules

### 2.1 HAR Importer (`POST /api/targets/{id}/har-import`)
Extended the HAR importer in `app/inventory/service.py` to extract request schemas while discarding raw data:

* **URL Path Parameters:** Dynamic segments in paths are normalized into `{id}` templates (UUIDs, integer sequences, emails, phone numbers). Secret path segments (e.g. `/tokens/`, `/api_keys/`) are replaced with `{redacted}`.
* **Query Parameters:** Key names and inferred types (`string`, `integer`, `boolean`, `number`) are stored; raw query parameter values (tokens, secrets, PII) are immediately dropped.
* **Headers:** Header names are indexed with observed type `string`. High-noise transport headers (`Host`, `Connection`, `Content-Length`, `Accept-Encoding`) are filtered out. Values of `Authorization`, `Cookie`, and tokens are discarded.
* **Cookies:** Cookie names are indexed; sensitive session values are completely stripped.
* **Body / Payloads:** JSON objects and form-encoded payloads are traversed to record key names and field types (including nested array elements like `array[integer]`). No raw customer or payload values enter memory or disk storage.

### 2.2 Gateway & Access Log Ingestion (`POST /api/targets/{id}/gateway-logs`)
Accepts raw log payloads covering standard 30–90 day observation windows:

* **Format Support:**
  * **JSON Line Format:** Keys `timestamp`/`time`/`@timestamp`, `method`/`http_method`, `path`/`url`/`uri`, `status`/`status_code`, and `role`/`user_role`/`user`.
  * **Common Log Format (CLF) / Combined Log Format:** Regex-based parser handling standard Apache/Nginx access log lines:
    ```
    192.168.1.1 - travel_agent [15/Sep/2026:12:00:00 +0000] "GET /api/v1/bookings/2002 HTTP/1.1" 200 1234
    ```
* **Shadow Route Discovery:** If an access log line targets a route that was not part of the documented HAR or crawled routes, the system creates a candidate **Shadow API** route with `source = 'traffic'`.
* **Access Observation Updates:** Each logged hit updates `first_seen_traffic`, `last_seen_traffic`, and increments `traffic_hit_count`. When user roles are present, `EndpointRoleObservation` records track which roles succeeded (`status < 400`) or failed (`status >= 400`).

---

## 3. Classification Engine (Active / Zombie / Shadow)

The automated classifier (`classify_endpoints()` in `app/inventory/service.py` and `POST /api/targets/{id}/classify`) compares the discovered route inventory against the traffic window:

$$\text{Window Cutoff} = T_{\text{current}} - \Delta t_{\text{window\_days}}$$

### 3.1 Classification Taxonomy

| State | Definition | Heuristic Condition | Recommended Action |
|---|---|---|---|
| **Active** | Discovered/documented endpoint with verified traffic inside the window. | `source != 'traffic' AND last_seen_traffic >= cutoff` | `keep_active` |
| **Zombie** | Discovered/documented endpoint with no traffic inside the observation window. | `source != 'traffic' AND (last_seen_traffic IS NULL OR last_seen_traffic < cutoff)` | `decommission` (if `last_seen_traffic IS NULL`)<br>`restrict` (if traffic is stale) |
| **Shadow** | Undocumented endpoint observed in gateway traffic but absent from HAR/docs. | `source == 'traffic'` | `bring_up_to_date` |

### 3.2 Derived Operational Metadata

1. **Auth Reachability:**
   * `unauthenticated`: An unauthenticated client successfully accessed the endpoint (`allowed = True` with `role == 'unauthenticated'`).
   * `role_restricted`: Access rejections (`allowed = False`, 401/403) observed across roles.
   * `authenticated_only`: Requires valid authentication with no observed role violations.
2. **Business Flow Classification:**
   * Rule-based domain taxonomy mapping travel lifecycle steps:
     * `cancel`: Routes containing `/cancel`, `/void`, `/release`, `/drop`.
     * `pay`: Routes containing `/pay`, `/payments`, `/refunds`, `/transactions`, `/billing`.
     * `hold`: Routes containing `/hold`, `/reserve`, `/lock`, `/prebook`.
     * `book`: Routes containing `/bookings`, `/orders`, `/tickets`, `/passengers`, `/checkout`.
     * `search`: Routes containing `/search`, `/flights`, `/hotels`, `/availability`, `/quotes`.
     * `other`: Internal, health, and administrative routes.
3. **API Versioning & Version Notes:**
   * Extracts API version tags (`v1`, `v2`, `v3`).
   * Computes cross-version comparison notes by grouping endpoint paths by their versionless base pattern (`/api/{version}/bookings/{id}`):
     * *Example Note:* `"Legacy v1 route remains active while v2, v3 is available"`
4. **Engineering Ownership Assignment:**
   * Domain routes are automatically mapped to responsible engineering teams:
     * `/bookings/*`, `/orders/*` $\rightarrow$ `Booking & Orders Team`
     * `/pay/*`, `/refunds/*` $\rightarrow$ `Payments & Settlement Team`
     * `/agencies/*`, `/partners/*` $\rightarrow$ `Agency Partner Ops`
     * `/search/*`, `/flights/*` $\rightarrow$ `Search & Inventory Team`
     * `/users/*`, `/auth/*`, `/sessions/*` $\rightarrow$ `Identity & Access Team`
     * `/admin/*`, `/internal/*`, `/debug/*` $\rightarrow$ `Core Platform Team`
5. **Redacted Data Fields Summary:**
   * Synthesizes discovered parameters into a structured, location-grouped summary string:
     * *Example:* `body: [customer_email:string, seat_count:integer]; query: [tier:string]`

---

## 4. API Endpoints Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/targets/{id}/endpoints` | Returns full endpoint inventory including parameters, role observations, flow links, version notes, and classification actions. |
| `POST` | `/api/targets/{id}/har-import` | Ingests HAR file, normalizes routes, extracts parameter shapes, redacts sensitive values, and runs classification. |
| `POST` | `/api/targets/{id}/gateway-logs` | Ingests JSON or Common Log Format traffic records, tags with `window_days`, discovers shadow endpoints, and updates classifications. |
| `POST` | `/api/targets/{id}/classify` | Triggers on-demand classification with configurable `window_days` (default: 90). |

---

## 5. Automated Test Suite & Verification

All automated tests in `services/api/tests/test_evidence_backed_inventory.py` pass without errors.

```
Ran 8 tests in 0.439s -> OK
```

### Test Case Breakdown

| Test Method | Focus & Validation Criteria |
|---|---|
| `test_endpoint_schema_and_business_flow_inference` | Validates travel business flow mapping (`search`, `hold`, `book`, `pay`, `cancel`), API version extraction (`v1`, `v2`), and owner assignment. |
| `test_har_import_preserves_parameter_shapes_under_strict_redaction` | Imports HAR containing JWT tokens, session cookies, and user emails. Asserts that cleartext values never appear in API responses or the database, while parameter names and types are preserved. |
| `test_gateway_log_ingestion_supports_json_and_clf_formats` | Ingests both JSON and Apache CLF format records. Asserts observation window tagging (`window_days = 90`) and verified role observation creation. |
| `test_classifier_labels_active_zombie_and_shadow_accurately` | Verifies classification of 4 endpoint conditions: active with recent traffic, zombie with stale traffic, zombie never seen in traffic, and shadow seen only in traffic. |
| `test_window_boundary_edge_behavior` | Tests precision at 30-day window boundary: route at 29.9 days classified as `active`, route at 30.1 days classified as `zombie`. |
| `test_day_90_boundary_behavior` | Tests precision at 90-day window boundary: route at 89.9 days classified as `active`, route at 90.1 days classified as `zombie`. |
| `test_version_comparison_notes_generated_correctly` | Verifies generation of cross-version warning notes when legacy v1 endpoints remain live after v3 release. |
| `test_definition_of_done_e2e_scan_with_har_and_gateway_logs` | Full end-to-end Definition of Done scan: supplies HAR + Gateway logs, executes bounded scan, and validates resulting parameters, role observations, flow links, versions, owners, and classifications. |

### Overall Repository Test Suite Status

```
Ran 43 tests in 2.174s -> OK
- test_evidence_backed_inventory.py: 8/8 passed
- test_staging_readiness.py: 6/6 passed
- test_scan_orchestration.py: 11/11 passed
- test_safety_policy.py: 9/9 passed
- test_api_integration.py: 8/8 passed
- test_migrations.py: 1/1 passed (Alembic revisions 0001 through 0006)
```

Frontend application build (`apps/web`):
```
next build -> Compiled successfully, type checks and static page generation passed (4/4).
```

---

## 6. Definition of Done Compliance

* **Parameters:** Discovered parameter names, locations, and observed types are recorded in `endpoint_parameters` with zero raw sensitive values stored.
* **Role Observations:** Test account role hits and access permissions are captured in `endpoint_role_observations`.
* **Flow Links & Versioning:** Endpoints carry structured travel flow classifications (`search`, `hold`, `book`, `pay`, `cancel`) and explicit version tags (`v1`, `v2`, `v3`).
* **Traffic Ingestion & Time-Window Bounds:** Both HAR and standard access logs (JSON, CLF) are ingested with explicit observation window tagging.
* **Classification Engine:** Heuristically computes `active`, `zombie`, and `shadow` states with real owners and actionable recommendations (`keep_active`, `decommission`, `restrict`, `bring_up_to_date`), replacing static sample data.
