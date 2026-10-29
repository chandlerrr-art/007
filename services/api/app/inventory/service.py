import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Endpoint, EndpointParameter, EndpointRoleObservation, Target, TrafficLogEntry


# Static segments that should not be replaced by dynamic ID markers
HAR_STATIC_RESOURCE_SEGMENTS = {
    "current", "me", "search", "all", "recent", "active", "quote",
    "history", "summary", "status", "health", "metrics", "ready",
}

# Common Log Format (CLF) / Combined Log Format regex
# e.g.: 192.168.1.1 - travel_agent [15/Sep/2026:12:00:00 +0000] "GET /api/v1/bookings/2002 HTTP/1.1" 200 1234
CLF_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>[^\s"]+)(?:\s+HTTP/[0-9.]+)?\"\s+(?P<status>\d{3})'
)


def normalize_endpoint_path(raw_path: str) -> str:
    """Normalize dynamic IDs and remove query strings/fragments for clean endpoint paths."""
    if not raw_path:
        return "/"
    path = unquote(raw_path).split("?", 1)[0].split("#", 1)[0]
    path = re.sub(r"[\x00-\x1f\x7f]", "", path)
    # Replace UUIDs
    path = re.sub(r"(?i)(?<=[/])[0-9a-f]{8}-[0-9a-f-]{27,}", "{id}", path)
    # Replace numeric segments
    path = re.sub(r"(?<=/)\d+(?=/|$)", "{id}", path)
    # Replace email addresses
    path = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "{id}", path)
    # Replace phone numbers
    path = re.sub(r"(?<!\w)\+?\d[\d ().-]{7,}\d(?!\w)", "{id}", path)
    # Token or secret URL paths
    path = re.sub(r"(?i)(/(?:access[_-]?tokens?|tokens?|sessions?|secrets?|api[_-]?keys?)/)[^/]+", r"\1{redacted}", path)

    def normalize_resource(match: re.Match[str]) -> str:
        if match.group(2).casefold() in HAR_STATIC_RESOURCE_SEGMENTS:
            return match.group(0)
        return f"{match.group(1)}{{id}}"

    return re.sub(r"(?i)(/(?:bookings?|users?|agencies|orders?|travelers?|refunds?|flights?|hotels?)/)([^/]+)", normalize_resource, path)


def infer_business_flow(path: str, method: str) -> str | None:
    """Classify the endpoint into a travel business flow: search, hold, book, pay, cancel."""
    p = path.lower()
    # Lifecycle actions take precedence over noun resources
    if any(k in p for k in ["/cancel", "/void", "/release", "/drop"]):
        return "cancel"
    if any(k in p for k in ["/pay", "/payments", "/refunds", "/transactions", "/charges", "/billing"]):
        return "pay"
    if any(k in p for k in ["/hold", "/reserve", "/lock", "/prebook"]):
        return "hold"
    if any(k in p for k in ["/bookings", "/orders", "/tickets", "/passengers", "/checkout"]):
        return "book"
    if any(k in p for k in ["/search", "/flights", "/hotels", "/availability", "/quotes", "/explore", "/catalog"]):
        return "search"
    return "other"


def infer_api_version(path: str) -> str:
    """Extract API version tag (v1, v2, v3, etc.) from the endpoint path."""
    match = re.search(r"(?i)/(v\d+)(?:/|$)", path)
    if match:
        return match.group(1).lower()
    return "v1"


def infer_likely_owner(path: str) -> str:
    """Determine the likely engineering owner team based on route domain."""
    p = path.lower()
    if any(k in p for k in ["/bookings", "/orders", "/tickets", "/passengers"]):
        return "Booking & Orders Team"
    if any(k in p for k in ["/pay", "/payments", "/refunds", "/billing"]):
        return "Payments & Settlement Team"
    if any(k in p for k in ["/agencies", "/partners", "/commissions"]):
        return "Agency Partner Ops"
    if any(k in p for k in ["/search", "/flights", "/hotels", "/availability"]):
        return "Search & Inventory Team"
    if any(k in p for k in ["/users", "/auth", "/sessions", "/roles"]):
        return "Identity & Access Team"
    if any(k in p for k in ["/admin", "/internal", "/debug", "/health"]):
        return "Core Platform Team"
    return "Core Application Team"


def infer_type(val: Any) -> str:
    """Infer data type without saving the raw value."""
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "integer"
    if isinstance(val, float):
        return "number"
    if isinstance(val, dict):
        return "object"
    if isinstance(val, list):
        return "array"
    if isinstance(val, str):
        cleaned = val.strip()
        if cleaned.isdigit():
            return "integer"
        try:
            float(cleaned)
            return "number"
        except ValueError:
            pass
        if cleaned.lower() in ("true", "false"):
            return "boolean"
        return "string"
    return "string"


def extract_parameters_from_har_entry(entry: dict[str, Any]) -> list[dict[str, str]]:
    """Extract parameter keys and types from HAR entry under strict redaction rules.
    
    Raw values (PII, tokens, passwords) are completely discarded. Only names,
    locations, and observed data types are preserved.
    """
    params: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add_param(name: str, location: str, observed_type: str) -> None:
        name_clean = name.strip()[:160]
        if not name_clean:
            return
        key = (name_clean.lower(), location)
        if key not in seen:
            seen.add(key)
            params.append({"name": name_clean, "location": location, "observed_type": observed_type})

    request = entry.get("request", {})
    raw_url = request.get("url", "")
    url_parts = urlsplit(raw_url)

    # 1. Path parameters from URL path
    for match in re.findall(r"\{([^}]+)\}", normalize_endpoint_path(url_parts.path)):
        add_param(match, "path", "integer" if "id" in match.lower() else "string")

    # 2. Query parameters (from queryString array and raw URL query string)
    for q in request.get("queryString", []):
        if isinstance(q, dict) and "name" in q:
            add_param(q["name"], "query", infer_type(q.get("value")))

    if url_parts.query:
        for q_name, q_vals in parse_qs(url_parts.query).items():
            add_param(q_name, "query", infer_type(q_vals[0] if q_vals else ""))

    # 3. Headers (names only, strict redaction of header values)
    for h in request.get("headers", []):
        if isinstance(h, dict) and "name" in h:
            h_name = h["name"]
            # Exclude standard transport headers from parameter pollution
            if h_name.lower() not in {"host", "connection", "accept-encoding", "content-length"}:
                add_param(h_name, "header", "string")

    # 4. Cookies (names only, strict redaction of cookie values)
    for c in request.get("cookies", []):
        if isinstance(c, dict) and "name" in c:
            add_param(c["name"], "cookie", "string")

    # 5. Body / PostData shape (names and types only)
    post_data = request.get("postData", {})
    mime_type = post_data.get("mimeType", "")
    body_text = post_data.get("text", "")

    if "application/json" in mime_type and body_text:
        try:
            parsed = json.loads(body_text)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    add_param(str(k), "body", infer_type(v))
            elif isinstance(parsed, list):
                elem_type = infer_type(parsed[0]) if parsed else "string"
                add_param("items", "body", f"array[{elem_type}]")
        except Exception:
            pass
    elif ("application/x-www-form-urlencoded" in mime_type or "multipart/form-data" in mime_type) and body_text:
        try:
            parsed_qs = parse_qs(body_text)
            for k, v in parsed_qs.items():
                add_param(str(k), "body", infer_type(v[0] if v else ""))
        except Exception:
            pass

    return params


def parse_gateway_log_entry(raw_line: str) -> dict[str, Any] | None:
    """Parse a single gateway or access log entry in JSON, CLF, or key-value format."""
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None

    # Format 1: JSON line
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            method = str(data.get("method") or data.get("http_method") or "GET").upper()
            url_str = str(data.get("path") or data.get("url") or data.get("uri") or "/")
            path = urlsplit(url_str).path
            status_code = int(data.get("status") or data.get("status_code") or data.get("response_code") or 200)
            
            ts_val = data.get("timestamp") or data.get("time") or data.get("@timestamp")
            if ts_val:
                if isinstance(ts_val, (int, float)):
                    timestamp = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                else:
                    try:
                        timestamp = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
                    except Exception:
                        timestamp = datetime.now(timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)

            role = data.get("role") or data.get("user_role") or data.get("user")
            return {
                "method": method[:12],
                "path": path,
                "status_code": status_code,
                "timestamp": timestamp,
                "role": str(role)[:80] if role else None,
            }
        except Exception:
            pass

    # Format 2: Common Log Format (CLF)
    clf_match = CLF_REGEX.match(line)
    if clf_match:
        try:
            groups = clf_match.groupdict()
            method = groups["method"].upper()
            path = urlsplit(groups["url"]).path
            status_code = int(groups["status"])
            time_str = groups["time"]  # e.g. 15/Sep/2026:12:00:00 +0000
            try:
                timestamp = datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
            except Exception:
                timestamp = datetime.now(timezone.utc)
            user = groups.get("user")
            role = user if user and user != "-" else None
            return {
                "method": method[:12],
                "path": path,
                "status_code": status_code,
                "timestamp": timestamp,
                "role": role,
            }
        except Exception:
            pass

    return None


def ingest_gateway_logs(
    db: Session,
    target_id: int,
    raw_logs: str,
    window_days: int = 90,
    source: str = "gateway_access_log",
) -> dict[str, int]:
    """Ingest gateway/access logs with time-window tagging and update traffic state."""
    target = db.get(Target, target_id)
    if not target:
        raise ValueError("Target not found.")

    lines = raw_logs.strip().splitlines()
    ingested_count = 0
    endpoints_created = 0

    for line in lines:
        parsed = parse_gateway_log_entry(line)
        if not parsed:
            continue

        norm_path = normalize_endpoint_path(parsed["path"])
        method = parsed["method"]
        ts = parsed["timestamp"]
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        status = parsed["status_code"]
        role = parsed["role"]

        # 1. Match or create Endpoint
        endpoint = db.execute(
            select(Endpoint).where(
                Endpoint.target_id == target_id,
                Endpoint.method == method,
                Endpoint.path == norm_path,
            )
        ).scalars().first()

        if not endpoint:
            # Undocumented route observed in traffic -> Candidate Shadow API
            endpoint = Endpoint(
                target_id=target_id,
                method=method,
                path=norm_path,
                classification="shadow",
                sensitivity="unknown",
                last_seen=ts,
                source="traffic",
                business_flow=infer_business_flow(norm_path, method),
                api_version=infer_api_version(norm_path),
                owner=infer_likely_owner(norm_path),
                likely_owner=infer_likely_owner(norm_path),
                auth_required=True,
                auth_reachability="authenticated_only" if status in {401, 403} else "unauthenticated" if status == 200 and not role else "role_restricted",
                recommended_action="bring_up_to_date",
            )
            db.add(endpoint)
            db.flush()
            endpoints_created += 1

        # 2. Update traffic timestamps and hit counts
        first_traffic = endpoint.first_seen_traffic
        if first_traffic is not None and first_traffic.tzinfo is None:
            first_traffic = first_traffic.replace(tzinfo=timezone.utc)
        last_traffic = endpoint.last_seen_traffic
        if last_traffic is not None and last_traffic.tzinfo is None:
            last_traffic = last_traffic.replace(tzinfo=timezone.utc)

        if first_traffic is None or ts < first_traffic:
            endpoint.first_seen_traffic = ts
        if last_traffic is None or ts > last_traffic:
            endpoint.last_seen_traffic = ts
            endpoint.last_seen = ts

        endpoint.traffic_hit_count += 1

        # 3. Record Role / Access observation if role is present
        if role:
            allowed = status < 400
            db.add(EndpointRoleObservation(
                endpoint_id=endpoint.id,
                role=role,
                allowed=allowed,
                status_code=status,
                last_observed=ts,
            ))

        # 4. Save traffic log entry tagged with its observation window
        db.add(TrafficLogEntry(
            target_id=target_id,
            endpoint_id=endpoint.id,
            method=method,
            path=norm_path,
            status_code=status,
            timestamp=ts,
            window_days=window_days,
            role=role,
            source=source,
        ))
        ingested_count += 1

    db.commit()
    return {"ingested_entries": ingested_count, "endpoints_discovered": endpoints_created}


def classify_endpoints(db: Session, target_id: int, window_days: int = 90) -> list[Endpoint]:
    """Phase 1 Classifier: Computes real active, zombie, and shadow status.
    
    Rules:
    - Routes seen in traffic but NEVER in discovered/documented set (source == 'traffic') -> 'shadow'
      Recommended action: 'bring_up_to_date'
    - Routes in discovered/documented set but with NO real traffic in the window -> 'zombie'
      Recommended action: 'decommission' (if no traffic ever) or 'restrict' (if stale)
    - Everything else -> 'active'
      Recommended action: 'keep_active'
      
    Also computes:
    - Version notes (e.g., legacy v1 active after v2/v3 shipped)
    - Redacted summary of observed data fields from discovered parameters
    - Likely owner and auth reachability
    """
    endpoints = db.execute(
        select(Endpoint).where(Endpoint.target_id == target_id).order_by(Endpoint.method, Endpoint.path)
    ).scalars().all()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=window_days)

    # Map paths by base resource without version for version-comparison notes
    # e.g., /api/v1/bookings -> base /api/{version}/bookings
    version_groups: dict[str, list[Endpoint]] = {}
    for ep in endpoints:
        base_pattern = re.sub(r"(?i)/v\d+/", "/{version}/", ep.path)
        version_groups.setdefault(base_pattern, []).append(ep)

    for ep in endpoints:
        # Load parameters for data fields summary
        params = db.execute(
            select(EndpointParameter).where(EndpointParameter.endpoint_id == ep.id).order_by(EndpointParameter.location, EndpointParameter.name)
        ).scalars().all()

        summary_parts = []
        by_loc: dict[str, list[str]] = {}
        for p in params:
            by_loc.setdefault(p.location, []).append(f"{p.name}:{p.observed_type}")
        for loc, items in sorted(by_loc.items()):
            summary_parts.append(f"{loc}: [{', '.join(items)}]")
        ep.data_fields_summary = "; ".join(summary_parts) if summary_parts else "No parameters observed"

        # Check role observations for auth reachability
        role_obs = db.execute(
            select(EndpointRoleObservation).where(EndpointRoleObservation.endpoint_id == ep.id)
        ).scalars().all()
        if role_obs:
            has_allowed_unauth = any(r.allowed for r in role_obs if r.role == "unauthenticated")
            has_denied = any(not r.allowed for r in role_obs)
            if has_allowed_unauth:
                ep.auth_reachability = "unauthenticated"
                ep.auth_required = False
            elif has_denied:
                ep.auth_reachability = "role_restricted"
                ep.auth_required = True
            else:
                ep.auth_reachability = "authenticated_only"
                ep.auth_required = True

        # Assign likely owner and business flow
        ep.likely_owner = infer_likely_owner(ep.path)
        if ep.owner in ("Unassigned", "", None):
            ep.owner = ep.likely_owner
        if not ep.business_flow:
            ep.business_flow = infer_business_flow(ep.path, ep.method)

        # Version comparison notes
        base_pattern = re.sub(r"(?i)/v\d+/", "/{version}/", ep.path)
        siblings = version_groups.get(base_pattern, [])
        versions_present = {s.api_version for s in siblings if s.api_version}
        if ep.api_version == "v1" and (("v2" in versions_present) or ("v3" in versions_present)):
            ep.version_notes = f"Legacy {ep.api_version} route remains active while {', '.join(sorted(versions_present - {'v1'}))} is available"
        else:
            ep.version_notes = f"Current {ep.api_version} release"

        # --- Active / Zombie / Shadow Classification ---
        last_traffic = ep.last_seen_traffic
        if last_traffic is not None and last_traffic.tzinfo is None:
            last_traffic = last_traffic.replace(tzinfo=timezone.utc)

        has_recent_traffic = (last_traffic is not None) and (last_traffic >= cutoff)

        if ep.source == "traffic":
            # Discovered only via traffic, not documented or imported
            ep.classification = "shadow"
            ep.recommended_action = "bring_up_to_date"
        elif not has_recent_traffic:
            # Documented/discovered in HAR/spec, but no legitimate traffic in the window
            ep.classification = "zombie"
            if last_traffic is None:
                ep.recommended_action = "decommission"
            else:
                ep.recommended_action = "restrict"
        else:
            # Documented and active in the traffic window
            ep.classification = "active"
            ep.recommended_action = "keep_active"

    db.commit()
    return endpoints
