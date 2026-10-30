"""OpenAPI 3.0 and Swagger 2.0 validation, normalization, and inventory ingestion."""
import json
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml
from yaml.events import AliasEvent
from openapi_spec_validator import OpenAPIV2SpecValidator, OpenAPIV30SpecValidator, validate
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.inventory.service import infer_api_version, infer_business_flow, infer_likely_owner, normalize_endpoint_path
from app.models import Endpoint, EndpointParameter, Target
from app.safety.policy import assert_request_scope, validate_target_url

MAX_SPEC_BYTES = 5 * 1024 * 1024
MAX_PATHS = 5000
MAX_PARAMETERS_PER_OPERATION = 250
MAX_YAML_ALIASES = 100
SUPPORTED_METHODS = {"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"}


class OpenAPIImportError(ValueError):
    """Invalid, unsupported, unsafe, or overlarge API specification."""


class _BoundedSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that bounds alias processing for untrusted uploads."""

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self.alias_count = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            self.alias_count += 1
            if self.alias_count > MAX_YAML_ALIASES:
                raise yaml.YAMLError("YAML alias limit exceeded.")
        return super().compose_node(parent, index)


def _walk(value: Any) -> Iterator[Any]:
    seen: set[int] = set()
    yield from _walk_once(value, seen)


def _walk_once(value: Any, seen: set[int]) -> Iterator[Any]:
    if isinstance(value, dict):
        if id(value) in seen:
            return
        seen.add(id(value))
        yield value
        for child in value.values():
            yield from _walk_once(child, seen)
    elif isinstance(value, list):
        if id(value) in seen:
            return
        seen.add(id(value))
        for child in value:
            yield from _walk_once(child, seen)


def _reject_external_refs(spec: dict[str, Any]) -> None:
    for node in _walk(spec):
        ref = node.get("$ref")
        if ref is not None and (not isinstance(ref, str) or not ref.startswith("#/")):
            raise OpenAPIImportError("External $ref values are not allowed; inline or use local document references.")


def _resolve_local(spec: dict[str, Any], value: Any) -> Any:
    seen: set[str] = set()
    while isinstance(value, dict) and "$ref" in value:
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise OpenAPIImportError("Only local JSON Pointer references are supported.")
        if ref in seen or len(seen) >= 32:
            raise OpenAPIImportError("Circular or overly deep local reference chain.")
        seen.add(ref)
        current: Any = spec
        for token in ref[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or token not in current:
                raise OpenAPIImportError("Specification contains a broken local reference.")
            current = current[token]
        value = current
    return value


def parse_openapi_document(content: bytes | str, filename: str = "") -> dict[str, Any]:
    """Safely load and validate a JSON/YAML OpenAPI 3.0 or Swagger 2.0 document."""
    if isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        raw = content
    if len(raw) > MAX_SPEC_BYTES:
        raise OpenAPIImportError("Specification exceeds the 5 MB size limit.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise OpenAPIImportError("Specification must be UTF-8 encoded.") from exc

    extension = (filename.rsplit(".", 1)[-1].lower() if "." in filename else "")
    try:
        if extension == "json" or text.lstrip().startswith(("{", "[")):
            document = json.loads(text)
        else:
            document = yaml.load(text, Loader=_BoundedSafeLoader)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise OpenAPIImportError("Specification is not valid JSON or YAML.") from exc
    if not isinstance(document, dict):
        raise OpenAPIImportError("Specification root must be a JSON/YAML object.")

    swagger = document.get("swagger")
    openapi = document.get("openapi")
    if swagger == "2.0":
        validator = OpenAPIV2SpecValidator
    elif isinstance(openapi, str) and openapi.startswith("3.0."):
        validator = OpenAPIV30SpecValidator
    else:
        raise OpenAPIImportError("Only Swagger 2.0 and OpenAPI 3.0 specifications are supported.")

    _reject_external_refs(document)
    try:
        validate(document, cls=validator)
    except Exception as exc:
        # Validator errors may quote source fragments; keep API errors bounded and non-sensitive.
        raise OpenAPIImportError("Specification failed OpenAPI/Swagger validation.") from exc
    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise OpenAPIImportError("Specification must define at least one path.")
    if len(paths) > MAX_PATHS:
        raise OpenAPIImportError(f"Specification exceeds the {MAX_PATHS} path limit.")
    return document


def _normalize_spec_path(raw_path: str) -> str:
    if not isinstance(raw_path, str) or not raw_path.startswith("/"):
        raise OpenAPIImportError("OpenAPI paths must be absolute path templates beginning with '/'.")
    path = raw_path.split("?", 1)[0].split("#", 1)[0]
    placeholders: list[str] = []

    def protect(match: re.Match[str]) -> str:
        placeholders.append(match.group(1))
        return f"__OPENAPI_PATH_PARAM_{len(placeholders) - 1}__"

    protected = re.sub(r"\{([^{}]+)\}", protect, path)
    if "{" in protected or "}" in protected:
        raise OpenAPIImportError("Path template contains malformed parameter braces.")
    # Normalize static segments with the inventory rules while keeping the
    # specification's named placeholders intact (the general inventory
    # normalizer intentionally collapses resource IDs to {id}).
    normalized_segments = []
    for segment in protected.split("/"):
        if not segment:
            continue
        if re.fullmatch(r"__OPENAPI_PATH_PARAM_\d+__", segment):
            normalized_segments.append(segment)
        else:
            normalized_segments.append(normalize_endpoint_path("/" + segment).strip("/"))
    normalized = "/" + "/".join(normalized_segments)
    for index, name in enumerate(placeholders):
        normalized = normalized.replace(f"__OPENAPI_PATH_PARAM_{index}__", "{" + name + "}")
    if len(normalized) > 1000:
        raise OpenAPIImportError("Normalized path exceeds the inventory path limit.")
    return normalized


def _schema_type(schema: Any, spec: dict[str, Any], depth: int = 0) -> str:
    schema = _resolve_local(spec, schema)
    if not isinstance(schema, dict) or depth > 10:
        return "string"
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((item for item in schema_type if item != "null"), "string")
    if schema_type == "integer":
        return "integer"
    if schema_type == "number":
        return "number"
    if schema_type == "boolean":
        return "boolean"
    if schema_type == "array":
        return "array"
    if schema_type == "object" or "properties" in schema:
        return "object"
    for union_key in ("oneOf", "anyOf", "allOf"):
        variants = schema.get(union_key)
        if isinstance(variants, list) and variants:
            inferred = [_schema_type(item, spec, depth + 1) for item in variants]
            return inferred[0] if len(set(inferred)) == 1 else "object"
    return "string"


def _schema_body_parameters(schema: Any, spec: dict[str, Any], prefix: str = "", depth: int = 0) -> list[dict[str, str]]:
    schema = _resolve_local(spec, schema)
    if not isinstance(schema, dict) or depth > 4:
        return []
    properties = schema.get("properties")
    result: list[dict[str, str]] = []
    if isinstance(properties, dict):
        for name, child in properties.items():
            child = _resolve_local(spec, child)
            clean_name = str(name).strip()[:120]
            if not clean_name:
                continue
            qualified = f"{prefix}.{clean_name}" if prefix else clean_name
            result.append({"name": qualified[:160], "location": "body", "observed_type": _schema_type(child, spec)})
            if isinstance(child, dict) and (child.get("type") == "object" or "properties" in child):
                result.extend(_schema_body_parameters(child, spec, qualified, depth + 1))
            elif isinstance(child, dict) and child.get("type") == "array":
                items = _resolve_local(spec, child.get("items", {}))
                if isinstance(items, dict) and (items.get("type") == "object" or "properties" in items):
                    result.extend(_schema_body_parameters(items, spec, qualified, depth + 1))
    elif schema.get("type") in {"object", "array"}:
        result.append({"name": prefix or "body", "location": "body", "observed_type": _schema_type(schema, spec)})
    return result


def _request_body_parameters(operation: dict[str, Any], spec: dict[str, Any]) -> list[dict[str, str]]:
    body = _resolve_local(spec, operation.get("requestBody", {}))
    if not isinstance(body, dict):
        return []
    content = body.get("content", {})
    if not isinstance(content, dict) or not content:
        return []
    media_types = sorted(content, key=lambda media: (media.lower() != "application/json", "json" not in media.lower()))
    schema: Any = {}
    for media_type in media_types:
        media = content.get(media_type)
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            schema = media["schema"]
            break
    fields = _schema_body_parameters(schema, spec)
    if not fields:
        fields = [{"name": "body", "location": "body", "observed_type": _schema_type(schema, spec)}]
    return fields


def _parameter_schema(parameter: dict[str, Any], spec: dict[str, Any], swagger: bool) -> Any:
    if isinstance(parameter.get("schema"), dict):
        return parameter["schema"]
    if isinstance(parameter.get("content"), dict):
        media = next(iter(parameter["content"].values()), {})
        return media.get("schema", {}) if isinstance(media, dict) else {}
    if swagger:
        schema = {key: parameter[key] for key in ("type", "items", "format", "properties") if key in parameter}
        return schema
    return {}


def _operation_parameters(path_item: dict[str, Any], operation: dict[str, Any], spec: dict[str, Any], swagger: bool) -> list[dict[str, str]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for source in (path_item.get("parameters", []), operation.get("parameters", [])):
        if not isinstance(source, list):
            continue
        for item in source:
            item = _resolve_local(spec, item)
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            location = str(item.get("in", "")).lower()
            if not name or location not in {"path", "query", "header", "cookie", "formdata", "body"}:
                continue
            if location in {"body", "formdata"}:
                schema = item.get("schema", item) if location == "body" else item
                body_items = _schema_body_parameters(schema, spec)
                if body_items:
                    for body_item in body_items:
                        merged[(body_item["name"].lower(), "body")] = body_item
                else:
                    observed = _schema_type(schema, spec) if location == "body" else _schema_type(item, spec)
                    merged[(name.lower(), "body")] = {"name": name[:160], "location": "body", "observed_type": observed}
                continue
            if location == "formdata":
                location = "body"
            schema = _parameter_schema(item, spec, swagger)
            observed = _schema_type(schema, spec)
            merged[(name.lower(), location)] = {"name": name[:160], "location": location, "observed_type": observed}
    if not swagger:
        for body_item in _request_body_parameters(operation, spec):
            merged[(body_item["name"].lower(), "body")] = body_item
    if len(merged) > MAX_PARAMETERS_PER_OPERATION:
        raise OpenAPIImportError("An operation exceeds the parameter limit.")
    return list(merged.values())


def _security_schemes(spec: dict[str, Any], swagger: bool) -> dict[str, dict[str, Any]]:
    container = spec.get("securityDefinitions", {}) if swagger else spec.get("components", {}).get("securitySchemes", {})
    return container if isinstance(container, dict) else {}


def _operation_security(spec: dict[str, Any], operation: dict[str, Any]) -> list[dict[str, str]]:
    swagger = spec.get("swagger") == "2.0"
    schemes = _security_schemes(spec, swagger)
    requirements = operation.get("security", spec.get("security", []))
    found: dict[tuple[str, str], dict[str, str]] = {}
    if isinstance(requirements, list):
        for requirement in requirements:
            if not isinstance(requirement, dict):
                continue
            for scheme_name in requirement:
                scheme = schemes.get(scheme_name)
                if not isinstance(scheme, dict):
                    continue
                scheme_type = str(scheme.get("type", "")).lower()
                if scheme_type == "apikey":
                    name = str(scheme.get("name", ""))[:160]
                    location = str(scheme.get("in", "header")).lower()
                else:
                    name, location = "Authorization", "header"
                if name and location in {"header", "query", "cookie"}:
                    found[(name.lower(), location)] = {"name": name, "location": location, "observed_type": "string"}
    return list(found.values())


def _scheme_summary(spec: dict[str, Any], swagger: bool) -> list[dict[str, str]]:
    summary = []
    for name, scheme in _security_schemes(spec, swagger).items():
        if not isinstance(scheme, dict):
            continue
        item = {"name": str(name)[:120], "type": str(scheme.get("type", "unknown"))[:40]}
        if scheme.get("type", "").lower() == "apikey":
            item["parameter_name"] = str(scheme.get("name", ""))[:160]
            item["location"] = str(scheme.get("in", ""))[:40]
        summary.append(item)
    return summary


def iter_spec_endpoints(spec: dict[str, Any]) -> Iterator[dict[str, Any]]:
    swagger = spec.get("swagger") == "2.0"
    paths = spec.get("paths", {})
    for raw_path, raw_item in paths.items():
        path_item = _resolve_local(spec, raw_item)
        if not isinstance(path_item, dict):
            continue
        effective_path = raw_path
        if swagger:
            base_path = spec.get("basePath", "")
            if isinstance(base_path, str) and base_path not in {"", "/"}:
                effective_path = base_path.rstrip("/") + "/" + raw_path.lstrip("/")
        normalized_path = _normalize_spec_path(effective_path)
        for raw_method, raw_operation in path_item.items():
            method = str(raw_method).upper()
            if method not in SUPPORTED_METHODS:
                continue
            operation = _resolve_local(spec, raw_operation)
            if not isinstance(operation, dict):
                continue
            parameters = _operation_parameters(path_item, operation, spec, swagger)
            for name in re.findall(r"\{([^{}]+)\}", effective_path):
                key = (name.lower(), "path")
                if not any((item["name"].lower(), item["location"]) == key for item in parameters):
                    parameters.append({"name": name[:160], "location": "path", "observed_type": "string"})
            for item in _operation_security(spec, operation):
                key = (item["name"].lower(), item["location"])
                if not any((p["name"].lower(), p["location"]) == key for p in parameters):
                    parameters.append(item)
            security = operation.get("security", spec.get("security", []))
            authenticated = bool(security)
            yield {"method": method, "path": normalized_path, "parameters": parameters,
                   "auth_required": authenticated,
                   "auth_reachability": "authenticated_only" if authenticated else "unauthenticated"}


def ingest_openapi_spec(db: Session, target_id: int, spec: dict[str, Any]) -> dict[str, Any]:
    """Upsert documented routes/parameters. Classification is intentionally a separate caller step."""
    target = db.get(Target, target_id)
    if target is None:
        raise LookupError("Target not found.")
    validate_target_url(target.base_url)
    swagger = spec.get("swagger") == "2.0"
    schemes = _scheme_summary(spec, swagger)
    inserted = updated = parameter_count = 0
    endpoints_count = 0
    for item in iter_spec_endpoints(spec):
        endpoints_count += 1
        endpoint = db.execute(select(Endpoint).where(
            Endpoint.target_id == target_id, Endpoint.method == item["method"], Endpoint.path == item["path"]
        )).scalars().first()
        owner = infer_likely_owner(item["path"])
        if endpoint is None:
            endpoint = Endpoint(target_id=target_id, method=item["method"], path=item["path"],
                classification="active", sensitivity="unknown", last_seen=datetime.now(timezone.utc),
                source="openapi", business_flow=infer_business_flow(item["path"], item["method"]),
                api_version=infer_api_version(item["path"]), owner=owner, likely_owner=owner,
                auth_required=item["auth_required"], auth_reachability=item["auth_reachability"],
                recommended_action="keep_active")
            db.add(endpoint)
            db.flush()
            inserted += 1
        else:
            endpoint.source = "openapi"
            endpoint.likely_owner = owner
            if endpoint.owner in {None, "", "Unassigned"}:
                endpoint.owner = owner
            endpoint.business_flow = endpoint.business_flow or infer_business_flow(item["path"], item["method"])
            endpoint.api_version = endpoint.api_version or infer_api_version(item["path"])
            endpoint.auth_required = item["auth_required"]
            endpoint.auth_reachability = item["auth_reachability"]
            updated += 1
        for parameter in item["parameters"]:
            existing = db.execute(select(EndpointParameter).where(
                EndpointParameter.endpoint_id == endpoint.id,
                EndpointParameter.name == parameter["name"],
                EndpointParameter.location == parameter["location"],
            )).scalars().first()
            if existing:
                existing.observed_type = parameter["observed_type"]
            else:
                db.add(EndpointParameter(endpoint_id=endpoint.id, **parameter))
                parameter_count += 1
    db.flush()
    return {"target_id": target_id, "discovered": endpoints_count, "inserted": inserted,
            "updated": updated, "parameters_added": parameter_count, "security_schemes": schemes}


def fetch_openapi_spec(url: str, target: Target, *, max_bytes: int = MAX_SPEC_BYTES) -> tuple[bytes, str]:
    """Fetch a spec only from the target's allowlisted origin; redirects are never followed."""
    validate_target_url(target.base_url)
    assert_request_scope(target, url)
    parsed = urlsplit(url)
    filename = parsed.path.rsplit("/", 1)[-1] or "openapi.yaml"
    collected = bytearray()
    try:
        with httpx.Client(timeout=httpx.Timeout(10.0, connect=3.0), follow_redirects=False, trust_env=False) as client:
            with client.stream("GET", url, headers={"Accept": "application/json, application/yaml, text/yaml, */*"}) as response:
                response.raise_for_status()
                declared = response.headers.get("content-length")
                if declared and int(declared) > max_bytes:
                    raise OpenAPIImportError("Specification exceeds the 5 MB size limit.")
                for chunk in response.iter_bytes():
                    collected.extend(chunk)
                    if len(collected) > max_bytes:
                        raise OpenAPIImportError("Specification exceeds the 5 MB size limit.")
    except OpenAPIImportError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise OpenAPIImportError("Unable to fetch the specification from the authorized target origin.") from exc
    return bytes(collected), filename
