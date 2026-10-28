from urllib.parse import urlsplit

from app.models import Target
from app.settings import settings


class ScopeRejected(ValueError):
    pass


def origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ScopeRejected("Target must be an HTTP(S) URL without embedded credentials.")
    if parsed.query or parsed.fragment:
        raise ScopeRejected("Target base URL cannot contain a query or fragment.")
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    suffix = f":{port}" if port and port != default_port else ""
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{suffix}"


def allowed_origins() -> set[str]:
    return {origin(item.strip()) for item in settings.allowed_target_origins.split(",") if item.strip()}


def validate_target_url(url: str) -> str:
    target_origin = origin(url)
    if target_origin not in allowed_origins():
        raise ScopeRejected(f"Target origin {target_origin} is not in the configured allowlist.")
    return target_origin


def assert_request_scope(target: Target, request_url: str) -> None:
    """Revalidate target configuration and each outgoing request at execution time."""
    base_origin = validate_target_url(target.base_url)
    request_origin = origin(request_url)
    if request_origin != base_origin or request_origin not in allowed_origins():
        raise ScopeRejected("Request URL does not match the authorized target origin.")
