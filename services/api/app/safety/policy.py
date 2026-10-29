import threading
import time
from urllib.parse import urlsplit

from sqlalchemy.exc import IntegrityError
from sqlalchemy import select

from app.models import SafetyControl, Target
from app.settings import settings


class ScopeRejected(ValueError):
    pass


class KillSwitchEngaged(RuntimeError):
    """Phase 0.2: the single override that halts every agent instantly."""


class RateLimited(RuntimeError):
    """Phase 0.2: the per-endpoint token bucket has no tokens left right now."""


class TokenBucket:
    """A small per-key token bucket used as the Phase 0.2 rate limiter.

    One bucket is kept per (target, path) key so a single endpoint cannot be hammered
    even when the overall per-scan request budget has room left. Thread-safe because the
    orchestrator may run concurrently with the API process issuing other requests.
    """

    def __init__(self, capacity: int = 3, refill_per_second: float = 0.5) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_refill_monotonic)

    def allow(self, key: str) -> bool:
        with self._lock:
            now = time.monotonic()
            tokens, last = self._buckets.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_second)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


# One process-wide limiter: a token-bucket per endpoint, backed by the same global cap the
# orchestrator's semaphore already enforces across scans.
endpoint_rate_limiter = TokenBucket(capacity=3, refill_per_second=0.5)


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


def supports_demo_executor(target: Target) -> bool:
    """Only the deliberately vulnerable, in-network fixture supports active checks."""
    try:
        return target.environment == "local-demo" and validate_target_url(target.base_url) == "http://demo-app:8080"
    except ScopeRejected:
        return False


def assert_request_scope(target: Target, request_url: str) -> None:
    """Revalidate target configuration and each outgoing request at execution time."""
    base_origin = validate_target_url(target.base_url)
    request_origin = origin(request_url)
    if request_origin != base_origin or request_origin not in allowed_origins():
        raise ScopeRejected("Request URL does not match the authorized target origin.")


def assert_rate_limit(target: Target, path: str) -> None:
    """Phase 0.2 rate limiter: a token-bucket per endpoint, checked before every request."""
    key = f"{target.id}:{path}"
    if not endpoint_rate_limiter.allow(key):
        raise RateLimited(f"Rate limit exceeded for {path}; back off before retrying.")


def get_safety_control(db) -> SafetyControl:
    """Fetch (or lazily create) the single safety-control row holding the kill switch."""
    control = db.get(SafetyControl, 1)
    if control is None:
        control = SafetyControl(id=1, kill_switch_engaged=False, reason="")
        db.add(control)
        try:
            db.commit()
        except IntegrityError:
            # Another API request created the singleton row at the same time.
            db.rollback()
            control = db.get(SafetyControl, 1)
        db.refresh(control)
    return control


def assert_kill_switch_clear(db) -> None:
    """Phase 0.2 kill switch: a single override that halts all agents instantly."""
    control = get_safety_control(db)
    if control.kill_switch_engaged:
        raise KillSwitchEngaged(f"Kill switch is engaged: {control.reason or 'no reason given'}.")
