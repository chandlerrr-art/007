"""Asynchronous signed event delivery for Slack, Teams, and custom HTTP hooks."""
import asyncio
import hashlib
import hmac
import ipaddress
import json
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.encryption import EncryptedEnvelope, EncryptionError, get_encryption_service
from app.models import WebhookSubscription
from app.safety.credentials import decrypt_secret, register_secret_for_redaction


class WebhookDeliveryError(RuntimeError):
    pass


def signature_for(secret: str, body: bytes) -> str:
    """Return the canonical X-007-Signature value."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def validate_webhook_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise WebhookDeliveryError("Webhook URL must be an HTTPS URL without embedded credentials.")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith((".localhost", ".local", ".internal")):
        raise WebhookDeliveryError("Webhook URL points to a non-public host.")
    try:
        addresses = {ipaddress.ip_address(hostname)}
    except ValueError:
        try:
            addresses = {ipaddress.ip_address(result[4][0]) for result in socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise WebhookDeliveryError("Webhook host could not be resolved.") from exc
    if not addresses or any(not addr.is_global for addr in addresses):
        raise WebhookDeliveryError("Webhook URL must resolve only to public IP addresses.")


def _payload_for(url: str, envelope: dict) -> dict:
    host = (urlsplit(url).hostname or "").lower()
    if host.endswith("hooks.slack.com"):
        return {"text": f"007 Security Scanner: {envelope['event']}", "attachments": [{"text": json.dumps(envelope.get("data", {}), sort_keys=True)}]}
    if host.endswith("webhook.office.com") or host.endswith("logic.azure.com"):
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": envelope["event"],
                "title": f"007 Security Scanner: {envelope['event']}", "text": json.dumps(envelope.get("data", {}), sort_keys=True)}
    return envelope


def _post_json(url: str, body: bytes, signature: str) -> int:
    request = Request(url, data=body, headers={"Content-Type": "application/json", "X-007-Signature": signature, "User-Agent": "007-Security-Scanner/1"}, method="POST")
    class RejectRedirects(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    try:
        with build_opener(RejectRedirects()).open(request, timeout=10) as response:
            return response.status
    except (HTTPError, URLError, TimeoutError) as exc:
        raise WebhookDeliveryError(f"Webhook request failed: {getattr(exc, 'code', type(exc).__name__)}") from exc


async def dispatch_subscription(subscription: WebhookSubscription, event: str, data: dict) -> dict:
    validate_webhook_url(subscription.url)
    envelope = {"event": event, "subscription_id": subscription.id, "target_id": subscription.target_id, "data": data}
    body = json.dumps(_payload_for(subscription.url, envelope), sort_keys=True, separators=(",", ":")).encode("utf-8")
    if subscription.secret_key_wrapped_dek:
        try:
            secret = get_encryption_service().decrypt(
                EncryptedEnvelope(subscription.secret_key, subscription.secret_key_wrapped_dek),
                context=f"webhook-subscription:{subscription.id}",
            )
        except EncryptionError as exc:
            raise WebhookDeliveryError("Webhook secret could not be decrypted.") from exc
    else:
        try:
            secret = decrypt_secret(subscription.secret_key)
        except ValueError as exc:
            raise WebhookDeliveryError("Webhook secret could not be decrypted.") from exc
    register_secret_for_redaction(secret)
    signature = signature_for(secret, body)
    status = await asyncio.to_thread(_post_json, subscription.url, body, signature)
    return {"subscription_id": subscription.id, "delivered": 200 <= status < 300, "http_status": status}


async def dispatch_event(db: Session, target_id: int | None, event: str, data: dict) -> list[dict]:
    stmt = select(WebhookSubscription).where(WebhookSubscription.is_active.is_(True))
    if target_id is not None:
        stmt = stmt.where(or_(WebhookSubscription.target_id.is_(None), WebhookSubscription.target_id == target_id))
    else:
        stmt = stmt.where(WebhookSubscription.target_id.is_(None))
    subscriptions = [item for item in db.execute(stmt).scalars().all() if event in (item.events or [])]
    results = await asyncio.gather(*(dispatch_subscription(item, event, data) for item in subscriptions), return_exceptions=True)
    return [{"subscription_id": sub.id, "delivered": False, "error": str(result)} if isinstance(result, Exception) else result
            for sub, result in zip(subscriptions, results)]
