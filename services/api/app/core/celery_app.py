"""Celery application configured for bounded, JSON-only security workloads."""
from celery import Celery

from app.settings import settings


celery_app = Celery(
    "007_security_scanner",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.vulnerability.tasks", "app.ai.patcher_tasks"],
)
celery_app.conf.update(
    broker_url=settings.redis_url,
    result_backend=settings.redis_url,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_always_eager=settings.celery_always_eager,
    task_eager_propagates=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=settings.celery_scan_soft_time_limit,
    task_time_limit=settings.celery_scan_time_limit,
    task_routes={
        "app.vulnerability.tasks.run_scan_task": {"queue": "security-scans"},
        "app.ai.patcher_tasks.generate_patch_task": {"queue": "patch-generation"},
    },
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": settings.celery_scan_time_limit + 120},
    result_expires=3600,
    enable_utc=True,
    timezone="UTC",
)
