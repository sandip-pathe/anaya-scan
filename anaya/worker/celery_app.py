"""
Celery application configuration.

Provides the Celery app instance used by:
- `celery -A anaya.worker.celery_app worker --loglevel=info`
- Task imports via `from anaya.worker.celery_app import celery_app`
"""

from __future__ import annotations

from celery import Celery

from anaya.config import settings

celery_app = Celery(
    "anaya",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

# ── Configuration ────────────────────────────────────────────
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task behavior
    task_acks_late=True,                 # Ack after execution (crash safety)
    worker_prefetch_multiplier=1,        # One task at a time per worker
    task_reject_on_worker_lost=True,     # Retry if worker dies

    # Result expiry
    result_expires=3600,                 # Results expire after 1 hour

    # Task routing — both worker and config use the 'default' queue
    # (If you add -Q scans to the worker command, uncomment the routing below)
    # task_routes={
    #     "anaya.worker.tasks.scan_pr": {"queue": "scans"},
    # },

    # Retry policy for broker connection
    broker_connection_retry_on_startup=True,
)

# Auto-discover tasks from the tasks module
celery_app.autodiscover_tasks(["anaya.worker"])
