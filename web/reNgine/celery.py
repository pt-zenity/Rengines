import os

from celery import Celery
from celery.signals import (
    setup_logging,
    task_postrun,
    task_prerun,
    worker_process_init,
    worker_process_shutdown,
    worker_ready,
    worker_shutting_down,
)
import django


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "reNgine.settings")
django.setup()

# ── Celery app ────────────────────────────────────────────────────────────────
app = Celery("reNgine")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@setup_logging.connect()
def config_loggers(*args, **kwargs):
    from logging.config import dictConfig

    dictConfig(app.conf["LOGGING"])


# ── DB connection management (Celery 5.6.x compatible) ───────────────────────
#
# Celery 5.6.1 fixed: "close DB pools only in prefork mode"
# For gevent pool (which reNgine uses), we manage connections manually via
# these signals to prevent "too many clients" on PostgreSQL.
#
# DO NOT call close_old_connections() in worker_process_init for gevent —
# gevent shares a single process, so closing connections at process init would
# drop every greenlet's connection. Instead, close per-task via prerun/postrun.


@worker_process_init.connect()
def worker_process_init_handler(**kwargs):
    """
    Called when a new worker process/greenlet pool starts.
    Reset the DB connection registry so gevent greenlets each get a fresh
    connection rather than inheriting a forked parent connection.
    """
    from django.db import connections

    # Close ALL connections - they will be re-opened on first DB access
    for conn in connections.all():
        try:
            conn.close()
        except Exception:
            pass


@worker_ready.connect()
def worker_ready_handler(**kwargs):
    """Called when the worker is fully ready to accept tasks."""
    import logging

    logger = logging.getLogger("celery.worker")
    logger.info("reNgine Celery worker ready | pool=gevent | soft_limit=10800s | hard_limit=14400s")


@task_prerun.connect()
def task_prerun_handler(task_id, task, *args, **kwargs):
    """
    Close stale DB connections before each task.
    With CONN_MAX_AGE=0, Django closes connections after each HTTP request,
    but Celery tasks are not HTTP requests. This signal recycles connections
    before each task to prevent 'too many clients' PostgreSQL errors.
    """
    from django.db import close_old_connections

    try:
        close_old_connections()
    except Exception:
        pass


@task_postrun.connect()
def task_postrun_handler(task_id, task, *args, **kwargs):
    """
    Close ALL DB connections after each task completes.
    Ensures gevent workers don't accumulate idle PostgreSQL connections.
    This is safe because CONN_MAX_AGE=0 — Django will open a fresh connection
    on the next DB access.
    """
    from django.db import connections

    for conn in connections.all():
        try:
            conn.close()
        except Exception:
            pass


@worker_shutting_down.connect()
def worker_shutting_down_handler(**kwargs):
    """Clean up DB connections when worker shuts down gracefully."""
    from django.db import connections

    for conn in connections.all():
        try:
            conn.close()
        except Exception:
            pass


@worker_process_shutdown.connect()
def worker_process_shutdown_handler(**kwargs):
    """Final cleanup when the worker process exits."""
    from django.db import connections

    for conn in connections.all():
        try:
            conn.close()
        except Exception:
            pass
