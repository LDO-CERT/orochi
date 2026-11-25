"""Recycle bin of deleted dumps.

Deleting a dump sets its status to Deleted and keeps its files and results: it disappears from every list
(``Dump.objects`` hides it) and can be restored for ``DUMP_RETENTION_DAYS`` days (Admin › Extra settings). Expired
dumps are purged, i.e. really deleted with their files, by :func:`purge_expired` — enqueued after every deletion and
when the recycle bin is opened, and available as ``manage.py purge_recycle_bin`` for a cron job.
``DUMP_RETENTION_DAYS = 0`` restores the old behaviour: deletion is immediate and permanent.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.utils import timezone

from orochi.website.defaults import DUMP_STATUS_DELETED
from orochi.website.runtime_settings import _get

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 7


def retention_days() -> int:
    """Days a deleted dump stays restorable (0 = no recycle bin)."""
    try:
        return max(0, int(_get("DUMP_RETENTION_DAYS", DEFAULT_RETENTION_DAYS)))
    except (TypeError, ValueError):
        return DEFAULT_RETENTION_DAYS


def deleted_dumps():
    """Every dump in the recycle bin, most recently deleted first."""
    from orochi.website.models import Dump

    return Dump.all_objects.filter(status=DUMP_STATUS_DELETED).order_by("-deleted_at")


def purge_at(dump):
    """When ``dump`` will be purged (``None`` if it is not in the recycle bin)."""
    if dump.deleted_at is None:
        return None
    return dump.deleted_at + timedelta(days=retention_days())


def purge(dump) -> None:
    """Delete the dump for good: results, bookmarks, media folder and upload go with it (``pre_delete`` signal)."""
    logger.info("Purging dump %s (%s)", dump.pk, dump.name)
    dump.delete()


def purge_expired(days: int | None = None) -> int:
    """Purge the dumps deleted more than ``days`` (default: the retention setting) ago; return how many."""
    days = retention_days() if days is None else max(0, days)
    expired = deleted_dumps().filter(deleted_at__lte=timezone.now() - timedelta(days=days))
    count = 0
    for dump in expired:
        try:
            purge(dump)
            count += 1
        except Exception as exc:
            logger.error("Purge of dump %s failed: %s", dump.pk, exc)
    return count


def schedule_purge() -> None:
    """Enqueue :func:`purge_expired` in the background; never raises."""
    from orochi.website.tasks import purge_recycle_bin_task

    try:
        purge_recycle_bin_task.enqueue()
    except Exception as exc:
        logger.warning("Recycle bin purge not scheduled: %s", exc)
