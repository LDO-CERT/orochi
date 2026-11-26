"""History of plugin runs (#1674 FR-4, FR-5, FR-8).

Every execution of a plugin on a dump is a :class:`~orochi.website.models.ResultRun`. Re-running a plugin
replaces the rows of its Result: :func:`archive_and_clear` first writes the current rows to a gzipped JSON
snapshot (``MEDIA_ROOT/<dump index>/history/<plugin>/run_<n>.json.gz``) attached to the run that produced
them, so nothing is lost across re-runs, playbooks and retries.

``rows_sha256`` is the SHA-256 of the rows in canonical JSON (one ``json.dumps(row, sort_keys=True)`` per row,
newline separated, in storage order): it is computed when a run stores its rows and again when they are
archived, so a downloaded snapshot can be checked against the run that produced it.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
from collections.abc import Iterable
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

logger = logging.getLogger(__name__)


def canonical_rows_hash(rows: Iterable[dict]) -> tuple[str, int]:
    """SHA-256 and count of ``rows`` in canonical JSON (see module docstring)."""
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        digest.update(json.dumps(row, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8"))
        digest.update(b"\n")
        count += 1
    return digest.hexdigest(), count


def _next_number(result) -> int:
    return (result.runs.aggregate(n=Max("number"))["n"] or 0) + 1


def start_run(result, *, user_pk=None, parameters=None, reason: str = "run"):
    """Record the start of a run; previous rows, if any, are archived first."""
    from orochi.website.models import Result, ResultRun

    with transaction.atomic():
        Result.objects.select_for_update().filter(pk=result.pk).first()
        if result.value_set.exists():
            archive_and_clear(result, user_pk=user_pk, reason=f"before {reason}")
        return ResultRun.objects.create(
            result=result,
            number=_next_number(result),
            status=result.result,
            started_at=timezone.now(),
            user_id=user_pk,
            reason=reason,
            parameters=parameters or {},
        )


def finish_run(run, *, status: int, rows: list[dict] | None = None, constructed=None, plugin=None) -> None:
    """Record the end of a run: status, row count and hash, Volatility/plugin versions and symbol tables."""
    if run is None:
        return
    rows = rows or []
    run.rows_sha256, run.row_count = canonical_rows_hash(rows) if rows else ("", 0)
    run.status = status
    run.finished_at = timezone.now()
    run.volatility_version = _volatility_version()
    if plugin is not None:
        run.plugin_version = ".".join(str(x) for x in getattr(plugin, "_version", ()) or ())
    if constructed is not None:
        run.symbols = symbol_tables_of(constructed)
    run.save()


def _volatility_version() -> str:
    try:
        from volatility3.framework import constants

        return constants.PACKAGE_VERSION
    except Exception:
        return ""


def symbol_tables_of(constructed) -> list[dict]:
    """Symbol tables (ISF) a constructed plugin used, with the SHA-256 of local ISF files."""
    try:
        config = dict(constructed.build_configuration())
    except Exception:
        return []
    tables = []
    for key, value in sorted(config.items()):
        if not key.endswith("isf_url") or not isinstance(value, str):
            continue
        entry = {"config": key, "isf_url": value}
        path = value.removeprefix("file://") if value.startswith("file://") else None
        if path and Path(path).is_file():
            entry["sha256"] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        tables.append(entry)
    return tables


def snapshot_dir(result) -> Path:
    """Folder of the snapshots of one Result."""
    safe_plugin = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in result.plugin.name)
    return Path(settings.MEDIA_ROOT) / str(result.dump.index) / "history" / safe_plugin


def archive_and_clear(result, *, user_pk=None, reason: str = "re-run"):
    """Archive the current rows of ``result`` as a snapshot of the run that produced them, then delete them.

    Returns the run holding the snapshot, or ``None`` when there was nothing to archive. Rows that predate
    run tracking get a run of their own (``reason="before history"``).
    """
    from orochi.website.models import ResultRun, Value

    rows_qs = Value.objects.filter(result=result).order_by("pk")
    if not rows_qs.exists():
        return None
    run = result.runs.filter(snapshot_path="").order_by("-number").first()
    if run is None or run.status in (0, 1):
        run = ResultRun.objects.create(
            result=result,
            number=_next_number(result),
            status=result.result,
            finished_at=result.updated_at,
            user_id=user_pk,
            reason="before history",
            parameters=result.parameter or {},
        )

    folder = snapshot_dir(result)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"run_{run.number}.json.gz"
    digest = hashlib.sha256()
    count = 0
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for value in rows_qs.values_list("value", flat=True).iterator(chunk_size=2000):
            line = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
            fh.write(line + "\n")
            digest.update(line.encode("utf-8") + b"\n")
            count += 1
    run.snapshot_path = str(path)
    run.snapshot_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    run.snapshot_size = path.stat().st_size
    if not run.rows_sha256:
        run.rows_sha256, run.row_count = digest.hexdigest(), count
    elif run.rows_sha256 != digest.hexdigest():
        logger.warning("Rows of %s run %s changed since the run stored them", result, run.number)
    with transaction.atomic():
        run.save()
        rows_qs.delete()
    logger.info("Archived %s rows of %s (run %s, %s) to %s", count, result, run.number, reason, path)
    return run


def read_snapshot(run) -> Iterable[dict]:
    """Rows of an archived run, in storage order."""
    with gzip.open(run.snapshot_path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def delete_snapshot(run, user) -> None:
    """Remove the archived rows of a run; the run record stays (custody)."""
    if run.snapshot_path:
        Path(run.snapshot_path).unlink(missing_ok=True)
    run.snapshot_deleted_at = timezone.now()
    run.snapshot_deleted_by = user
    run.save(update_fields=["snapshot_deleted_at", "snapshot_deleted_by"])
