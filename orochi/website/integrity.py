"""Evidence integrity of dumps (#1674 FR-1, FR-2).

- On receipt (:func:`record_received`) the uploaded file is hashed before anything touches it; with
  ``KEEP_ORIGINAL_UPLOAD`` (Admin › Extra settings, on by default) an archive is kept as received under
  ``MEDIA_ROOT/<index>/original/`` after the memory image is extracted.
- After extraction (:func:`record_image`) the memory image hash becomes the reference for later checks.
- :func:`verify_dump` re-hashes the image (and the kept original) and records the outcome; a mismatch
  notifies the users who can see the dump. Every check is an :class:`~orochi.website.models.IntegrityCheck`,
  exported with the case bundle as part of the custody log.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def sha256_of(path: str | Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(block_size):
            digest.update(block)
    return digest.hexdigest()


def keep_original_upload() -> bool:
    from orochi.website.runtime_settings import _get

    return bool(_get("KEEP_ORIGINAL_UPLOAD", True))


def record_received(dump, path: str, user_pk=None) -> str:
    """Hash the upload exactly as received and remember it on the dump."""
    from orochi.website.models import IntegrityCheck

    digest = sha256_of(path)
    dump.received_name = Path(path).name
    dump.received_size = Path(path).stat().st_size
    dump.received_sha256 = digest
    dump.save(update_fields=["received_name", "received_size", "received_sha256"])
    IntegrityCheck.objects.create(
        dump=dump, kind="received", user_id=user_pk, target=dump.received_name, actual_sha256=digest, ok=True
    )
    return digest


def record_image(dump, user_pk=None) -> None:
    """Record the hash of the extracted memory image (computed by the upload pipeline)."""
    from orochi.website.models import IntegrityCheck

    IntegrityCheck.objects.create(
        dump=dump, kind="image", user_id=user_pk, target=Path(dump.upload.name).name, actual_sha256=dump.sha256, ok=True
    )


def verify_dump(dump, user=None):
    """Re-hash the memory image and the kept original upload; record and return the check."""
    from orochi.website.models import IntegrityCheck
    from orochi.website.storage import ensure_local_dump_path

    problems, details = [], []
    try:
        image = ensure_local_dump_path(dump)
        actual = sha256_of(image)
        details.append(f"image {Path(image).name}: {actual}")
        if dump.sha256 and actual != dump.sha256:
            problems.append(f"memory image hash {actual} differs from the recorded {dump.sha256}")
    except Exception as exc:
        actual = ""
        problems.append(f"memory image not readable: {exc}")
    if dump.original_path:
        if Path(dump.original_path).is_file():
            original = sha256_of(dump.original_path)
            details.append(f"original {Path(dump.original_path).name}: {original}")
            if dump.received_sha256 and original != dump.received_sha256:
                problems.append(f"original upload hash {original} differs from the one received {dump.received_sha256}")
        else:
            problems.append("the original upload kept on receipt is missing")
    check = IntegrityCheck.objects.create(
        dump=dump,
        kind="verify",
        user=user,
        target=Path(dump.upload.name).name if dump.upload else "",
        expected_sha256=dump.sha256 or "",
        actual_sha256=actual,
        ok=not problems,
        detail="\n".join(problems or details),
    )
    if problems:
        logger.error("Integrity check failed for dump %s: %s", dump.pk, "; ".join(problems))
        try:
            from orochi.website.notifier import notify_dump_users

            notify_dump_users(dump, "INTEGRITY CHECK FAILED: " + "; ".join(problems), kind="dump")
        except Exception:
            pass
    return check
