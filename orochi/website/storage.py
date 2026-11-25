"""Local access to dump files for Volatility, hex viewer and scanners (Issue #1562).

With the default FileSystemStorage dumps already live on the shared /media volume and are
used in place. With a remote backend (django-storages: S3, MinIO, Azure Blob) the object is
copied once into MEDIA_ROOT/_storage_cache/<dump index>/ and reused from there.

Remote storage is experimental: the ingestion pipeline still unzips and moves dumps inside
MEDIA_ROOT, so only the original upload goes through the remote backend.
"""

import fcntl
import logging
import os
import shutil
import tempfile
from pathlib import Path

from django.conf import settings
from django.core import checks

logger = logging.getLogger(__name__)

CACHE_DIRNAME = "_storage_cache"


def sanitize_filename(filename: str | None) -> str:
    """Return a single-segment safe filename or raise ValueError on invalid/traversal input."""
    if not filename or "\x00" in filename:
        raise ValueError("Invalid filename")
    normalized = str(filename).replace("\\", "/").strip()
    if "/" in normalized or normalized in ("", ".", ".."):
        raise ValueError(f"Invalid filename: {filename}")
    return normalized


def allowed_upload_source_roots() -> tuple[Path, ...]:
    """Return trusted directories from which staged/local upload files may be moved."""
    roots = [
        Path(settings.MEDIA_ROOT) / "tmp",
        Path(settings.MEDIA_ROOT) / "uploads",
    ]
    local_upload = getattr(settings, "LOCAL_UPLOAD_PATH", "")
    if local_upload:
        roots.append(Path(local_upload))
    return tuple(roots)


def resolve_path_within(
    candidate: str | Path,
    allowed_roots: list[str | Path] | tuple[str | Path, ...],
    *,
    must_exist_file: bool = False,
) -> Path:
    """Resolve candidate path and verify it stays strictly within one of allowed_roots."""
    candidate_str = str(candidate or "")
    if not candidate_str or "\x00" in candidate_str:
        raise ValueError("Invalid file path")
    raw_path = Path(candidate_str)
    if must_exist_file and raw_path.is_symlink():
        raise ValueError(f"Symlink upload source rejected: {candidate_str}")
    resolved = raw_path.resolve()
    if not any(resolved.is_relative_to(Path(root).resolve()) for root in allowed_roots):
        raise ValueError(f"Path outside allowed directories: {candidate_str}")
    if must_exist_file and not resolved.is_file():
        raise FileNotFoundError(f"Source file not found: {candidate_str}")
    return resolved


def unique_path_in_dir(directory: Path, filename: str) -> Path:
    """Return a non-colliding, strictly contained Path for filename under directory."""
    safe_name = sanitize_filename(filename)
    base_dir = Path(directory)
    base_dir.mkdir(parents=True, exist_ok=True)
    candidate = resolve_path_within(base_dir / safe_name, [base_dir])
    stem, extension = os.path.splitext(safe_name)
    counter = 1
    while candidate.exists():
        candidate = resolve_path_within(base_dir / f"{stem}{counter}{extension}", [base_dir])
        counter += 1
    return candidate


def _cache_root() -> Path:
    """Local cache folder for dumps kept on remote (S3 / MinIO) storage."""
    return Path(settings.MEDIA_ROOT) / CACHE_DIRNAME


def get_local_dump_size(dump) -> int:
    """Size of the dump file without downloading it from a remote backend (0 if missing)."""
    if not dump or not dump.upload:
        return 0
    try:
        local_path = dump.upload.path
    except (NotImplementedError, AttributeError, ValueError):
        local_path = None
    if local_path:
        return os.path.getsize(local_path) if os.path.exists(local_path) else 0
    try:
        return dump.upload.size
    except Exception:
        return 0


def ensure_local_dump_path(dump) -> str:
    """Return a local POSIX path for the dump file, materializing it from remote storage if needed."""
    if not dump or not dump.upload:
        raise FileNotFoundError("Dump has no associated upload file.")

    try:
        local_path = dump.upload.path
    except (NotImplementedError, AttributeError, ValueError):
        local_path = None  # remote backend: no local path
    if local_path:
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Dump file not found: {local_path}")
        return os.path.abspath(local_path)

    cache_dir = _cache_root() / str(dump.index)
    cache_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(dump.upload.name).name or f"{dump.index}.raw"
    cached_file = cache_dir / filename

    # Several Dask workers may need the same dump at once: serialize the download per dump
    with open(cache_dir / ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _is_complete(cached_file, dump):
            os.utime(cached_file)  # LRU: mark as recently used
            return str(cached_file.resolve())

        logger.info("Materializing remote dump %s (%s) into %s", dump.index, dump.upload.name, cached_file)
        with tempfile.NamedTemporaryFile(dir=cache_dir, prefix=f".{filename}.", delete=False) as dst:
            tmp_path = dst.name
            try:
                with dump.upload.open("rb") as src:
                    shutil.copyfileobj(src, dst, length=8 * 1024 * 1024)
            except BaseException:
                os.unlink(tmp_path)
                raise
        os.replace(tmp_path, cached_file)

    evict_cache(keep=cache_dir)
    return str(cached_file.resolve())


def _is_complete(cached_file: Path, dump) -> bool:
    """True when the cached copy exists, is not empty and matches the dump size (when known)."""
    if not cached_file.exists() or cached_file.stat().st_size == 0:
        return False
    return not dump.size or cached_file.stat().st_size == dump.size


def evict_cache(keep: Path | None = None, max_bytes: int | None = None) -> list[Path]:
    """Remove the least recently used cached dumps until the cache fits STORAGE_CACHE_MAX_BYTES."""
    if max_bytes is None:
        from orochi.website.runtime_settings import storage_cache_max_bytes

        max_bytes = storage_cache_max_bytes()
    root = _cache_root()
    if not max_bytes or not root.exists():
        return []

    entries = []
    for entry in root.iterdir():
        if not entry.is_dir():
            continue
        files = [f for f in entry.iterdir() if f.is_file() and not f.name.startswith(".")]
        size = sum(f.stat().st_size for f in files)
        last_used = max((f.stat().st_mtime for f in files), default=0)
        entries.append((last_used, size, entry))

    total = sum(size for _, size, _ in entries)
    removed = []
    for _, size, entry in sorted(entries):
        if total <= max_bytes:
            break
        if keep is not None and entry.resolve() == keep.resolve():
            continue
        shutil.rmtree(entry, ignore_errors=True)
        total -= size
        removed.append(entry)
        logger.info("Evicted cached dump %s", entry.name)
    return removed


@checks.register(checks.Tags.compatibility)
def check_remote_storage(app_configs, **kwargs):
    """System check: with ``USE_S3_STORAGE`` or ``USE_AZURE_STORAGE`` the storage backend must be importable."""
    if getattr(settings, "USE_S3_STORAGE", False):
        flag, extra = "USE_S3_STORAGE", "s3"
    elif getattr(settings, "USE_AZURE_STORAGE", False):
        flag, extra = "USE_AZURE_STORAGE", "azure"
    else:
        return []
    backend = settings.STORAGES["default"]["BACKEND"]
    module = backend.rsplit(".", 1)[0]
    try:
        __import__(module)
    except ImportError:
        return [
            checks.Error(
                f"{flag} is enabled but the storage backend {backend} is not installed.",
                hint=f'Install it in the django and worker images, e.g. uv pip install "django-storages[{extra}]". '
                "It is not in uv.lock: remote storage is optional.",
                id="orochi.E001",
            )
        ]
    return []
