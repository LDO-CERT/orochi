import io
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.core.management import call_command

from orochi.website import storage


class RemoteUpload:
    """Mimics a django-storages FieldFile: no local path, readable stream."""

    def __init__(self, name, data):
        self.name = name
        self.data = data
        self.opened = 0

    def __bool__(self):
        return True

    @property
    def path(self):
        raise NotImplementedError("This backend doesn't support absolute paths.")

    @property
    def size(self):
        return len(self.data)

    def open(self, mode="rb"):
        self.opened += 1
        return io.BytesIO(self.data)


def remote_dump(index="abc", data=b"MEMORY" * 100, size=None):
    upload = RemoteUpload(f"{index}/memory.raw", data)
    return SimpleNamespace(index=index, upload=upload, size=len(data) if size is None else size)


def test_local_dump_is_used_in_place(dump):
    path = storage.ensure_local_dump_path(dump)
    assert path == os.path.abspath(dump.upload.path)
    assert storage.get_local_dump_size(dump) == len(b"file_content")
    assert not (Path(path).parent / storage.CACHE_DIRNAME).exists()


def test_missing_local_dump_raises_without_creating_cache(dump, settings):
    os.remove(dump.upload.path)
    with pytest.raises(FileNotFoundError):
        storage.ensure_local_dump_path(dump)
    assert not (Path(settings.MEDIA_ROOT) / storage.CACHE_DIRNAME).exists()
    assert storage.get_local_dump_size(dump) == 0


def test_remote_dump_is_materialized_once(settings):
    dump = remote_dump()
    first = storage.ensure_local_dump_path(dump)
    second = storage.ensure_local_dump_path(dump)

    assert first == second
    assert Path(first).read_bytes() == dump.upload.data
    assert Path(first).is_relative_to(Path(settings.MEDIA_ROOT) / storage.CACHE_DIRNAME)
    assert dump.upload.opened == 1
    # No temporary leftovers
    assert [p.name for p in Path(first).parent.iterdir() if not p.name.startswith(".lock")] == ["memory.raw"]
    assert storage.get_local_dump_size(dump) == len(dump.upload.data)


def test_truncated_cache_is_downloaded_again():
    dump = remote_dump()
    path = Path(storage.ensure_local_dump_path(dump))
    path.write_bytes(b"MEM")  # interrupted copy from an older version
    storage.ensure_local_dump_path(dump)
    assert path.read_bytes() == dump.upload.data
    assert dump.upload.opened == 2


def test_failed_download_leaves_no_partial_file(settings):
    dump = remote_dump()

    def broken_open(mode="rb"):
        raise OSError("connection reset")

    dump.upload.open = broken_open
    with pytest.raises(OSError):
        storage.ensure_local_dump_path(dump)
    cache_dir = Path(settings.MEDIA_ROOT) / storage.CACHE_DIRNAME / dump.index
    assert [p.name for p in cache_dir.iterdir()] == [".lock"]


def test_cache_eviction_least_recently_used(settings):
    settings.STORAGE_CACHE_MAX_BYTES = 0
    old = remote_dump("old", b"a" * 1000)
    recent = remote_dump("recent", b"b" * 1000)
    old_path = Path(storage.ensure_local_dump_path(old))
    recent_path = Path(storage.ensure_local_dump_path(recent))
    past = time.time() - 3600
    os.utime(old_path, (past, past))

    removed = storage.evict_cache(max_bytes=1500)

    assert [p.name for p in removed] == ["old"]
    assert not old_path.exists()
    assert recent_path.exists()


def test_eviction_never_removes_the_dump_in_use(settings):
    settings.STORAGE_CACHE_MAX_BYTES = 10  # smaller than any dump
    dump = remote_dump("big", b"x" * 1000)
    path = Path(storage.ensure_local_dump_path(dump))
    assert path.exists()


def test_system_check_reports_missing_backend(settings):
    settings.USE_S3_STORAGE = True
    settings.STORAGES = {**settings.STORAGES, "default": {"BACKEND": "not_installed_pkg.backends.S3Storage"}}
    errors = storage.check_remote_storage(None)
    assert [e.id for e in errors] == ["orochi.E001"]

    settings.USE_S3_STORAGE = False
    assert storage.check_remote_storage(None) == []


def test_system_check_reports_missing_azure_backend(settings):
    settings.USE_S3_STORAGE = False
    settings.USE_AZURE_STORAGE = True
    settings.STORAGES = {**settings.STORAGES, "default": {"BACKEND": "not_installed_pkg.azure_storage.AzureStorage"}}
    errors = storage.check_remote_storage(None)
    assert [e.id for e in errors] == ["orochi.E001"]
    assert "USE_AZURE_STORAGE" in errors[0].msg and "azure" in errors[0].hint


def test_check_command_runs_with_default_storage():
    call_command("check")
