"""Archive extraction never destroys the uploaded dump (#167 live test on import_local)."""

import shutil
from uuid import uuid4

import pytest

from orochi.utils.volatility_dask_elk import unzip
from orochi.website.models import Dump

pytestmark = pytest.mark.django_db


def _dump(admin):
    return Dump.objects.create(operating_system="Linux", name="z", index=str(uuid4()), author=admin)


def test_failed_extraction_keeps_the_archive(admin, tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"PK\x03\x04 not really a zip")
    out = tmp_path / "out"
    out.mkdir()
    assert unzip(_dump(admin), str(archive), str(out), password=None) is None
    assert archive.exists()


def test_archive_inside_the_dump_folder_is_extracted_and_removed(admin, tmp_path, synthetic_zip):
    dump_dir = tmp_path / "dump_index"
    dump_dir.mkdir()
    archive = dump_dir / "upload.zip"
    shutil.copy(synthetic_zip, archive)
    newpath = unzip(_dump(admin), str(archive), str(dump_dir), password=None)
    assert newpath is not None and newpath.endswith("sample.vmem")
    assert not archive.exists()
