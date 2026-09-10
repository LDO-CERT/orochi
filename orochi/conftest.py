import subprocess
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest
from django.contrib.auth.models import Group
from django.core.files.uploadedfile import SimpleUploadedFile
from guardian.shortcuts import assign_perm

from orochi.users.models import User
from orochi.users.tests.factories import AdminFactory, UserFactory
from orochi.website.models import Bookmark, Dump, Folder, Plugin


@pytest.fixture(autouse=True)
def media_storage(settings, tmpdir):
    settings.MEDIA_ROOT = tmpdir.strpath


@pytest.fixture
def user() -> User:
    return UserFactory()


@pytest.fixture
def admin() -> User:
    return AdminFactory()


@pytest.fixture
def readonly_user(db):
    user = User.objects.create_user("readonly", "readonly@example.com", "password")
    group, _ = Group.objects.get_or_create(name="ReadOnly")
    user.groups.add(group)
    return user


@pytest.fixture
def analyst_user(db):
    user = User.objects.create_user("analyst", "analyst@example.com", "password")
    group, _ = Group.objects.get_or_create(name="Analyst")
    user.groups.add(group)
    return user


@pytest.fixture
def reviewer_user(db):
    user = User.objects.create_user("reviewer", "reviewer@example.com", "password")
    group, _ = Group.objects.get_or_create(name="Reviewer")
    user.groups.add(group)
    return user


@pytest.fixture
def plugin(db):
    return Plugin.objects.create(name="test_plugin", operating_system="Linux")


@pytest.fixture
def folder(db, admin):
    return Folder.objects.create(name="test_folder", user=admin)


@pytest.fixture
def dump(db, admin, folder):
    dump = Dump.objects.create(
        operating_system="Linux",
        name="test_dump",
        index=str(uuid4()),
        author=admin,
        folder=folder,
        upload=SimpleUploadedFile("test.raw", b"file_content"),
    )
    assign_perm("can_see", admin, dump)
    return dump


@pytest.fixture
def bookmark(db, admin, dump, plugin):
    bookmark = Bookmark.objects.create(
        user=admin,
        name="test_bookmark",
        plugin=plugin,
        query="test",
    )
    bookmark.indexes.add(dump)
    return bookmark


SORPRESA_ZIP_PATH = Path("../examples/sorpresa.zip")


@pytest.fixture
def synthetic_vmem(tmp_path) -> Path:
    """Creates a deterministic synthetic .vmem file with known patterns."""
    vmem_path = tmp_path / "sample.vmem"
    data = bytearray(64 * 1024)
    data[:5] = b"ELF\x02\x01"
    banner_str = b"Linux version 5.4.0-test (gcc version 9.3.0) #42 SMP"
    data[512 : 512 + len(banner_str)] = banner_str
    needle = b"loading"
    data[33075 : 33075 + len(needle)] = needle
    vmem_path.write_bytes(bytes(data))
    return vmem_path


@pytest.fixture
def synthetic_zip(tmp_path, synthetic_vmem) -> Path:
    """Creates a zip archive containing synthetic sample.vmem."""
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(synthetic_vmem, arcname="sample.vmem")
    return zip_path


@pytest.fixture(scope="session")
def sorpresa_extracted_file(tmp_path_factory):
    """Extracts sorpresa.vmem once per test session if sorpresa.zip exists."""
    if not SORPRESA_ZIP_PATH.exists():
        return None
    extract_dir = tmp_path_factory.mktemp("sorpresa_cache")
    vmem_file = extract_dir / "sorpresa.vmem"
    if not vmem_file.exists():
        res = subprocess.run(
            ["7z", "e", str(SORPRESA_ZIP_PATH), f"-o{extract_dir}", "-y"],
            capture_output=True,
        )
        if res.returncode != 0 or not vmem_file.exists():
            return None
    return vmem_file
