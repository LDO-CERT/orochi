"""/api/utils/: VirusTotal report files, task re-run and info, MaxMind and changelog."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from django.conf import settings
from guardian.shortcuts import assign_perm

from orochi.users.tests.factories import UserFactory
from orochi.website.models import TaskLog


@pytest.fixture
def vt_report(dump):
    folder = Path(settings.MEDIA_ROOT) / dump.index
    folder.mkdir(parents=True, exist_ok=True)
    report = folder / "pid.1.dmp.vt.json"
    report.write_text(json.dumps({"positives": 3}))
    secret = Path(settings.MEDIA_ROOT) / "secret.json"
    secret.write_text(json.dumps({"key": "do-not-leak"}))
    return report


@pytest.mark.django_db
def test_vt_report_for_a_visible_dump(client, analyst_user, dump, vt_report):
    assign_perm("website.can_see", analyst_user, dump)
    client.force_login(analyst_user)
    res = client.get("/api/utils/vt", {"path": f"/media/{dump.index}/{vt_report.name}"})
    assert res.status_code == 200
    assert res.json() == {"positives": 3}


@pytest.mark.django_db
def test_vt_report_refuses_traversal_other_users_and_short_paths(client, analyst_user, dump, vt_report):
    assign_perm("website.can_see", analyst_user, dump)
    client.force_login(analyst_user)
    # Used to read any JSON file: the permission check only looked at the second path component
    traversal = f"{settings.MEDIA_ROOT}/{dump.index}/../secret.json"
    res = client.get("/api/utils/vt", {"path": traversal})
    assert res.status_code == 403
    assert "do-not-leak" not in res.content.decode()
    # Not a .vt.json file
    other = Path(settings.MEDIA_ROOT) / dump.index / "notes.json"
    other.write_text("{}")
    assert client.get("/api/utils/vt", {"path": str(other)}).status_code == 403
    # Used to answer 500 (IndexError)
    assert client.get("/api/utils/vt", {"path": "/x"}).status_code == 403

    client.force_login(UserFactory())
    assert client.get("/api/utils/vt", {"path": str(vt_report)}).status_code == 403


@pytest.mark.django_db
def test_rerun_task(client, admin):
    client.force_login(admin)
    assert client.post("/api/utils/tasks/rerun/missing").status_code == 404
    TaskLog.objects.create(task_id="t-unsupported", name="something_else")
    res = client.post("/api/utils/tasks/rerun/t-unsupported")
    assert res.status_code == 400 and "unsupported" in res.json()["errors"]

    TaskLog.objects.create(task_id="t-sync", name="sync_volatility_plugins")
    with patch("orochi.website.tasks.sync_volatility_plugins") as task:
        task.enqueue.return_value = MagicMock(id="new-id")
        res = client.post("/api/utils/tasks/rerun/t-sync")
    assert res.status_code == 200 and "new-id" in res.json()["message"]

    with patch("orochi.website.tasks.sync_volatility_plugins") as task:
        task.enqueue.side_effect = RuntimeError("scheduler down")
        res = client.post("/api/utils/tasks/rerun/t-sync")
    assert res.status_code == 400 and "scheduler down" in res.json()["errors"]


@pytest.mark.django_db
def test_rerun_task_is_superuser_only(client, analyst_user):
    TaskLog.objects.create(task_id="t-sync", name="sync_volatility_plugins")
    client.force_login(analyst_user)
    assert client.post("/api/utils/tasks/rerun/t-sync").status_code == 403


@pytest.mark.django_db
def test_task_info_for_dumps_and_logs(client, analyst_user, admin, dump):
    client.force_login(analyst_user)
    assert client.get("/api/utils/tasks/info/dump_abc").status_code == 404
    assert client.get(f"/api/utils/tasks/info/dump_{dump.pk}").status_code == 403
    assign_perm("website.can_see", analyst_user, dump)
    res = client.get(f"/api/utils/tasks/info/dump_{dump.pk}")
    assert res.status_code == 200
    assert res.json()["dump_index"] == dump.index

    TaskLog.objects.create(task_id="log-1", name="sync_yara_rules", status="Completed", result="ok")
    client.force_login(admin)
    res = client.get("/api/utils/tasks/info/log-1")
    assert res.status_code == 200
    assert res.json()["task_type"] == "system_task" and res.json()["can_kill"] is True


@pytest.mark.django_db
def test_task_info_unknown_raw_key_with_dask_down(client, admin):
    client.force_login(admin)
    with patch("orochi.api.routers.utils._get_dask_client", side_effect=OSError("unreachable")):
        assert client.get("/api/utils/tasks/info/raw-key").status_code == 404


@pytest.mark.django_db
def test_maxmind_without_databases(client, analyst_user):
    client.force_login(analyst_user)
    with patch("orochi.api.routers.utils.Path.exists", return_value=False):
        res = client.get("/api/utils/maxmind", {"ip": "8.8.8.8"})
    assert res.status_code == 400
    assert "not found" in res.json()["errors"]


@pytest.mark.django_db
def test_changelog(client, analyst_user):
    client.force_login(analyst_user)
    res = client.get("/api/utils/changelog")
    assert res.status_code == 200
    assert "OROCHI" in res.json()["note"]
