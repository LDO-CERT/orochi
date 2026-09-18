import json
from unittest.mock import MagicMock, patch

import pytest

from orochi.website.defaults import (
    RESULT_STATUS_RUNNING,
)
from orochi.website.models import Result, TaskLog

pytestmark = pytest.mark.django_db


@pytest.fixture
def sample_tasks(admin, dump, plugin):
    # 1. Create a running Result
    res = Result.objects.create(
        dump=dump,
        plugin=plugin,
        result=RESULT_STATUS_RUNNING,
    )

    # 2. Create TaskLog entries
    t1 = TaskLog.objects.create(task_id="tlog-1", name="sync_volatility_plugins", status="Running")
    t2 = TaskLog.objects.create(task_id="tlog-2", name="sync_volatility_symbols", status="Submitted")
    t3 = TaskLog.objects.create(task_id="tlog-3", name="build_cache_in_background", status="Completed", result="OK")
    t4 = TaskLog.objects.create(task_id="tlog-4", name="sync_yara_rules", status="Failed", error="Timeout")

    return {
        "dump": dump,
        "result": res,
        "tasklogs": [t1, t2, t3, t4],
    }


def test_tasks_list_and_filters(client, admin, sample_tasks):
    client.force_login(admin)

    with patch("orochi.api.routers.tasks.get_dask_cluster_state") as mock_cluster:
        mock_cluster.return_value = ([], {}, {}, 1)

        # 1. List all
        resp = client.get("/api/tasks/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 5
        assert len(data["tasks"]) >= 5

        # 2. Filter by status: Running
        resp_running = client.get("/api/tasks/?status=Running")
        assert resp_running.status_code == 200
        running_tasks = resp_running.json()["tasks"]
        for t in running_tasks:
            assert t["state"].lower() in ("running", "processing", "unzipping")

        # 3. Filter by status: Queued / Submitted
        resp_queued = client.get("/api/tasks/?status=Submitted")
        assert resp_queued.status_code == 200
        queued_tasks = resp_queued.json()["tasks"]
        assert any(t["task_id"] == "tlog-2" for t in queued_tasks)

        # 4. Filter by task_type: system_task
        resp_system = client.get("/api/tasks/?task_type=system_task")
        assert resp_system.status_code == 200
        for t in resp_system.json()["tasks"]:
            assert t["task_type"] == "system_task"

        # 5. Search query
        resp_search = client.get("/api/tasks/?search=yara")
        assert resp_search.status_code == 200
        search_tasks = resp_search.json()["tasks"]
        assert len(search_tasks) == 1
        assert search_tasks[0]["name"] == "sync_yara_rules"

        # 6. Pagination
        resp_page = client.get("/api/tasks/?limit=2&offset=0")
        assert resp_page.status_code == 200
        assert len(resp_page.json()["tasks"]) == 2


def test_tasks_summary_endpoint(client, admin, sample_tasks):
    client.force_login(admin)

    with patch("orochi.api.routers.tasks.get_dask_cluster_state") as mock_cluster:
        mock_worker = MagicMock()
        mock_worker.name = "worker-1"
        mock_worker.address = "tcp://worker:8786"
        mock_worker.nthreads = 4
        mock_worker.memory_limit = 1024 * 1024 * 1024
        mock_worker.executing = 1
        mock_cluster.return_value = ([mock_worker], {}, {}, 1)

        resp = client.get("/api/tasks/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] >= 1
        assert data["queued"] >= 1
        assert data["completed"] >= 1
        assert data["failed"] >= 1
        assert data["workers_count"] == 1


def test_tasks_get_info_endpoints(client, admin, sample_tasks):
    client.force_login(admin)
    res = sample_tasks["result"]
    tlog = sample_tasks["tasklogs"][0]

    # Info for Result task
    resp_res = client.get(f"/api/tasks/result_{res.pk}")
    assert resp_res.status_code == 200
    assert resp_res.json()["plugin_name"] == res.plugin.name

    # Info for TaskLog task
    resp_tlog = client.get(f"/api/tasks/{tlog.task_id}")
    assert resp_tlog.status_code == 200
    assert resp_tlog.json()["name"] == tlog.name


def test_tasks_kill_individual(client, admin, sample_tasks):
    client.force_login(admin)
    tlog = sample_tasks["tasklogs"][0]

    with patch("orochi.api.routers.utils.Client"):
        resp = client.post(f"/api/tasks/{tlog.task_id}/kill")
        assert resp.status_code == 200
        tlog.refresh_from_db()
        assert tlog.status == "Failed"
        assert "killed" in tlog.error.lower() or "cancel" in tlog.error.lower()


def test_tasks_retry_tasklog(client, admin, sample_tasks):
    client.force_login(admin)
    failed_log = sample_tasks["tasklogs"][3]  # sync_yara_rules

    with patch("orochi.ya.tasks.sync_yara_rules") as mock_task:
        mock_task.enqueue.return_value = MagicMock(id="new-task-id-123")

        resp = client.post(f"/api/tasks/{failed_log.task_id}/retry")
        assert resp.status_code == 200
        assert "new-task-id-123" in resp.json()["message"]
        mock_task.enqueue.assert_called_once()


def test_tasks_bulk_kill(client, admin, sample_tasks):
    client.force_login(admin)

    with patch("orochi.api.routers.tasks.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.processing.return_value = {}
        mock_client_cls.return_value = mock_client

        resp = client.post(
            "/api/tasks/bulk/kill",
            data=json.dumps({"all_running": True, "all_queued": True}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert "cancelled" in resp.json()["message"].lower()

        # Running and queued logs should now be Failed
        assert not TaskLog.objects.filter(status="Running").exists()
        assert not TaskLog.objects.filter(status="Submitted").exists()


def test_tasks_prune(client, admin, sample_tasks):
    client.force_login(admin)
    # Prune all completed and failed logs
    resp = client.delete("/api/tasks/prune?all=true")
    assert resp.status_code == 200
    assert "pruned" in resp.json()["message"].lower()

    # Completed and Failed logs should be deleted
    assert not TaskLog.objects.filter(status__in=["Completed", "Failed"]).exists()
    # Running / Submitted logs should remain
    assert TaskLog.objects.filter(status__in=["Running", "Submitted"]).exists()


def test_tasks_workers_restart(client, admin, analyst_user):
    # Analyst cannot restart workers
    client.force_login(analyst_user)
    resp_analyst = client.post("/api/tasks/workers/restart")
    assert resp_analyst.status_code == 403

    # Admin can restart workers
    client.force_login(admin)
    with patch("orochi.api.routers.tasks.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        resp = client.post("/api/tasks/workers/restart")
        assert resp.status_code == 200
        assert "restarted" in resp.json()["message"].lower()
        mock_client.restart.assert_called_once()
