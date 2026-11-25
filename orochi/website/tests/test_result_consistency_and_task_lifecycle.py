"""Regression tests for result storage consistency (#1666) and task lifecycle/reconciliation (#1663, #1564)."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from orochi.api.routers.tasks import reconcile_stale_tasks
from orochi.utils.volatility_dask_elk import run_plugin
from orochi.website.defaults import DUMP_STATUS_ERROR, DUMP_STATUS_UNZIPPING, RESULT_STATUS_SUCCESS
from orochi.website.models import Dump, Plugin, Result, TaskLog, Value

pytestmark = pytest.mark.django_db


def test_result_rows_are_readable_immediately_when_status_becomes_success(dump, tmp_path):
    """AC1 (#1666): Value rows must already be persisted when Result transitions to RESULT_STATUS_SUCCESS."""
    fake_file = tmp_path / "sample.raw"
    fake_file.write_bytes(b"\x00" * 64)
    plugin_obj, _ = Plugin.objects.get_or_create(
        name="windows.cmdline.CmdLine",
        defaults={"operating_system": "Windows"},
    )

    observed_row_counts_on_success: list[int] = []
    original_save = Result.save

    def _spy_save(self, *args, **kwargs):
        original_save(self, *args, **kwargs)
        if self.result == RESULT_STATUS_SUCCESS:
            observed_row_counts_on_success.append(Value.objects.filter(result=self).count())

    sample_rows = [{"PID": 100 + i, "Args": f"cmd.exe /c echo {i}"} for i in range(31)]
    fake_constructed = MagicMock()
    fake_constructed.run.return_value = MagicMock()
    fake_constructed.build_configuration.return_value = {}

    with (
        patch("orochi.utils.volatility_dask_elk.close_old_connections"),
        patch("orochi.website.storage.ensure_local_dump_path", return_value=str(fake_file)),
        patch("orochi.utils.volatility_dask_elk.plugins.construct_plugin", return_value=fake_constructed),
        patch("orochi.utils.volatility_dask_elk.ReturnJsonRenderer.render", return_value=(sample_rows, None)),
        patch("orochi.website.tasks.index_result_values_task", MagicMock()),
        patch.object(Result, "save", _spy_save),
    ):
        run_plugin(dump, plugin_obj, params=None)

    assert observed_row_counts_on_success == [31]


def test_worker_restart_reports_success_when_workers_are_active_after_timeout(client, admin):
    """AC2 (#1663): Worker restart returning TimeoutError while workers are online must return HTTP 200."""
    client.force_login(admin)
    fake_client = MagicMock()
    fake_client.restart.side_effect = TimeoutError("RPC timed out after 30s")
    fake_client.scheduler_info.return_value = {"workers": {"tcp://10.0.0.2:1234": {}}}

    with patch("orochi.api.routers.tasks.Client", return_value=fake_client):
        resp = client.post("/api/tasks/workers/restart")

    assert resp.status_code == 200
    assert "worker(s)" in resp.json()["message"]


def test_worker_restart_reports_how_many_workers_it_restarted(client, admin):
    """Found live: right after the restart no worker is connected yet, so the message must not say "0 online"."""
    client.force_login(admin)
    fake_client = MagicMock()
    fake_client.scheduler_info.side_effect = [{"workers": {"a": {}, "b": {}, "c": {}, "d": {}}}, {"workers": {}}]
    with patch("orochi.api.routers.tasks.Client", return_value=fake_client):
        resp = client.post("/api/tasks/workers/restart")
    assert resp.status_code == 200
    assert "Restart of 4 Dask worker process(es) requested" in resp.json()["message"]


def test_reconcile_stale_unzipping_dump_and_running_tasklog(admin):
    """AC3 (#1663 / #1564): Stale transient Unzipping dumps and Running TaskLogs are reconciled."""
    old_time = timezone.now() - timedelta(hours=23)
    stale_dump = Dump.objects.create(
        name="StaleUnzipDump",
        operating_system="Windows",
        author=admin,
        status=DUMP_STATUS_UNZIPPING,
    )
    Dump.objects.filter(pk=stale_dump.pk).update(created_at=old_time)

    stale_log = TaskLog.objects.create(
        task_id="sys-stale-999",
        name="sync_yara_rules",
        status="Running",
    )
    TaskLog.objects.filter(pk=stale_log.pk).update(updated_at=old_time)

    reconciled = reconcile_stale_tasks(active_dask_keys=set(), max_age_seconds=3600)
    assert reconciled == 2

    stale_dump.refresh_from_db()
    stale_log.refresh_from_db()
    assert stale_dump.status == DUMP_STATUS_ERROR
    assert "reconciled" in (stale_dump.description or "")
    assert stale_log.status == "Failed"


def test_reconcile_never_touches_work_that_may_still_run(admin):
    """Unknown scheduler state, an active upload or a busy cluster leave transient dumps alone."""
    old_time = timezone.now() - timedelta(hours=23)
    unzipping = Dump.objects.create(
        name="Unz", index="unz-idx", operating_system="Windows", author=admin, status=DUMP_STATUS_UNZIPPING
    )
    processing = Dump.objects.create(name="Proc", index="proc-idx", operating_system="Windows", author=admin, status=1)
    Dump.objects.filter(pk__in=[unzipping.pk, processing.pk]).update(created_at=old_time)

    assert reconcile_stale_tasks(None, max_age_seconds=3600) == 0
    assert reconcile_stale_tasks({"manage_upload-abc"}, max_age_seconds=3600) == 0
    unzipping.refresh_from_db()
    processing.refresh_from_db()
    assert unzipping.status == DUMP_STATUS_UNZIPPING
    assert processing.status == 1  # cluster busy: a long plugin may still be running for it

    assert reconcile_stale_tasks(set(), max_age_seconds=3600) == 2


def test_cancelled_task_keeps_its_failed_state_and_stops_the_feed_sync():
    """A system job killed while running skips the rule import and is not reported Completed afterwards."""
    from orochi.backends.dask import _dask_task_wrapper
    from orochi.ya.models import Ruleset

    feed = Ruleset.objects.create(name="feed", url="https://github.com/example/rules", enabled=True)
    TaskLog.objects.create(task_id="live-yara-1", name="sync_yara_rules", status="Submitted")

    def fake_down(item):
        # The user cancels while the repository is being cloned
        TaskLog.objects.filter(task_id="live-yara-1").update(status="Failed", error="Killed by user")
        return [("/yara/feed/a.yar", feed.pk)]

    with (
        patch("orochi.ya.tasks.down_repo", side_effect=fake_down),
        patch("orochi.ya.tasks.connection"),
        patch("django.db.close_old_connections"),  # the wrapper would close the test transaction's connection
        patch("orochi.ya.tasks.ThreadPool") as pool_cls,
        patch("orochi.ya.tasks.compile_and_commit_block") as compile_block,
    ):
        # Run the pool inline: worker threads would not see this test's uncommitted rows
        pool_cls.return_value.map.side_effect = lambda fn, items: [fn(x) for x in items]
        res = _dask_task_wrapper(
            "orochi.ya.tasks.sync_yara_rules", "live-yara-1", ruleset_id=feed.pk, compile_default=False
        )

    assert "cancelled" in str(res).lower()
    compile_block.assert_not_called()
    assert TaskLog.objects.get(task_id="live-yara-1").status == "Failed"
