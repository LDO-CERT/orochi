"""Result history across re-runs, playbooks and retries (#1674 FR-4, FR-5, FR-8)."""

import gzip
import json
from unittest.mock import MagicMock, patch

import pytest
from django.urls import reverse

from orochi.utils.volatility_dask_elk import run_plugin
from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Plugin, Result, ResultRun, Value
from orochi.website.result_history import archive_and_clear, canonical_rows_hash, read_snapshot

pytestmark = pytest.mark.django_db


def _run(dump, plugin, rows, tmp_path, user_pk=None, params=None):
    """Run ``plugin`` through the real run_plugin with Volatility mocked to return ``rows``."""
    fake_file = tmp_path / "sample.raw"
    fake_file.write_bytes(b"\x00" * 64)
    isf = tmp_path / "kernel.json.xz"
    isf.write_bytes(b"isf")
    constructed = MagicMock()
    constructed.build_configuration.return_value = {"kernel.symbol_table_name.isf_url": f"file://{isf}"}
    with (
        patch("orochi.utils.volatility_dask_elk.close_old_connections"),
        patch("orochi.website.storage.ensure_local_dump_path", return_value=str(fake_file)),
        patch("orochi.utils.volatility_dask_elk.plugins.construct_plugin", return_value=constructed),
        patch("orochi.utils.volatility_dask_elk.ReturnJsonRenderer.render", return_value=(rows, None)),
        patch("orochi.website.tasks.index_result_values_task", MagicMock()),
    ):
        run_plugin(dump, plugin, params=params, user_pk=user_pk)
    return Result.objects.get(dump=dump, plugin=plugin)


@pytest.fixture
def cmdline(db):
    return Plugin.objects.get_or_create(name="windows.cmdline.CmdLine", defaults={"operating_system": "Windows"})[0]


def test_each_run_is_recorded_and_previous_rows_are_archived(dump, admin, cmdline, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    first = [{"PID": i, "Args": f"first {i}", "__children": []} for i in range(3)]
    second = [{"PID": 9, "Args": "second", "__children": []}]

    result = _run(dump, cmdline, first, tmp_path, user_pk=admin.pk, params={"pid": [4]})
    run1 = result.runs.get()
    assert (run1.number, run1.status, run1.row_count, run1.user) == (1, RESULT_STATUS_SUCCESS, 3, admin)
    assert run1.rows_sha256 == canonical_rows_hash(first)[0]
    assert run1.volatility_version and run1.plugin_version  # tool versions (FR-5)
    assert run1.parameters == {"pid": [4]} and run1.started_at and run1.finished_at
    assert run1.symbols[0]["isf_url"].endswith("kernel.json.xz") and run1.symbols[0]["sha256"]

    result = _run(dump, cmdline, second, tmp_path, user_pk=admin.pk)
    run1.refresh_from_db()
    assert list(Value.objects.filter(result=result).values_list("value", flat=True)) == second
    assert result.runs.count() == 2 and run1.has_snapshot
    archived = list(read_snapshot(run1))
    assert archived == first
    assert canonical_rows_hash(archived)[0] == run1.rows_sha256  # the archive is the run's rows, unaltered


def test_rows_from_before_history_are_archived_too(dump, cmdline, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    result = Result.objects.create(dump=dump, plugin=cmdline, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=result, value={"PID": 1})
    run = archive_and_clear(result, reason="re-run")
    assert run.reason == "before history" and run.row_count == 1 and run.has_snapshot
    assert not Value.objects.filter(result=result).exists()


def test_playbook_keeps_completed_results_unless_forced(dump, admin, tmp_path, settings):
    from orochi.website.playbooks import PLAYBOOKS
    from orochi.website.tasks import run_playbook_task

    settings.MEDIA_ROOT = str(tmp_path)
    dump.operating_system = "Linux"
    dump.save()
    pb_id, pb = next((k, v) for k, v in PLAYBOOKS.items() if v["operating_system"] == "Linux")
    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", defaults={"operating_system": "Linux"})
    result = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=result, value={"PID": 1})
    with (
        patch("orochi.website.playbooks.resolve_playbook_plugins", return_value=[plugin]),
        patch("orochi.api.routers.dumps.plugin_f_and_f") as launch,
        patch("orochi.website.tasks.evaluate_dump_triage"),
    ):
        kept = run_playbook_task.call(dump.pk, pb_id, user_pk=admin.pk)
        launch.assert_not_called()
        assert kept["kept_plugins"] == ["linux.pslist.PsList"]
        assert Value.objects.filter(result=result).count() == 1

        forced = run_playbook_task.call(dump.pk, pb_id, user_pk=admin.pk, force=True)
    assert forced["launched_plugins"] == ["linux.pslist.PsList"]
    assert not Value.objects.filter(result=result).exists()
    assert result.runs.get().has_snapshot  # replaced rows went to the history


def test_history_modal_download_and_delete(client, admin, dump, cmdline, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    first = [{"PID": 1, "__children": []}]
    _run(dump, cmdline, first, tmp_path, user_pk=admin.pk)
    _run(dump, cmdline, [{"PID": 2, "__children": []}], tmp_path, user_pk=admin.pk)
    run1 = ResultRun.objects.get(number=1)
    client.force_login(admin)

    html = client.get(
        reverse("website:result_history"), {"indexes[]": dump.index, "plugin": cmdline.name}
    ).content.decode()
    assert 'data-run="1"' in html and 'data-run="2"' in html
    assert reverse("website:result_run_snapshot", kwargs={"run_id": run1.pk}) in html

    resp = client.get(reverse("website:result_run_snapshot", kwargs={"run_id": run1.pk}))
    rows = [json.loads(line) for line in gzip.decompress(b"".join(resp.streaming_content)).decode().splitlines()]
    assert rows == first and resp["X-Rows-SHA256"] == run1.rows_sha256

    client.post(reverse("website:result_run_snapshot_delete", kwargs={"run_id": run1.pk}), HTTP_HX_REQUEST="true")
    run1.refresh_from_db()
    assert not run1.has_snapshot and run1.snapshot_deleted_by == admin
    assert ResultRun.objects.filter(pk=run1.pk).exists()  # the record stays for custody


def test_history_api_and_permissions(client, admin, user, dump, cmdline, tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    _run(dump, cmdline, [{"PID": 1, "__children": []}], tmp_path, user_pk=admin.pk)
    _run(dump, cmdline, [{"PID": 2, "__children": []}], tmp_path, user_pk=admin.pk)
    client.force_login(admin)
    base = f"/api/dumps/{dump.index}/plugin/{cmdline.name}/runs"
    runs = client.get(base).json()
    assert [r["number"] for r in runs] == [2, 1] and runs[1]["has_snapshot"]
    assert client.get(f"{base}/1/snapshot").status_code == 200
    assert client.delete(f"{base}/1/snapshot").status_code == 200
    assert client.get(f"{base}/1/snapshot").status_code == 404

    client.force_login(user)  # cannot see the dump
    assert client.get(base).status_code == 404
    run2 = ResultRun.objects.get(number=2)
    assert client.get(reverse("website:result_run_snapshot", kwargs={"run_id": run2.pk})).status_code == 404


def test_reexecute_api_archives_instead_of_deleting(client, admin, dump, cmdline, tmp_path, settings):
    from orochi.website.models import UserPlugin

    settings.MEDIA_ROOT = str(tmp_path)
    _run(dump, cmdline, [{"PID": 1, "__children": []}], tmp_path, user_pk=admin.pk)
    UserPlugin.objects.get_or_create(user=admin, plugin=cmdline)
    client.force_login(admin)
    with patch("orochi.api.routers.dumps.plugin_f_and_f"):
        resp = client.post(
            f"/api/dumps/{dump.index}/plugin/{cmdline.name}/execute", data="{}", content_type="application/json"
        )
    assert resp.status_code == 200, resp.content
    assert ResultRun.objects.get(number=1).has_snapshot


def test_report_appendix_lists_the_last_run_tools_and_symbols(admin, dump, cmdline, tmp_path, settings):
    """#1540: the technical appendix states who ran each plugin, with which versions and symbol tables."""
    from orochi.website.case_reporting import export_case_to_markdown
    from orochi.website.models import Case, Evidence

    settings.MEDIA_ROOT = str(tmp_path)
    _run(dump, cmdline, [{"PID": 1, "__children": []}], tmp_path, user_pk=admin.pk)
    case = Case.objects.create(name="Appendix", user=admin)
    Evidence.objects.create(case=case, dump=dump, plugin=cmdline.name, name="row")
    md = export_case_to_markdown(case)
    appendix = md[md.index("## Technical Appendix") :]
    run = ResultRun.objects.get()
    assert "#1 " in appendix and f"by {admin.username}" in appendix
    assert f"Volatility {run.volatility_version}" in appendix and "kernel.json.xz" in appendix
