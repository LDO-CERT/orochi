import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from orochi.utils.download_symbols import Downloader, download_symbols
from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
)
from orochi.website.models import Result, SymbolStatus
from orochi.website.symbols_assistant import auto_resolve_symbols
from orochi.website.tasks import download_symbols_task

pytestmark = pytest.mark.django_db


def test_downloader_dwarf2json_failure():
    """Verify Downloader.process_files raises errors on dwarf2json failure."""
    d = Downloader()

    # 1. Test None value in named files raises ValueError
    with pytest.raises(ValueError, match="Failed to extract kernel binaries"):
        d.process_files({"pkg.deb": None})

    # 2. Test non-zero returncode raises RuntimeError
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stderr = b"kernel symbols mismatch"
    mock_proc.stdout = b""

    with patch("subprocess.run", return_value=mock_proc):
        with pytest.raises(RuntimeError, match="dwarf2json failed"):
            d.process_files({"vmlinux": "/tmp/fake_vmlinux"})

    # 3. Test empty stdout raises RuntimeError
    mock_proc_ok = MagicMock()
    mock_proc_ok.returncode = 0
    mock_proc_ok.stderr = b""
    mock_proc_ok.stdout = b""

    with patch("subprocess.run", return_value=mock_proc_ok):
        with pytest.raises(RuntimeError, match="empty output"):
            d.process_files({"vmlinux": "/tmp/fake_vmlinux"})


def test_download_symbols_convenience_function():
    """Verify download_symbols() top-level helper function."""
    with patch.object(Downloader, "download_list") as mock_dl, patch.object(Downloader, "process_list") as mock_pl:
        # Url list
        download_symbols(url_list=["https://example.com/kernel-dbg.deb"])
        mock_dl.assert_called_once()

        # File list
        download_symbols(file_list=[("/tmp/file.deb", "file.deb")])
        mock_pl.assert_called_once()


def test_download_symbols_task_success(admin, dump, plugin):
    """Verify download_symbols_task execution and dump updates."""
    # Setup dump with disabled result
    dump.operating_system = "Linux"
    dump.symbol_status = SymbolStatus.MISSING
    dump.save()

    res = Result.objects.create(
        dump=dump,
        plugin=plugin,
        result=RESULT_STATUS_DISABLED,
    )

    with (
        patch("orochi.utils.download_symbols.Downloader.download_list") as mock_dl,
        patch("orochi.website.symbols_assistant.distribute_symbols_to_workers") as mock_dist,
        patch("orochi.utils.volatility_dask_elk.check_runnable", return_value=True) as mock_chk,
        patch("orochi.website.tasks._send_task_notification") as mock_notify,
    ):
        msg = download_symbols_task.call(
            url_list=["https://example.com/pkg.deb"],
            dump_pk=dump.pk,
            user_pk=admin.pk,
        )

        mock_dl.assert_called_once()
        mock_dist.assert_called_once()
        mock_chk.assert_called_once()

        # Dump status and results should be updated
        dump.refresh_from_db()
        assert dump.status == DUMP_STATUS_COMPLETED
        assert dump.symbol_status == SymbolStatus.OK

        res.refresh_from_db()
        assert res.result == RESULT_STATUS_NOT_STARTED

        # Notification sent to user
        mock_notify.assert_called()
        assert "compiled and verified successfully" in msg


def test_download_symbols_task_file_cleanup(admin):
    """Verify temporary files in file_list are unlinked upon task completion."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"dummy package content")
        temp_path = f.name

    assert os.path.exists(temp_path)

    with (
        patch("orochi.utils.download_symbols.Downloader.process_list") as mock_pl,
        patch("orochi.website.symbols_assistant.distribute_symbols_to_workers"),
        patch("orochi.website.tasks._send_task_notification"),
    ):
        download_symbols_task.call(
            file_list=[(temp_path, "test.deb")],
            user_pk=admin.pk,
        )

        mock_pl.assert_called_once()
        # Temp file cleaned up
        assert not os.path.exists(temp_path)


def test_download_symbols_task_failure(admin, dump):
    """Verify task failure triggers notification and re-raises exception."""
    with (
        patch(
            "orochi.utils.download_symbols.Downloader.download_list",
            side_effect=RuntimeError("Simulated dwarf2json crash"),
        ),
        patch("orochi.website.tasks._send_task_notification") as mock_notify,
    ):
        with pytest.raises(RuntimeError, match="Simulated dwarf2json crash"):
            download_symbols_task.call(
                url_list=["https://example.com/pkg.deb"],
                dump_pk=dump.pk,
                user_pk=admin.pk,
            )

        # Notification sent with failure details
        mock_notify.assert_called()
        call_args = mock_notify.call_args[0]
        assert "Symbol Task Failed" in call_args[1]
        assert "Simulated dwarf2json crash" in call_args[2]


def test_auto_resolve_symbols_async(admin, dump):
    """Verify auto_resolve_symbols enqueues Dask task when async_task is True."""
    dump.operating_system = "Linux"
    dump.suggested_symbols_path = ["https://example.com/kernel-dbg.deb"]
    dump.save()

    with patch("django.tasks.base.Task.enqueue") as mock_enqueue:
        mock_task_res = MagicMock()
        mock_task_res.id = "mock-dask-task-uuid"
        mock_enqueue.return_value = mock_task_res

        res = auto_resolve_symbols(dump, async_task=True, user=admin)
        assert res["success"] is True
        assert res["task_id"] == "mock-dask-task-uuid"
        mock_enqueue.assert_called_once()
        assert mock_enqueue.call_args.kwargs.get("dump_pk") == dump.pk


def test_api_banner_symbols_enqueues_task(client, admin, dump):
    """Verify POST /api/symbols/banner enqueues Dask task."""
    client.force_login(admin)

    with patch("django.tasks.base.Task.enqueue") as mock_enqueue:
        mock_task_res = MagicMock()
        mock_task_res.id = "mock-task-uuid"
        mock_enqueue.return_value = mock_task_res

        resp = client.post(
            "/api/symbols/banner",
            {
                "index": str(dump.index),
                "path": ["https://example.com/kernel.deb"],
                "operating_system": "Linux",
            },
            content_type="application/json",
        )

        assert resp.status_code == 200
        assert "queued successfully" in resp.json()["message"]
        mock_enqueue.assert_called_once()


def test_api_dump_auto_resolve_enqueues_task(client, admin, dump):
    """Verify POST /api/dumps/{pk}/symbols/auto-resolve calls auto_resolve_symbols."""
    from guardian.shortcuts import assign_perm

    assign_perm("website.can_see", admin, dump)
    client.force_login(admin)
    dump.operating_system = "Linux"
    dump.suggested_symbols_path = ["https://example.com/kernel.deb"]
    dump.save()

    with patch("django.tasks.base.Task.enqueue") as mock_enqueue:
        mock_task_res = MagicMock()
        mock_task_res.id = "mock-task-uuid"
        mock_enqueue.return_value = mock_task_res

        resp = client.post(
            f"/api/dumps/{dump.index}/symbols/auto-resolve",
            {},
            content_type="application/json",
        )

        assert resp.status_code == 200
        mock_enqueue.assert_called_once()
