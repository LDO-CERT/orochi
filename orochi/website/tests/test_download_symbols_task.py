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


def test_downloader_process_list_vmlinux_and_system_map_and_exe(tmp_path, monkeypatch):
    """
    Verify Downloader.process_list correctly passes --elf for vmlinux and --system-map for System.map
    to dwarf2json, and handles Windows PE (.exe -> PDB -> JSON) extraction.
    """
    d = Downloader()
    d.down_path = f"{tmp_path}/"

    vmlinux_file = tmp_path / "vmlinux-6.1.0-generic"
    sysmap_file = tmp_path / "System.map-6.1.0-generic"
    vmlinux_file.write_bytes(b"\x7fELF_fake_kernel")
    sysmap_file.write_text("ffffffff81000000 T _text\n")

    captured_cmd = []

    def fake_run(args, capture_output=True, check=False):
        captured_cmd.extend(args)
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = b'{"symbols": {"_text": 0}}'
        proc.stderr = b""
        return proc

    monkeypatch.setattr("orochi.utils.download_symbols.subprocess.run", fake_run)
    d.file_list = [
        (str(vmlinux_file), "vmlinux-6.1.0-generic"),
        (str(sysmap_file), "System.map-6.1.0-generic"),
    ]
    d.process_list()

    # Must contain one --elf and one --system-map flag
    assert "--elf" in captured_cmd, captured_cmd
    assert "--system-map" in captured_cmd, captured_cmd
    assert len(d.created_symbols) == 1
    assert os.path.exists(d.created_symbols[0])

    # Test Windows PE process_exe with mocked PE & PdbRetreiver/PdbReader
    class FakeDebugEntry:
        Signature_Data1 = 0x11223344
        Signature_Data2 = 0x5566
        Signature_Data3 = 0x7788
        Signature_Data4 = 0x09
        Signature_Data5 = 0x0A
        Signature_Data6 = b"\xbc\xde\xf0\x12\x34\x56"
        Age = 1
        PdbFileName = b"ntkrnlmp.pdb\x00"

    class FakeDirDebug:
        entry = FakeDebugEntry()

    class FakePE:
        def __init__(self, path):
            self.DIRECTORY_ENTRY_DEBUG = [FakeDirDebug()]

    class FakePdbReader:
        def __init__(self, ctx, filename):
            pass

        def get_json(self):
            return {"metadata": {"producer": "pdbconv"}, "symbols": {}}

    monkeypatch.setattr("orochi.utils.download_symbols.PE", FakePE)
    monkeypatch.setattr(
        "orochi.utils.download_symbols.PdbRetreiver.retreive_pdb",
        lambda self, guid, file_name, progress_callback=None: "/tmp/fake.pdb",
    )
    monkeypatch.setattr("orochi.utils.download_symbols.PdbReader", FakePdbReader)

    exe_path = tmp_path / "ntoskrnl.exe"
    exe_path.write_bytes(b"MZ_fake_pe")
    out_pdb_json = d.process_exe(str(exe_path))
    assert out_pdb_json is not None
    assert os.path.exists(out_pdb_json)
    assert out_pdb_json.endswith("1122334455667788090ABCDEF01234561.json")


def test_symbols_api_upload_isf_download_packages_and_delete(client, admin, settings, tmp_path, monkeypatch):
    """
    End-to-end test for:
    - POST /api/symbols/upload (direct .json, .json.xz, invalid JSON rejection, and multi-file staged payload)
    - POST /api/symbols/upload_packages (multi-file staged payload + direct multipart)
    - POST /api/symbols/isf_download (JSON payload & form payload)
    - POST /api/symbols/dwarf_generate (multipart upload of elf + system_map)
    - DELETE /api/symbols/delete
    - GET /api/symbols/diagnostics & POST /api/symbols/sync_workers
    """
    import json
    import lzma

    from django.core.files.uploadedfile import SimpleUploadedFile

    client.force_login(admin)
    sym_root = tmp_path / "symbols_store"
    (sym_root / "added").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("extra_settings.models.Setting.get", lambda key, *a, **kw: str(sym_root))
    monkeypatch.setattr("orochi.api.routers.symbols.refresh_symbols", lambda: None)

    # 1. Direct multipart upload of valid .json and .json.xz ISF files
    valid_isf = json.dumps({"metadata": {}, "symbols": {}, "base_types": {}}).encode("utf-8")
    valid_isf_xz = lzma.compress(valid_isf)
    f1 = SimpleUploadedFile("custom_win.json", valid_isf, content_type="application/json")
    f2 = SimpleUploadedFile("custom_linux.json.xz", valid_isf_xz, content_type="application/x-xz")
    resp_up = client.post("/api/symbols/upload", data={"symbols": [f1, f2]})
    assert resp_up.status_code == 200, resp_up.json()
    assert (sym_root / "added" / "custom_win.json").exists()
    assert (sym_root / "added" / "custom_linux.json.xz").exists()

    # 2. Invalid ISF file is rejected and deleted
    bad_f = SimpleUploadedFile("corrupt.json", b"not-a-json-object", content_type="application/json")
    resp_bad = client.post("/api/symbols/upload", data={"symbols": [bad_f]})
    assert resp_bad.status_code == 400
    assert not (sym_root / "added" / "corrupt.json").exists()

    # 3. Staged multi-file upload via payload (simulating django-file-form /media/tmp/<id>)
    tmp_stage_dir = os.path.join(settings.MEDIA_ROOT, "tmp")
    os.makedirs(tmp_stage_dir, exist_ok=True)
    staged_1 = os.path.join(tmp_stage_dir, "stage_id_1")
    staged_2 = os.path.join(tmp_stage_dir, "stage_id_2")
    with open(staged_1, "wb") as fh:
        fh.write(valid_isf)
    with open(staged_2, "wb") as fh:
        fh.write(valid_isf_xz)

    staged_payload = {
        "info": [
            {"local_folder": "/media/tmp/stage_id_1", "original_name": "staged_one.json"},
            {"local_folder": "/media/tmp/stage_id_2", "original_name": "staged_two.json.xz"},
        ]
    }
    resp_staged = client.post(
        "/api/symbols/upload",
        data=json.dumps(staged_payload),
        content_type="application/json",
    )
    assert resp_staged.status_code == 200, resp_staged.json()
    assert (sym_root / "added" / "staged_one.json").exists()
    assert (sym_root / "added" / "staged_two.json.xz").exists()

    # 4. POST /api/symbols/upload_packages with multi-file staged payload (vmlinux + System.map)
    pkg_1 = os.path.join(tmp_stage_dir, "pkg_vmlinux_id")
    pkg_2 = os.path.join(tmp_stage_dir, "pkg_sysmap_id")
    with open(pkg_1, "wb") as fh:
        fh.write(b"\x7fELF")
    with open(pkg_2, "w") as fh:
        fh.write("ffffffff81000000 T _text\n")

    enqueued_files = []

    class FakeDownloadTask:
        @staticmethod
        def enqueue(file_list=None, user_pk=None, **kw):
            enqueued_files.extend(file_list or [])

    monkeypatch.setattr("orochi.api.routers.symbols.download_symbols_task", FakeDownloadTask)
    pkg_payload = {
        "info": [
            {"local_folder": "/media/tmp/pkg_vmlinux_id", "original_name": "vmlinux-5.15.0"},
            {"local_folder": "/media/tmp/pkg_sysmap_id", "original_name": "System.map-5.15.0"},
        ]
    }
    resp_pkg = client.post(
        "/api/symbols/upload_packages",
        data=json.dumps(pkg_payload),
        content_type="application/json",
    )
    assert resp_pkg.status_code == 200, resp_pkg.json()
    assert len(enqueued_files) == 2
    assert [name for _, name in enqueued_files] == ["vmlinux-5.15.0", "System.map-5.15.0"]

    # 5. POST /api/symbols/dwarf_generate with multipart uploaded elf and system_map
    dwarf_calls = []

    class FakeDwarfTaskRes:
        id = "dwarf-multipart-777"

    class FakeDwarfTask:
        @staticmethod
        def enqueue(**kw):
            dwarf_calls.append(kw)
            return FakeDwarfTaskRes()

    monkeypatch.setattr("orochi.api.routers.symbols.generate_dwarf_isf_task", FakeDwarfTask)
    elf_up = SimpleUploadedFile("vmlinux-arm64", b"\x7fELF_arm64")
    map_up = SimpleUploadedFile("System.map-arm64", b"ffffffc008000000 T _text\n")
    resp_dwarf = client.post(
        "/api/symbols/dwarf_generate",
        data={"elf": elf_up, "system_map": map_up, "output_name": "arm64_custom.json.xz"},
    )
    assert resp_dwarf.status_code == 200, resp_dwarf.json()
    assert len(dwarf_calls) == 1
    assert dwarf_calls[0]["output_name"] == "arm64_custom.json.xz"
    assert os.path.exists(dwarf_calls[0]["elf_path"])
    assert os.path.exists(dwarf_calls[0]["system_map_path"])

    # 6. POST /api/symbols/isf_download downloads manifest and symbol files
    monkeypatch.setattr("orochi.api.routers.symbols.validate_public_https_url", lambda u: u)

    class FakeISFManifestResp:
        def __init__(self, content):
            self.content = content

    def fake_isf_get(url, timeout=60):
        if url.endswith("banners.json"):
            manifest = {"linux": {"banner1": ["https://isf.example.com/linux/test_kernel.json.xz"]}}
            return FakeISFManifestResp(json.dumps(manifest).encode("utf-8"))
        return FakeISFManifestResp(valid_isf_xz)

    monkeypatch.setattr("orochi.api.routers.symbols.requests.get", fake_isf_get)
    resp_isf = client.post(
        "/api/symbols/isf_download",
        data=json.dumps({"path": "https://isf.example.com/banners.json"}),
        content_type="application/json",
    )
    assert resp_isf.status_code == 200, resp_isf.json()
    assert (sym_root / "isfexamplecom" / "test_kernel.json.xz").exists()

    # 7. DELETE /api/symbols/delete removes file from added/
    resp_del = client.delete("/api/symbols/delete?path=/added/custom_win.json")
    assert resp_del.status_code == 200, resp_del.json()
    assert not (sym_root / "added" / "custom_win.json").exists()

    # 8. GET /api/symbols/diagnostics & POST /api/symbols/sync_workers
    resp_diag = client.get("/api/symbols/diagnostics")
    assert resp_diag.status_code == 200
    assert "pe_lookup_operational" in resp_diag.json()

    monkeypatch.setattr(
        "orochi.website.symbols_assistant.distribute_symbols_to_workers",
        lambda: {"worker_count": 2},
    )
    resp_sync = client.post("/api/symbols/sync_workers")
    assert resp_sync.status_code == 200
    assert "2 workers" in resp_sync.json()["message"]
