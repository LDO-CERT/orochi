import lzma
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError

from orochi.utils.download_symbols import Downloader
from orochi.website.defaults import DUMP_STATUS_COMPLETED, SymbolStatus
from orochi.website.models import Dump
from orochi.website.roles import ROLE_READONLY, set_user_role
from orochi.website.tasks import generate_btf_isf_task

pytestmark = pytest.mark.django_db
User = get_user_model()


def test_downloader_process_btf_kernel():
    """Test Downloader.process_btf_kernel invokes btf2json and writes a compressed ISF archive."""
    with tempfile.TemporaryDirectory() as tmpdir:
        downloader = Downloader()
        downloader.down_path = f"{tmpdir}/"

        fake_btf = os.path.join(tmpdir, "vmlinux.btf")
        with open(fake_btf, "wb") as f:
            f.write(b"\x9f\xeb\x01\x00fake_btf_data")

        fake_map = os.path.join(tmpdir, "System.map-6.8.0")
        with open(fake_map, "w") as f:
            f.write("ffffffff81000000 T _text\n")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b'{"metadata": {"format": "6.2.0"}, "symbols": {"_text": {"address": 0}}}'

        banner = "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-001)"
        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            out_path = downloader.process_btf_kernel(
                btf_path=fake_btf,
                system_map_path=fake_map,
                banner=banner,
                output_name="custom_btf_test.json.xz",
            )

        assert os.path.exists(out_path)
        assert out_path.endswith("custom_btf_test.json.xz")
        with lzma.open(out_path, "rb") as fh:
            assert b'"_text"' in fh.read()

        called_args = mock_run.call_args[0][0]
        assert "--btf" in called_args
        assert fake_btf in called_args
        assert "--map" in called_args
        assert fake_map in called_args
        assert "--banner" in called_args
        assert banner in called_args


def test_run_btf_management_command():
    """Test run_btf management command validation and async enqueue mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_btf = os.path.join(tmpdir, "vmlinux")
        with open(fake_btf, "wb") as f:
            f.write(b"\x9f\xeb")

        with pytest.raises(CommandError, match="BTF file not found"):
            call_command("run_btf", btf="/nonexistent/vmlinux")

        with (
            patch("orochi.website.management.commands.run_btf.wait_for_scheduler", return_value=True),
            patch("orochi.website.management.commands.run_btf.generate_btf_isf_task") as mock_task,
        ):
            mock_res = MagicMock()
            mock_res.id = "task-btf-999"
            mock_task.enqueue.return_value = mock_res

            call_command(
                "run_btf",
                btf=fake_btf,
                banner="Linux version 6.8.0-generic",
                run_async=True,
            )
            mock_task.enqueue.assert_called_once()


def test_generate_btf_isf_task_auto_banner_and_cleanup(admin, settings):
    """Test generate_btf_isf_task auto-fills banner from dump, updates status, and cleans temp uploads."""
    dump = Dump.objects.create(
        index="test_dump_btf_isf",
        name="linux_btf_memory.raw",
        author=admin,
        operating_system="Linux",
        banner="Linux version 6.8.0-45-generic",
    )

    btf_tmp_dir = os.path.join(settings.MEDIA_ROOT, "uploads", "btf")
    os.makedirs(btf_tmp_dir, exist_ok=True)
    fake_btf = os.path.join(btf_tmp_dir, "vmlinux_btf_tmp")
    with open(fake_btf, "wb") as f:
        f.write(b"\x9f\xeb")

    with tempfile.TemporaryDirectory() as tmpdir:
        fake_out = os.path.join(tmpdir, "added_btf_vmlinux.json.xz")
        with open(fake_out, "wb") as f:
            f.write(b"fake_compressed_json")

        with (
            patch.object(Downloader, "process_btf_kernel", return_value=fake_out) as mock_proc,
            patch("orochi.website.symbols_assistant.ensure_symbol_environment"),
            patch("orochi.website.symbols_assistant.distribute_symbols_to_workers", return_value={"worker_count": 2}),
            patch("orochi.utils.volatility_dask_elk.refresh_symbols"),
            patch("orochi.utils.volatility_dask_elk.check_runnable", return_value=True),
            patch("orochi.website.tasks._send_task_notification"),
        ):
            res_msg = generate_btf_isf_task.call(
                btf_path=fake_btf,
                dump_pk=dump.pk,
                user_pk=admin.pk,
            )

            assert "compiled and verified with btf2json" in res_msg
            assert mock_proc.call_args.kwargs["banner"] == "Linux version 6.8.0-45-generic"
            dump.refresh_from_db()
            assert dump.symbol_status == SymbolStatus.OK
            assert dump.status == DUMP_STATUS_COMPLETED
            assert not os.path.exists(fake_btf)


def test_api_btf_generate_json_multipart_and_rbac(client, admin, settings):
    """Test POST /api/symbols/btf_generate for JSON payload, multipart upload, path traversal, and RBAC."""
    # 1. ReadOnly user must receive 403
    ro_user = User.objects.create_user(username="ro_btf_user", password="secret")
    set_user_role(ro_user, ROLE_READONLY)
    client.force_login(ro_user)
    resp_ro = client.post("/api/symbols/btf_generate", data={}, content_type="application/json")
    assert resp_ro.status_code == 403

    # 2. Admin JSON payload + path traversal rejection
    client.force_login(admin)
    uploads_dir = os.path.join(settings.MEDIA_ROOT, "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    btf_file = os.path.join(uploads_dir, "vmlinux-6.8.0.btf")
    map_file = os.path.join(uploads_dir, "System.map-6.8.0")
    with open(btf_file, "wb") as f:
        f.write(b"\x9f\xeb")
    with open(map_file, "w") as f:
        f.write("ffffffff81000000 T _text\n")

    dump = Dump.objects.create(
        index="test_dump_btf_api",
        name="btf_api.raw",
        author=admin,
        operating_system="Linux",
        banner="Linux version 6.8.0-btf",
    )

    with patch("orochi.api.routers.symbols.generate_btf_isf_task") as mock_task:
        mock_res = MagicMock()
        mock_res.id = "task-btf-api-123"
        mock_task.enqueue.return_value = mock_res

        payload = {
            "btf_path": btf_file,
            "system_map_path": map_file,
            "output_name": "linux-6.8.0-btf.json.xz",
            "dump_index": str(dump.index),
        }
        resp = client.post(
            "/api/symbols/btf_generate",
            data=payload,
            content_type="application/json",
        )
        assert resp.status_code == 200, f"Status: {resp.status_code}, Body: {resp.content}"
        assert "task-btf-api-123" in resp.json()["message"]
        mock_task.enqueue.assert_called_once()
        assert mock_task.enqueue.call_args.kwargs["banner"] == "Linux version 6.8.0-btf"

        # Path outside allowed roots must be rejected
        bad_resp = client.post(
            "/api/symbols/btf_generate",
            data={"btf_path": "/etc/passwd"},
            content_type="application/json",
        )
        assert bad_resp.status_code == 400

        # Multipart upload
        mock_task.enqueue.reset_mock()
        fake_btf = SimpleUploadedFile("vmlinux.btf", b"\x9f\xeb\x01\x00")
        fake_map = SimpleUploadedFile("System.map", b"ffffffff81000000 T _text\n")
        resp_mp = client.post(
            "/api/symbols/btf_generate",
            data={
                "btf": fake_btf,
                "system_map": fake_map,
                "dump_index": str(dump.index),
                "output_name": "mp_btf.json.xz",
            },
        )
        assert resp_mp.status_code == 200, resp_mp.content
        mock_task.enqueue.assert_called_once()
        assert mock_task.enqueue.call_args.kwargs["banner"] == "Linux version 6.8.0-btf"
        assert os.path.exists(mock_task.enqueue.call_args.kwargs["btf_path"])
        assert os.path.exists(mock_task.enqueue.call_args.kwargs["system_map_path"])
