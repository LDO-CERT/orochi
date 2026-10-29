import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError

from orochi.utils.download_symbols import Downloader
from orochi.website.defaults import DUMP_STATUS_COMPLETED, SymbolStatus
from orochi.website.models import Dump
from orochi.website.tasks import generate_dwarf_isf_task

pytestmark = pytest.mark.django_db
User = get_user_model()


def test_downloader_process_raw_kernel():
    """Test Downloader.process_raw_kernel creates a compressed ISF archive."""
    with tempfile.TemporaryDirectory() as tmpdir:
        downloader = Downloader()
        downloader.down_path = f"{tmpdir}/"

        fake_elf = os.path.join(tmpdir, "vmlinux-5.15.0")
        with open(fake_elf, "wb") as f:
            f.write(b"\x7fELFfake_kernel_binary")

        fake_map = os.path.join(tmpdir, "System.map-5.15.0")
        with open(fake_map, "w") as f:
            f.write("0000000000000000 T startup_64\n")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b'{"symbols": {"startup_64": 0}}'

        with patch("subprocess.run", return_value=mock_proc):
            out_path = downloader.process_raw_kernel(
                elf_path=fake_elf,
                system_map_path=fake_map,
                output_name="custom_linux_test.json.xz",
            )

        assert os.path.exists(out_path)
        assert out_path.endswith("custom_linux_test.json.xz")


def test_run_dwarf_management_command():
    """Test run_dwarf management command synchronous and asynchronous modes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_elf = os.path.join(tmpdir, "vmlinux")
        with open(fake_elf, "wb") as f:
            f.write(b"\x7fELF")

        # 1. Error on nonexistent ELF
        with pytest.raises(CommandError, match="Kernel ELF file not found"):
            call_command("run_dwarf", elf="/nonexistent/vmlinux")

        # 2. Async queue mode
        with patch("orochi.website.management.commands.run_dwarf.generate_dwarf_isf_task") as mock_task:
            mock_res = MagicMock()
            mock_res.id = "task-dwarf-999"
            mock_task.enqueue.return_value = mock_res

            call_command("run_dwarf", elf=fake_elf, run_async=True)
            mock_task.enqueue.assert_called_once()


def test_generate_dwarf_isf_task(admin):
    """Test generate_dwarf_isf_task executes and updates dump status."""
    dump = Dump.objects.create(
        index="test_dump_dwarf_isf",
        name="linux_memory.raw",
        author=admin,
        operating_system="Linux",
        banner="Linux version 5.15.0-generic",
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        fake_elf = os.path.join(tmpdir, "vmlinux")
        with open(fake_elf, "wb") as f:
            f.write(b"\x7fELF")

        fake_out = os.path.join(tmpdir, "added_vmlinux.json.xz")
        with open(fake_out, "wb") as f:
            f.write(b"fake_compressed_json")

        with (
            patch.object(Downloader, "process_raw_kernel", return_value=fake_out),
            patch("orochi.website.symbols_assistant.ensure_symbol_environment"),
            patch("orochi.website.symbols_assistant.distribute_symbols_to_workers", return_value={"worker_count": 2}),
            patch("orochi.utils.volatility_dask_elk.refresh_symbols"),
            patch("orochi.utils.volatility_dask_elk.check_runnable", return_value=True),
            patch("orochi.website.tasks._send_task_notification"),
        ):
            res_msg = generate_dwarf_isf_task.call(
                elf_path=fake_elf,
                dump_pk=dump.pk,
                user_pk=admin.pk,
            )

            assert "compiled and verified" in res_msg
            dump.refresh_from_db()
            assert dump.symbol_status == SymbolStatus.OK
            assert dump.status == DUMP_STATUS_COMPLETED


def test_api_dwarf_generate(client, admin):
    """Test POST /api/symbols/dwarf_generate API endpoint."""
    client.force_login(admin)

    with patch("orochi.api.routers.symbols.generate_dwarf_isf_task") as mock_task:
        mock_res = MagicMock()
        mock_res.id = "task-dwarf-api-123"
        mock_task.enqueue.return_value = mock_res

        payload = {
            "elf_path": "/media/uploads/vmlinux-5.15.0",
            "system_map_path": "/media/uploads/System.map-5.15.0",
            "output_name": "linux-5.15.0.json.xz",
        }
        resp = client.post(
            "/api/symbols/dwarf_generate",
            data=payload,
            content_type="application/json",
        )
        assert resp.status_code == 200, f"Status: {resp.status_code}, Body: {resp.content}"
        assert "task-dwarf-api-123" in resp.json()["message"]
        mock_task.enqueue.assert_called_once()
