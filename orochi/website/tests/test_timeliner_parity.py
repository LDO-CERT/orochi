"""Regression tests for Issue #1556: Timeliner row parity with Volatility 3 CLI."""

import datetime
import io
import json
from collections import Counter
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import pytest
import volatility3.plugins
from volatility3 import framework
from volatility3.cli.text_renderer import JsonRenderer
from volatility3.framework import renderers
from volatility3.plugins.timeliner import Timeliner

from orochi.utils.volatility_dask_elk import ReturnJsonRenderer, run_plugin
from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Plugin, Result, Value

pytestmark = pytest.mark.django_db


def _build_sample_timeliner_grid() -> renderers.TreeGrid:
    """Create a synthetic Timeliner TreeGrid containing PsScan, PsList, and MFTScan rows."""
    t0 = datetime.datetime(2025, 1, 15, 12, 0, 0, tzinfo=datetime.UTC)
    rows = [
        (
            0,
            (
                "PsScan",
                "Process: 4 (System)",
                t0,
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
            ),
        ),
        (
            0,
            (
                "PsScan",
                "Process: 612 (lsass.exe)",
                t0,
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
            ),
        ),
        (
            0,
            (
                "PsList",
                "Process: 4 (System)",
                t0,
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
            ),
        ),
        (
            0,
            (
                "PsList",
                "Process: 1337 (cmd.exe)",
                t0,
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
            ),
        ),
        (0, ("MFTScan", "MFT FILE_NAME: C:\\Windows\\System32\\cmd.exe", t0, t0, t0, t0)),
    ]
    return renderers.TreeGrid(
        columns=[
            ("Plugin", str),
            ("Description", str),
            ("Created Date", datetime.datetime),
            ("Modified Date", datetime.datetime),
            ("Accessed Date", datetime.datetime),
            ("Changed Date", datetime.datetime),
        ],
        generator=iter(rows),
    )


def test_timeliner_return_json_renderer_matches_cli_json_renderer_per_source():
    """Differential test (#1556): ReturnJsonRenderer produces the exact same per-source counts as Volatility CLI."""
    orochi_rows, error = ReturnJsonRenderer().render(_build_sample_timeliner_grid())
    assert error is None

    buf = io.StringIO()
    with redirect_stdout(buf):
        JsonRenderer().render(_build_sample_timeliner_grid())
    cli_rows = json.loads(buf.getvalue())

    orochi_counts = Counter(r["Plugin"] for r in orochi_rows)
    cli_counts = Counter(r["Plugin"] for r in cli_rows)

    assert orochi_counts == cli_counts
    assert orochi_counts["PsScan"] == 2
    assert orochi_counts["PsList"] == 2
    assert orochi_counts["MFTScan"] == 1


def test_timeliner_usable_plugins_include_psscan_and_pslist():
    """AC (#1556): Default Timeliner usable plugins include both PsScan and PsList."""
    framework.import_files(volatility3.plugins, True)
    usable = Timeliner.get_usable_plugins()
    names = {f"{cls.__module__}.{cls.__name__}" for cls in usable}
    assert "volatility3.plugins.windows.psscan.PsScan" in names
    assert "volatility3.plugins.windows.pslist.PsList" in names


def test_run_plugin_timeliner_does_not_inject_synthetic_plugin_filter_and_stores_psscan(dump, tmp_path):
    """Regression test (#1556): run_plugin does not inject synthetic plugin_filter and stores PsScan rows."""
    fake_file = tmp_path / "sample.raw"
    fake_file.write_bytes(b"\x00" * 64)
    plugin_obj, _ = Plugin.objects.get_or_create(
        name="timeliner.Timeliner",
        defaults={"operating_system": "Other"},
    )

    captured_config = {}
    fake_constructed = MagicMock()
    fake_constructed.run.return_value = _build_sample_timeliner_grid()
    fake_constructed.build_configuration.return_value = {}

    def _fake_construct(ctx, *args, **kwargs):
        captured_config.update(dict(ctx.config))
        return fake_constructed

    with (
        patch("orochi.utils.volatility_dask_elk.close_old_connections"),
        patch("orochi.website.storage.ensure_local_dump_path", return_value=str(fake_file)),
        patch("orochi.utils.volatility_dask_elk.plugins.construct_plugin", side_effect=_fake_construct),
        patch("orochi.website.tasks.index_result_values_task", MagicMock()),
    ):
        run_plugin(dump, plugin_obj, params=None)

    assert not any("plugin_filter" in k or "plugin-filter" in k for k in captured_config)

    res = Result.objects.get(dump=dump, plugin=plugin_obj)
    assert res.result == RESULT_STATUS_SUCCESS
    stored_plugins = Counter(v.value["Plugin"] for v in Value.objects.filter(result=res))
    assert stored_plugins["PsScan"] == 2
    assert stored_plugins["PsList"] == 2
    assert stored_plugins["MFTScan"] == 1


def test_orochi_does_not_import_volshell_before_the_plugins_load():
    """Root cause of #1556 found live: importing volatility3.cli.volshell (for NullFileHandler) before the plugins
    are loaded broke Timeliner's automagic for PsScan, dropping all its rows and one PsList row per process."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    code = (
        "import os, sys, django; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test'); django.setup();"
        "import orochi.utils.volatility_dask_elk as v;"
        "print(any(m.startswith('volatility3.cli.volshell') for m in sys.modules));"
        "h = v.NullFileHandler('x.bin'); print(h.write(b'abc'))"
    )
    env = {k: os.environ[k] for k in ("PATH", "HOME", "DATABASE_URL") if k in os.environ}
    env["DJANGO_READ_DOT_ENV_FILE"] = "False"
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[3],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.returncode == 0, out.stderr[-500:]
    assert out.stdout.split() == ["False", "3"]
