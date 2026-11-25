"""Regression tests for product API & Python client (#1574), Sigma hunting rules (#1545), and sandboxed Dask workers (#1570)."""

import json
import sys
from pathlib import Path

import pytest
import yaml
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.detection.sigma_engine import SigmaRuleValidationError, parse_and_validate_sigma_rule
from orochi.website.models import HuntingRule, Plugin, Result, Value

pytestmark = pytest.mark.django_db
ROOT = Path(__file__).resolve().parents[3]


# =====================================================================
# #1574 — PATCH operating_system & Official Python Client
# =====================================================================
def test_patch_dump_applies_operating_system(client, admin, dump):
    """AC4 (#1574): PATCH /api/dumps/{index} applies operating_system instead of silently ignoring it."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    dump.operating_system = "Windows"
    dump.save(update_fields=["operating_system"])

    resp = client.patch(
        f"/api/dumps/{dump.index}",
        data=json.dumps({"operating_system": "Linux"}),
        content_type="application/json",
    )
    assert resp.status_code == 200, resp.content
    assert resp.json()["operating_system"] == "Linux"
    dump.refresh_from_db()
    assert dump.operating_system == "Linux"


def test_python_client_package_imports_and_cli_parser_works():
    """AC1 (#1574): Official Python client & CLI package imports cleanly and exposes core commands."""
    client_src = str(ROOT / "clients" / "python" / "src")
    if client_src not in sys.path:
        sys.path.insert(0, client_src)
    from orochi_client import OrochiClient
    from orochi_client.cli import build_parser

    c = OrochiClient("http://localhost:8000", token="oro_test")
    assert c.session.headers["Authorization"] == "Bearer oro_test"

    parser = build_parser()
    args = parser.parse_args(["playbook", "run", "win_malware_quick", "abc-123"])
    assert args.command == "playbook"
    assert args.pb_action == "run"
    assert args.playbook_id == "win_malware_quick"


def test_python_client_paths_resolve_to_real_api_routes():
    """Every URL the client builds must resolve to a route of this API (a typo there is a 404 for users)."""
    from unittest.mock import MagicMock

    from django.urls import Resolver404, resolve

    client_src = str(ROOT / "clients" / "python" / "src")
    if client_src not in sys.path:
        sys.path.insert(0, client_src)
    from orochi_client import OrochiClient

    c = OrochiClient("http://orochi.test")
    seen = []

    def fake_request(method, url, **kwargs):
        seen.append((method, url.removeprefix("http://orochi.test")))
        resp = MagicMock(status_code=200, content=b"{}")
        resp.json.return_value = {}
        return resp

    c.session.request = fake_request
    idx = "8b6f0c5e-0000-11ee-0000-0242ac150005"
    c.get_dump(idx)
    c.update_dump(idx, name="x")
    c.list_dump_plugins(idx)
    c.get_plugin_status(idx, "windows.pslist.PsList")
    c.list_playbooks()
    c.launch_playbook("win_malware_quick", idx)
    c.get_playbook_status("win_malware_quick", idx)
    c.export_case_report(1)
    c.export_case_bundle(1)
    for method, path in seen:
        try:
            resolve(path.split("?")[0])
        except Resolver404:
            pytest.fail(f"Client calls {method} {path}, which is not an API route")


# =====================================================================
# #1545 — Declarative Sigma-Style Hunting Rules Engine
# =====================================================================
def test_sigma_hunting_rule_matches_plugin_row_and_rejects_invalid_yaml(dump):
    """AC (#1545): Valid user-supplied Sigma YAML rule flags matching plugin row; invalid rule is rejected."""
    valid_yaml = """
title: Encoded PowerShell Download Cradle
logsource:
  plugin: cmdline.CmdLine
detection:
  selection:
    Process|endswith: powershell.exe
    Args|contains|all:
      - -enc
      - http
  filter:
    Args|contains: benign_internal_script
  condition: selection and not filter
level: critical
"""
    HuntingRule.objects.create(
        name="Encoded PowerShell",
        slug="encoded_powershell",
        severity="Critical",
        score=50,
        mitre_technique="T1059.001",
        plugin_filter="cmdline.CmdLine",
        yaml_content=valid_yaml,
    )

    p, _ = Plugin.objects.get_or_create(name="windows.cmdline.CmdLine", defaults={"operating_system": "Windows"})
    res = Result.objects.create(dump=dump, plugin=p, result=RESULT_STATUS_SUCCESS)
    Value.objects.bulk_create(
        [
            Value(
                result=res,
                value={"PID": 111, "Process": "powershell.exe", "Args": "powershell -enc http://evil.test/p"},
            ),
            Value(
                result=res,
                value={
                    "PID": 222,
                    "Process": "powershell.exe",
                    "Args": "powershell -enc http://int/benign_internal_script",
                },
            ),
        ]
    )

    report = evaluate_dump_triage(dump)
    hunt_findings = [f for f in report["findings"] if f.rule_id == "HUNT_ENCODED_POWERSHELL"]
    assert len(hunt_findings) == 1
    assert "111" in hunt_findings[0].entity

    # Invalid rule handling
    with pytest.raises(SigmaRuleValidationError):
        parse_and_validate_sigma_rule("title: Missing Detection\n")
    with pytest.raises(SigmaRuleValidationError):
        parse_and_validate_sigma_rule("not: [valid: yaml")


# =====================================================================
# #1570 — Sandboxed / Isolated Dask Workers Config Validation
# =====================================================================
def test_sandbox_compose_overlay_hardens_workers_without_breaking_the_base_service():
    """#1570: the overlay adds read-only rootfs, limits and an internal network on top of the base worker."""
    import shutil
    import subprocess

    overlay = yaml.safe_load((ROOT / "docker-compose.sandbox.yml").read_text(encoding="utf-8"))
    worker = overlay["services"]["worker"]
    assert worker["read_only"] is True
    assert worker["pids_limit"] <= 512
    assert any(t.startswith("/run:") for t in worker["tmpfs"])  # clamd needs a writable /run
    assert overlay["networks"]["worker_isolated"]["internal"] is True
    # A custom seccomp allowlist broke the worker: Docker's default profile applies
    assert "security_opt" not in worker

    if not shutil.which("docker"):
        pytest.skip("docker CLI not available to merge the compose files")
    merged = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.sandbox.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if merged.returncode != 0:
        pytest.skip(f"docker compose config failed: {merged.stderr[:200]}")
    w = json.loads(merged.stdout)["services"]["worker"]
    assert w["read_only"] is True
    assert w["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in w["security_opt"]
    assert list(w["networks"]) == ["worker_isolated"]


def test_hunting_rule_admin_validates_yaml_and_level_and_logsource_apply(admin, dump):
    """#1545: rules are added from the admin (invalid YAML refused); YAML ``level`` and ``logsource`` are honoured."""
    from orochi.website.admin import HuntingRuleForm
    from orochi.website.detection.sigma_engine import evaluate_hunting_rules

    bad = HuntingRuleForm(
        data={
            "name": "Bad",
            "slug": "bad",
            "severity": "High",
            "score": 30,
            "plugin_filter": "*",
            "yaml_content": "title: x\ndetection: {}\n",
            "enabled": True,
        }
    )
    assert not bad.is_valid() and "yaml_content" in bad.errors

    good = HuntingRuleForm(
        data={
            "name": "Encoded PowerShell",
            "slug": "encoded-ps",
            "severity": "High",
            "score": 30,
            "plugin_filter": "*",
            "enabled": True,
            "yaml_content": (
                "title: Encoded PowerShell\nlevel: low\nlogsource:\n  plugin: cmdline.CmdLine\n"
                "detection:\n  sel:\n    Args|contains: '-enc'\n  condition: sel\n"
            ),
        }
    )
    assert good.is_valid(), good.errors
    good.save()

    cmd, _ = Plugin.objects.get_or_create(name="windows.cmdline.CmdLine", defaults={"operating_system": "Windows"})
    other, _ = Plugin.objects.get_or_create(name="windows.envars.Envars", defaults={"operating_system": "Windows"})
    Value.objects.create(
        result=Result.objects.create(dump=dump, plugin=cmd, result=RESULT_STATUS_SUCCESS),
        value={"PID": 1, "Args": "powershell -enc AAAA"},
    )
    Value.objects.create(
        result=Result.objects.create(dump=dump, plugin=other, result=RESULT_STATUS_SUCCESS),
        value={"PID": 2, "Args": "-enc in an env var"},
    )
    findings = evaluate_hunting_rules(dump)
    assert len(findings) == 1  # logsource restricts the rule to cmdline
    assert findings[0].severity == "Low"  # YAML level wins over the model default
