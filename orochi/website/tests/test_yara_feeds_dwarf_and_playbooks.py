"""Regression tests for YARA feed scheduler/duplicates (#1552), dwarf2json upload (#1554), playbooks (#1544), and CI gates (#1672)."""

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Plugin, Result, Value
from orochi.website.playbooks import (
    create_custom_playbook,
    trigger_auto_playbooks_for_dump,
    update_custom_playbook,
)
from orochi.ya.models import Rule, Ruleset
from orochi.ya.rules_sync import compile_yara_rules_queryset
from orochi.ya.tasks import run_due_yara_feed_updates

pytestmark = pytest.mark.django_db
ROOT = Path(__file__).resolve().parents[3]


# =====================================================================
# #1552 — YARA Feed Scheduler & Duplicate/Invalid Rule Resilience
# =====================================================================
def test_yara_compilation_skips_invalid_and_handles_duplicate_rule_names(tmp_path):
    """AC2 (#1552): Duplicate rule names across files and one invalid rule do not abort ruleset compilation."""
    rs = Ruleset.objects.create(name="DupFeed", enabled=True, url="https://example.com/dup.git")
    f1 = tmp_path / "r1.yar"
    f2 = tmp_path / "r2.yar"
    f3 = tmp_path / "bad.yar"
    f1.write_text('rule SharedName { strings: $a = "alpha" condition: $a }', encoding="utf-8")
    f2.write_text('rule SharedName { strings: $b = "beta" condition: $b }', encoding="utf-8")
    f3.write_text("rule Broken { condition: ??? }", encoding="utf-8")

    Rule.objects.create(ruleset=rs, path=str(f1), enabled=True)
    Rule.objects.create(ruleset=rs, path=str(f2), enabled=True)
    Rule.objects.create(ruleset=rs, path=str(f3), enabled=True)

    built, compiled_count, skipped = compile_yara_rules_queryset(Rule.objects.filter(ruleset=rs), ignore_errors=True)
    assert built is not None
    assert compiled_count == 2
    assert len(skipped) == 1
    assert str(f3) in skipped[0][0]


def test_due_auto_update_yara_feeds_are_scheduled():
    """AC1 (#1552): Feeds with auto_update=True and stale last_sync are synced; recent ones are skipped."""
    stale_feed = Ruleset.objects.create(
        name="StaleFeed",
        url="https://example.com/stale.git",
        enabled=True,
        auto_update=True,
        last_sync=timezone.now() - timedelta(hours=48),
    )
    fresh_feed = Ruleset.objects.create(
        name="FreshFeed",
        url="https://example.com/fresh.git",
        enabled=True,
        auto_update=True,
        last_sync=timezone.now() - timedelta(hours=1),
    )

    with patch("orochi.ya.tasks.sync_yara_rules") as mock_sync:
        res = run_due_yara_feed_updates(interval_hours=24.0, compile_default=False)

    assert res["synced"] == [stale_feed.name]
    assert fresh_feed.name not in res["synced"]
    mock_sync.func.assert_called_once()


# =====================================================================
# #1554 — dwarf2json Analyst Upload-Only API
# =====================================================================
def test_dwarf_generate_accepts_upload_only_request_from_analyst(client, admin):
    """AC1 (#1554): Uploading only an ELF kernel file succeeds (HTTP 200, not 422)."""
    client.force_login(admin)
    elf_file = SimpleUploadedFile("vmlinux-6.1", b"\x7fELF" + b"\x00" * 64, content_type="application/octet-stream")
    fake_task = MagicMock()
    fake_task.enqueue.return_value = MagicMock(id="dwarf-task-42")

    with patch("orochi.api.routers.symbols.generate_dwarf_isf_task", fake_task):
        resp = client.post("/api/symbols/dwarf_generate", data={"elf": elf_file})

    assert resp.status_code == 200, resp.content
    assert "dwarf-task-42" in resp.json()["message"]
    fake_task.enqueue.assert_called_once()


# =====================================================================
# #1544 — Playbook Versioning, Auto-Run on Upload & Per-Run Status
# =====================================================================
def test_playbook_version_bump_auto_run_and_per_run_status(client, admin, user, dump):
    """AC1-AC3 (#1544): Playbook version bumps on edit, per-user auto-run (like UserPlugin) queues on upload, per-run status aggregates plugins."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    dump.operating_system = "Windows"
    dump.save(update_fields=["operating_system"])
    p1, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList", defaults={"operating_system": "Windows"})
    p2, _ = Plugin.objects.get_or_create(name="windows.cmdline.CmdLine", defaults={"operating_system": "Windows"})

    created = create_custom_playbook(
        name="Auto Win Triage",
        operating_system="Windows",
        plugin_names=[p1.name, p2.name],
        user=admin,
        auto_run_on_upload=True,
    )
    assert created["version"] == 1
    assert created["auto_run_on_upload"] is True

    updated = update_custom_playbook(
        playbook_id=created["id"],
        description="Updated description",
        user=admin,
    )
    assert updated["version"] == 2

    # Admin enables a built-in playbook via per-user API endpoint
    toggle_resp = client.post("/api/playbooks/win_malware_quick/auto_run?auto_run=true")
    assert toggle_resp.status_code == 200, toggle_resp.content
    assert toggle_resp.json()["auto_run_on_upload"] is True

    # Auto-run on upload queues only the uploading user's enabled playbooks (custom + built-in)
    fake_task = MagicMock()
    with patch("orochi.website.tasks.run_playbook_task", fake_task):
        launched_admin = trigger_auto_playbooks_for_dump(dump, user=admin)
        launched_other = trigger_auto_playbooks_for_dump(dump, user=user)
    assert created["id"] in launched_admin
    assert "win_malware_quick" in launched_admin
    assert launched_other == []
    assert fake_task.enqueue.call_count == 2

    # Per-run status aggregates plugin statuses and row counts
    r1 = Result.objects.create(dump=dump, plugin=p1, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=r1, value={"PID": 4})
    resp = client.get(f"/api/playbooks/{created['id']}/status/{dump.index}")
    assert resp.status_code == 200, resp.content
    data = resp.json()
    assert data["version"] == 2
    assert data["total_plugins"] == 2
    assert data["completed_plugins"] == 1
    assert any(p["plugin"] == p1.name and p["row_count"] == 1 for p in data["plugins"])

    # API list exposes version and per-user auto_run_on_upload
    list_resp = client.get("/api/playbooks/")
    assert list_resp.status_code == 200
    item = next(p for p in json.loads(list_resp.content) if p["id"] == created["id"])
    assert item["version"] == 2
    assert item["auto_run_on_upload"] is True


# =====================================================================
# #1672 — Release Quality Gates (Workflow Verification)
# =====================================================================
def test_release_workflow_enforces_tests_sbom_trivy_and_attestation():
    """Verify push.yml gates builds on tests and the release gates, and signs, scans and attests tag images."""
    import yaml

    workflows = ROOT / ".github" / "workflows"
    wf = (workflows / "push.yml").read_text(encoding="utf-8")
    jobs = yaml.safe_load(wf)["jobs"]
    # Images are built only after the tests and the release gates (#1670, #1672)
    assert jobs["release-gates"]["uses"] == "./.github/workflows/release-gates.yml"
    assert jobs["release-gates"]["needs"] == "tests"
    assert set(jobs["build"]["needs"]) == {"tests", "release-gates"}
    assert "sbom: true" in wf
    assert "provenance: true" in wf
    assert "trivy-action" in wf
    assert "attest-build-provenance" in wf
    # The scan must be able to fail the release, and its report is published
    assert 'exit-code: "1"' in wf and "upload-sarif" in wf
    # Keyless cosign signature of the pushed tag digest
    assert "sigstore/cosign-installer" in wf
    assert "cosign sign --yes" in wf and "steps.build_tag.outputs.digest" in wf

    gates_text = (workflows / "release-gates.yml").read_text(encoding="utf-8")
    gates = yaml.safe_load(gates_text)
    assert "workflow_call" in gates[True]  # YAML 1.1 reads the `on:` key as True
    gate_jobs = gates["jobs"]
    assert {"offline-start", "fresh-install", "upgrade-smoke"} <= set(gate_jobs)
    offline = str(gate_jobs["offline-start"])
    assert "docker network create --internal" in offline and "/accounts/login/" in offline
    fresh = str(gate_jobs["fresh-install"])
    assert "docker compose" in fresh and "OrochiClient" in fresh and "Analyst" in fresh
    assert "upload_dump" in fresh and "get_plugin_status" in fresh
    upgrade = str(gate_jobs["upgrade-smoke"])
    assert "ghcr.io/ldo-cert/orochi_django" in gates_text and "PREVIOUS_IMAGE" in upgrade
    assert upgrade.count("migrate --noinput") >= 2


def test_yara_feeds_update_command_runs_the_due_feeds():
    """#1552: the cron entry point syncs the due feeds."""
    from io import StringIO

    from django.core.management import call_command

    with patch(
        "orochi.ya.management.commands.yara_feeds_update.run_due_yara_feed_updates",
        return_value={"synced_count": 1, "skipped_count": 2, "compile": {"skipped_count": 1, "skipped": ["dup.yar"]}},
    ) as run:
        out = StringIO()
        call_command("yara_feeds_update", "--interval", "6", stdout=out)
    run.assert_called_once_with(6.0, compile_default=True)
    assert "Synced 1 feed(s)" in out.getvalue() and "dup.yar" in out.getvalue()
