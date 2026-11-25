"""Regression tests for restart failed/unsatisfied (#1665), LLM constraints (#1668), threaded annotations (#1669), ATT&CK ICS (#1667), network DNS/GeoIP (#1557), concurrent index docs (#1673), and playbook UI auto-run toggle."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.ai_narrative import strip_raw_identifiers_outside_citations, validate_llm_endpoint
from orochi.website.attack import ICS_ATTACK_TECHNIQUES, generate_navigator_layer, is_ics_technique
from orochi.website.defaults import (
    RESULT_STATUS_EMPTY,
    RESULT_STATUS_ERROR,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
    RESULT_STATUS_UNSATISFIED,
)
from orochi.website.models import Case, Finding, Plugin, Result, UserPlaybookPreference, Value
from orochi.website.network import extract_network_report

pytestmark = pytest.mark.django_db
ROOT = Path(__file__).resolve().parents[3]


# =====================================================================
# #1665 — Restart failed & unsatisfied plugins with feedback & RUNNING state
# =====================================================================
def test_restart_failed_includes_unsatisfied_reports_scheduled_and_marks_running(client, admin, dump):
    """AC1-AC3 (#1665): Restart covers ERROR and UNSATISFIED (skips EMPTY), reports scheduled, sets RUNNING."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    p_err, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList", defaults={"operating_system": "Windows"})
    p_unsat, _ = Plugin.objects.get_or_create(name="windows.cmdline.CmdLine", defaults={"operating_system": "Windows"})
    p_empty, _ = Plugin.objects.get_or_create(name="windows.malfind.Malfind", defaults={"operating_system": "Windows"})

    r_err = Result.objects.create(dump=dump, plugin=p_err, result=RESULT_STATUS_ERROR)
    r_unsat = Result.objects.create(dump=dump, plugin=p_unsat, result=RESULT_STATUS_UNSATISFIED)
    r_empty = Result.objects.create(dump=dump, plugin=p_empty, result=RESULT_STATUS_EMPTY)

    url = reverse("website:index_restart")
    with patch("orochi.website.views.index_f_and_f"):
        resp = client.post(
            url,
            {"index": str(dump.index), "restart_failed": "on"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["scheduled_count"] == 2
    assert set(data["scheduled_plugins"]) == {p_err.name, p_unsat.name}

    r_err.refresh_from_db()
    r_unsat.refresh_from_db()
    r_empty.refresh_from_db()
    assert r_err.result == RESULT_STATUS_RUNNING
    assert r_unsat.result == RESULT_STATUS_RUNNING
    assert r_empty.result == RESULT_STATUS_EMPTY


# =====================================================================
# #1668 — LLM local endpoint validation & raw identifier stripping
# =====================================================================
def test_llm_endpoint_validation_rejects_remote_unless_opt_in():
    """AC1 (#1668): Local/private endpoints pass; remote endpoints fail unless explicitly opted in."""
    assert validate_llm_endpoint("http://localhost:11434") == "http://localhost:11434"
    assert validate_llm_endpoint("http://127.0.0.1:11434") == "http://127.0.0.1:11434"
    assert validate_llm_endpoint("http://ollama:11434") == "http://ollama:11434"

    with pytest.raises(ValueError, match="Non-local LLM endpoint"):
        validate_llm_endpoint("https://api.openai.com/v1")

    assert validate_llm_endpoint("https://api.openai.com/v1", allow_remote=True) == "https://api.openai.com/v1"


def test_strip_raw_identifiers_outside_citations():
    """AC2 (#1668): Raw PIDs, hex offsets, and hashes outside citations are removed while citations remain."""
    raw = (
        "Suspicious process PID 1337 at offset 0xdeadbeef with hash "
        "d41d8cd98f00b204e9800998ecf8427e was observed [TriageFinding:1]."
    )
    cleaned = strip_raw_identifiers_outside_citations(raw)
    assert "1337" not in cleaned
    assert "0xdeadbeef" not in cleaned
    assert "d41d8cd98f00b204e9800998ecf8427e" not in cleaned
    assert "[TriageFinding:1]" in cleaned


# =====================================================================
# #1669 — Threaded replies on row annotations
# =====================================================================
def test_value_annotations_two_level_thread_api(client, admin, dump):
    """AC1-AC2 (#1669): Create parent annotation and reply; GET returns nested replies."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    p, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList", defaults={"operating_system": "Windows"})
    res = Result.objects.create(dump=dump, plugin=p, result=RESULT_STATUS_SUCCESS)
    val = Value.objects.create(result=res, value={"PID": 42, "ImageFileName": "evil.exe"})

    r1 = client.post(
        f"/api/dumps/values/{val.pk}/annotations",
        data=json.dumps({"status": "suspicious", "comment": "Looks injected"}),
        content_type="application/json",
    )
    assert r1.status_code == 201, r1.content
    parent_id = r1.json()["id"]

    r2 = client.post(
        f"/api/dumps/values/{val.pk}/annotations",
        data=json.dumps({"status": "comment", "comment": "Confirmed via malfind", "parent_id": parent_id}),
        content_type="application/json",
    )
    assert r2.status_code == 201, r2.content
    assert r2.json()["parent_id"] == parent_id

    get_resp = client.get(f"/api/dumps/values/{val.pk}/annotations")
    assert get_resp.status_code == 200
    threads = get_resp.json()
    assert len(threads) == 1
    assert threads[0]["id"] == parent_id
    assert len(threads[0]["replies"]) == 1
    assert threads[0]["replies"][0]["comment"] == "Confirmed via malfind"


# =====================================================================
# #1667 — ATT&CK for ICS tagging & Navigator export
# =====================================================================
def test_attack_ics_technique_tagging_and_navigator_export(admin):
    """AC1-AC2 (#1667): Tag finding with ICS technique T0855 and export ics-attack Navigator layer."""
    assert is_ics_technique("T0855")
    assert "T0855" in ICS_ATTACK_TECHNIQUES
    assert not is_ics_technique("T1055")

    case = Case.objects.create(name="PLC Incident", user=admin)
    Finding.objects.create(
        case=case,
        severity="Critical",
        mitre_attack_technique="T0855 - Unauthorized Command Message",
        note="Rogue Modbus write command sent to PLC",
    )
    layer = generate_navigator_layer(case, case.findings.all())
    assert layer["domain"] == "ics-attack"
    assert len(layer["techniques"]) == 1
    assert layer["techniques"][0]["techniqueID"] == "T0855"


# =====================================================================
# #1557 — Network view DNS records & missing GeoIP DB status
# =====================================================================
def test_network_report_includes_dns_records_and_geoip_status(dump):
    """AC1-AC2 (#1557): DNS records surfaced in report and missing GeoIP DB reports clear status message."""
    p_dns, _ = Plugin.objects.get_or_create(name="windows.dnscache.DnsCache", defaults={"operating_system": "Windows"})
    r_dns = Result.objects.create(dump=dump, plugin=p_dns, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=r_dns, value={"Domain": "c2.evil.example", "IP": "203.0.113.10", "Type": "A"})

    with patch("orochi.website.network.Path.exists", return_value=False):
        report = extract_network_report(dump)

    assert report["geoip_available"] is False
    assert "not installed" in report["geoip_status_message"].lower()
    assert report["stats"]["dns_records_count"] == 1
    assert report["dns_records"][0]["domain"] == "c2.evil.example"


def test_network_view_renders_dns_records_and_missing_geoip_notice(client, admin, dump):
    """UI (#1557): the network view shows the DNS table and says when the GeoLite2 database is missing."""
    from django.urls import reverse
    from guardian.shortcuts import assign_perm

    assign_perm("website.can_see", admin, dump)
    p_dns, _ = Plugin.objects.get_or_create(name="windows.dnscache.DnsCache", defaults={"operating_system": "Windows"})
    r_dns = Result.objects.create(dump=dump, plugin=p_dns, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=r_dns, value={"Domain": "c2.evil.example", "IP": "203.0.113.10", "Type": "A"})
    client.force_login(admin)
    with patch("orochi.website.network.Path.exists", return_value=False):
        resp = client.get(reverse("website:dump_network", kwargs={"index": dump.index}), HTTP_HX_REQUEST="true")
    html = resp.content.decode()
    assert resp.status_code == 200
    assert 'id="net-geoip-status"' in html and "not installed" in html
    assert 'id="net-dns-records"' in html and "c2.evil.example" in html


# =====================================================================
# #1673 — Concurrent index zero-downtime documentation check
# =====================================================================
def test_postgres_upgrade_guide_documents_concurrent_value_index():
    """AC2 (#1673): Zero-downtime CREATE INDEX CONCURRENTLY alternative is documented."""
    guide = (ROOT / "docs" / "Postgres-Upgrade-Guide.md").read_text(encoding="utf-8")
    assert "CREATE INDEX CONCURRENTLY IF NOT EXISTS value_result_idx" in guide


# =====================================================================
# Playbooks UI per-user auto-run toggle
# =====================================================================
def test_playbooks_page_toggle_auto_run_ui(client, admin):
    """Users can toggle per-user auto-run on upload directly from /playbooks."""
    client.force_login(admin)
    url = reverse("website:list_playbooks")

    # Enable built-in playbook
    resp = client.post(url, {"action": "toggle_auto_run", "playbook_id": "win_malware_quick", "auto_run": "1"})
    assert resp.status_code == 302
    assert UserPlaybookPreference.objects.filter(user=admin, playbook_id="win_malware_quick", auto_run=True).exists()

    # Page renders Auto-run: ON
    page = client.get(url)
    assert page.status_code == 200
    assert b"Auto-run: ON" in page.content


def test_value_result_index_migration_reuses_a_concurrently_built_index():
    """#1673: migration 0081 must not fail (or lock) when the index was pre-built with CREATE INDEX CONCURRENTLY."""
    from importlib import import_module

    from django.db import connection

    mod = import_module("orochi.website.migrations.0081_casenote_forensicedge_forensicnode_alter_service_key_and_more")
    sqls = [
        db_op.sql
        for op in mod.Migration.operations
        if op.__class__.__name__ == "SeparateDatabaseAndState"
        for db_op in op.database_operations
    ]
    assert any("CREATE INDEX IF NOT EXISTS" in sql and "value_result_idx" in sql for sql in sqls)
    with connection.cursor() as cursor:
        # The index already exists in the test database: running the migration SQL again is a no-op
        for sql in sqls:
            cursor.execute(sql)
