"""Regression tests for Phase 2 Batch 2: #1538 (Case Timeline), #1540 (Case Report), #1543 (Triage Scoring)."""

import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from guardian.shortcuts import assign_perm

from orochi.website.case_reporting import export_case_to_html, export_case_to_markdown, export_case_to_pdf
from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.detection.rules import evaluate_parent_child_incoherence
from orochi.website.models import (
    Case,
    DumpIOC,
    Evidence,
    Finding,
    ForensicNode,
    Plugin,
    Result,
    TimelineEvent,
    Value,
)

pytestmark = pytest.mark.django_db


# =====================================================================
# #1538 — Case Investigation Timeline (Manual + Artefact vs Activity)
# =====================================================================
def test_case_timeline_api_manual_create_list_delete_and_artefact_separation(client, admin, dump):
    """AC1-AC3 (#1538): Create, list, delete manual timeline events and separate artefact vs activity time."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    case = Case.objects.create(name="Timeline Case", user=admin)

    artefact_ts = datetime(2024, 5, 10, 8, 30, 0, tzinfo=UTC)
    ForensicNode.objects.create(
        case=case,
        dump=dump,
        node_type="process",
        label="beacon.exe (PID 4242)",
        first_seen=artefact_ts,
    )

    # Create manual timeline event via API
    manual_ts = "2024-05-10T09:00:00Z"
    create_resp = client.post(
        f"/api/cases/{case.pk}/timeline/",
        data=json.dumps(
            {
                "timestamp": manual_ts,
                "event_type": "Initial Access",
                "description": "Phishing attachment opened by user",
            }
        ),
        content_type="application/json",
    )
    assert create_resp.status_code == 201, create_resp.content
    event_id = create_resp.json()["id"]
    assert create_resp.json()["metadata"]["timeline_kind"] == "manual"

    # List timeline and verify artefact vs manual kinds are present & separated
    list_resp = client.get(f"/api/cases/{case.pk}/timeline/")
    assert list_resp.status_code == 200
    items = list_resp.json()
    kinds = {it["metadata"].get("timeline_kind") for it in items}
    assert "artefact" in kinds
    assert "manual" in kinds

    # Delete manual event via API
    del_resp = client.delete(f"/api/cases/{case.pk}/timeline/{event_id}/")
    assert del_resp.status_code == 200
    assert not TimelineEvent.objects.filter(pk=event_id).exists()


# =====================================================================
# #1540 — Case Report Sections (Scope, IOCs, Technical Appendix, Artefact Timeline)
# =====================================================================
def test_case_report_contains_scope_iocs_appendix_and_artefact_timeline(admin, dump):
    """AC1-AC4 (#1540): Markdown, HTML, and PDF reports contain Scope, IOCs, Appendix, and artefact timestamps."""
    dump.md5 = "d41d8cd98f00b204e9800998ecf8427e"
    dump.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    dump.banner = "Windows 10 Build 19045"
    dump.save(update_fields=["md5", "sha256", "banner"])

    case = Case.objects.create(name="Report Case", user=admin, description="Full incident report test")
    Evidence.objects.create(case=case, dump=dump, plugin="windows.pslist.PsList", result_row={"PID": 4})
    Finding.objects.create(
        case=case,
        severity="High",
        mitre_attack_technique="T1055",
        note="Suspicious injection",
    )
    DumpIOC.objects.create(
        dump=dump,
        ioc_type="ip",
        value="198.51.100.77",
        source_plugin="windows.netscan.NetScan",
        is_malicious=True,
        threat_score=90,
    )
    plugin, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList", defaults={"operating_system": "Windows"})
    Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS, parameter={"pid": 4})

    artefact_ts = datetime(2023, 11, 20, 14, 15, 0, tzinfo=UTC)
    ForensicNode.objects.create(
        case=case,
        dump=dump,
        node_type="process",
        label="malware.exe (PID 999)",
        first_seen=artefact_ts,
    )

    md = export_case_to_markdown(case)
    assert "## Scope" in md
    assert dump.sha256 in md
    assert "Windows 10 Build 19045" in md
    assert "## Indicators of Compromise (IOCs)" in md
    assert "198.51.100.77" in md
    assert "## Technical Appendix" in md
    assert "windows.pslist.PsList" in md
    assert "Volatility 3 Version" in md
    assert "2023-11-20 14:15:00 UTC" in md

    html_doc = export_case_to_html(case)
    assert "198.51.100.77" in html_doc
    assert "Technical Appendix" in html_doc
    assert "2023-11-20 14:15:00 UTC" in html_doc

    # Verify PDF path compiles the same HTML (mock WeasyPrint if system libs absent)
    with patch("weasyprint.HTML") as mock_wp:
        mock_wp.return_value.write_pdf.return_value = b"%PDF-1.4 mock"
        pdf_bytes = export_case_to_pdf(case)
    assert pdf_bytes.startswith(b"%PDF")
    passed_html = mock_wp.call_args.kwargs["string"]
    assert "198.51.100.77" in passed_html
    assert "Technical Appendix" in passed_html


# =====================================================================
# #1543 — Triage Scoring & Missing Signals
# =====================================================================
def test_triage_winxp_parents_no_false_positive_and_modern_misparented_lsass_no_t1003():
    """AC1 & AC4 (#1543): WinXP lsass/services under winlogon are clean; misparented lsass avoids T1003.001."""
    winxp_procs = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 368, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 520, "PPID": 368, "ImageFileName": "winlogon.exe"},
        {"PID": 564, "PPID": 520, "ImageFileName": "services.exe"},
        {"PID": 576, "PPID": 520, "ImageFileName": "lsass.exe"},
        {"PID": 1200, "PPID": 900, "ImageFileName": "chrome.exe"},
    ]
    xp_findings = evaluate_parent_child_incoherence(winxp_procs)
    assert xp_findings == []

    modern_procs = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 400, "PPID": 4, "ImageFileName": "wininit.exe"},
        {"PID": 999, "PPID": 400, "ImageFileName": "cmd.exe"},
        {"PID": 1337, "PPID": 999, "ImageFileName": "lsass.exe"},
    ]
    mod_findings = evaluate_parent_child_incoherence(modern_procs)
    assert len(mod_findings) == 1
    assert mod_findings[0].rule_id == "PROC_INCOHERENT_PARENT_LSASS"
    assert "T1003.001" not in mod_findings[0].mitre_technique


def test_triage_scores_dll_path_yara_hits_extracted_files_and_known_bad_hash(dump):
    """AC2 & AC3 (#1543): Suspicious DLL path, YARA hits, extracted files, and known-bad hashes appear in triage."""
    p_dll, _ = Plugin.objects.get_or_create(name="windows.dlllist.DllList", defaults={"operating_system": "Windows"})
    p_yara, _ = Plugin.objects.get_or_create(name="yarascan.YaraScan", defaults={"operating_system": "Other"})
    p_df, _ = Plugin.objects.get_or_create(name="windows.dumpfiles.DumpFiles", defaults={"operating_system": "Windows"})

    r_dll = Result.objects.create(dump=dump, plugin=p_dll, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=r_dll,
        value={"PID": 2048, "Process": "explorer.exe", "Path": "C:\\Users\\Public\\evil_helper.dll"},
    )

    r_yara = Result.objects.create(dump=dump, plugin=p_yara, result=RESULT_STATUS_SUCCESS)
    Value.objects.bulk_create(
        [
            Value(
                result=r_yara,
                value={"Rule": "CobaltStrike_Beacon", "PID": 2048, "Process": "explorer.exe", "Offset": f"0x{i:x}"},
            )
            for i in range(15)
        ]
    )

    r_df = Result.objects.create(dump=dump, plugin=p_df, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=r_df,
        value={"FileName": "payload.exe", "sha256": "b" * 64, "clamav": "Win.Trojan.Agent-123"},
    )

    DumpIOC.objects.create(
        dump=dump,
        ioc_type="hash_sha256",
        value="c" * 64,
        source_plugin="windows.dumpfiles.DumpFiles",
        context={"filename": "dropper.dll"},
        is_malicious=True,
        threat_score=95,
    )

    report = evaluate_dump_triage(dump)
    rule_ids = {f.rule_id for f in report["findings"]}
    assert "DLL_SUSPICIOUS_PATH" in rule_ids
    assert "YARA_RULE_MATCH" in rule_ids
    assert "EXTRACTED_FILE_MALICIOUS" in rule_ids
    assert "KNOWN_BAD_HASH_REPUTATION" in rule_ids
    assert report["risk_score"] >= 75
