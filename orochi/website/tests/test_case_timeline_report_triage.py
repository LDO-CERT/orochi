"""Regression tests for Phase 2 Batch 2: #1538 (Case Timeline), #1540 (Case Report), #1543 (Triage Scoring)."""

import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from guardian.shortcuts import assign_perm

from orochi.website.case_reporting import export_case_to_html, export_case_to_markdown, export_case_to_pdf
from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.detection.rules import (
    evaluate_parent_child_incoherence,
    evaluate_unbacked_exec_images,
    evaluate_unexpected_drivers,
)
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


# =====================================================================
# #1543 — Optional signals: unexpected / unlinked drivers, unbacked executable images
# =====================================================================
# Clean Windows XP kernel module list and driver objects (path spellings as volatility3 prints them)
XP_MODULES = [
    {"Base": 0x804D7000, "Size": 0x1F8580, "Name": "ntoskrnl.exe", "Path": "\\WINDOWS\\system32\\ntoskrnl.exe"},
    {"Base": 0x806D0000, "Size": 0x20380, "Name": "hal.dll", "Path": "\\WINDOWS\\system32\\hal.dll"},
    {"Base": 0xF8B9A000, "Size": 0x2000, "Name": "kdcom.dll", "Path": "\\WINDOWS\\system32\\KDCOM.DLL"},
    {"Base": 0xF8A7A000, "Size": 0x5000, "Name": "atapi.sys", "Path": "\\SystemRoot\\System32\\DRIVERS\\atapi.sys"},
    {"Base": 0xB2E3A000, "Size": 0x58000, "Name": "tcpip.sys", "Path": "\\SystemRoot\\system32\\DRIVERS\\tcpip.sys"},
    {"Base": 0xB2D00000, "Size": 0x9000, "Name": "vmci.sys", "Path": "\\??\\C:\\WINDOWS\\system32\\Drivers\\vmci.sys"},
    {"Base": 0xBF800000, "Size": 0x1C2000, "Name": "win32k.sys", "Path": "\\SystemRoot\\System32\\win32k.sys"},
    # Boot-start drivers: the XP boot loader records them by file name alone (as on sample003)
    {"Base": 0xF986D000, "Size": 0x2DD80, "Name": "ACPI.sys", "Path": "ACPI.sys"},
]
XP_DRIVERS = [
    {"Start": 0xB2E3A000, "Size": 0x58000, "Service Key": "Tcpip", "Driver Name": "Tcpip", "Name": "\\Driver\\Tcpip"},
    {"Start": 0xF8A7A000, "Size": 0x5000, "Service Key": "atapi", "Driver Name": "atapi", "Name": "\\Driver\\atapi"},
    # Built-in pseudo drivers: no image of their own, or code inside ntoskrnl
    {"Start": 0, "Size": 0, "Service Key": "", "Driver Name": "\\Driver\\WMIxWDM", "Name": ""},
    {"Start": 0x80500000, "Size": 0, "Service Key": "", "Driver Name": "\\FileSystem\\RAW", "Name": ""},
    {"Start": 0, "Size": 0, "Service Key": "PnpManager", "Driver Name": "\\Driver\\PnpManager", "Name": ""},
    # Pool-scan hit on freed memory: garbage name, start outside every module (as on sample003)
    {"Start": 0xF9B2C000, "Size": 0xAE00, "Service Key": None, "Driver Name": None, "Name": "\u0500\ue15a\u0500"},
]
# Clean XP malfind rows: RWX/RX heaps without executable header, as sample003 shows
XP_MALFIND = [
    {
        "PID": 596,
        "Process": "csrss.exe",
        "Start VPN": 2137980928,
        "Protection": "PAGE_EXECUTE_READWRITE",
        "Tag": "Vad ",
        "Hexdump": "c8 00 00 00 0f 01 00 00 ff ee ff ee 08 70 00 00",
        "Disasm": '"\n0x7f6f0000:\tenter\t0, 0"',
    },
]
XP_VADS = [
    {"PID": 596, "Process": "csrss.exe", "Start VPN": 2137980928, "Protection": "PAGE_EXECUTE_READWRITE", "File": None},
    {
        "PID": 596,
        "Process": "csrss.exe",
        "Start VPN": 2089811968,
        "Protection": "PAGE_EXECUTE_WRITECOPY",
        "File": "\\WINDOWS\\system32\\ntdll.dll",
    },
]


def test_triage_clean_winxp_drivers_and_memory_have_no_optional_signal_finding():
    """A clean XP module list, driver objects and malfind/vadinfo output give no driver or unbacked-image finding."""
    assert evaluate_unexpected_drivers(XP_DRIVERS, XP_MODULES) == []
    assert evaluate_unbacked_exec_images(XP_MALFIND, XP_VADS) == []
    # Without the module list nothing can be called unlinked
    assert evaluate_unexpected_drivers(XP_DRIVERS, []) == []


def test_triage_flags_unexpected_path_and_unlinked_driver():
    """Ground truth: a driver loaded from Temp, one without path, and one hidden from the module list."""
    modules = XP_MODULES + [
        {"Base": 0xB1000000, "Size": 0x4000, "Name": "evil.sys", "Path": "\\??\\C:\\Users\\Public\\evil.sys"},
        {"Base": 0xB1100000, "Size": 0x4000, "Name": "tmpdrv.sys", "Path": "\\SystemRoot\\Temp\\tmpdrv.sys"},
        {"Base": 0xB1200000, "Size": 0x3000, "Name": "", "Path": ""},
    ]
    drivers = XP_DRIVERS + [
        {"Start": 0xB0F00000, "Size": 0x6000, "Service Key": "", "Driver Name": "hidden", "Name": "\\Driver\\hidden"},
        # Same driver object found twice by the pool scanner: one finding
        {"Start": 0xB0F00000, "Size": 0x6000, "Service Key": "", "Driver Name": "hidden", "Name": "\\Driver\\hidden"},
    ]
    findings = evaluate_unexpected_drivers(drivers, modules)
    by_rule: dict[str, list] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    paths = sorted(f.entity for f in by_rule["DRIVER_UNEXPECTED_PATH"])
    assert paths == ["Driver 0xb1200000", "Driver evil.sys", "Driver tmpdrv.sys"]
    assert all(
        f.mitre_technique.startswith("T1543.003") and f.severity == "High" for f in by_rule["DRIVER_UNEXPECTED_PATH"]
    )
    assert len(by_rule["DRIVER_UNLINKED"]) == 1
    unlinked = by_rule["DRIVER_UNLINKED"][0]
    assert unlinked.mitre_technique.startswith("T1014") and unlinked.severity == "High"
    assert "\\Driver\\hidden" in unlinked.entity


def test_triage_flags_unbacked_pe_image_once_per_region(dump):
    """Ground truth: an RWX private region starting with MZ gives one unbacked-image finding, not a malfind duplicate."""
    injected = {
        "PID": 1516,
        "Process": "explorer.exe",
        "Start VPN": 0x2060000,
        "Protection": "PAGE_EXECUTE_READWRITE",
        "Tag": "VadS",
        "Hexdump": "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00",
        "Disasm": '"\n0x2060000:\tdec\tebp\n0x2060001:\tpop\tedx"',
    }
    # An image mapped from a file at the same kind of address is not reported
    mapped = dict(injected, PID=1600, Process="iexplore.exe")
    vads = XP_VADS + [
        {
            "PID": 1516,
            "Process": "explorer.exe",
            "Start VPN": 0x2060000,
            "Protection": "PAGE_EXECUTE_READWRITE",
            "File": None,
        },
        {
            "PID": 1600,
            "Process": "iexplore.exe",
            "Start VPN": 0x2060000,
            "Protection": "PAGE_EXECUTE_WRITECOPY",
            "File": "\\Program Files\\Internet Explorer\\iexplore.exe",
        },
    ]
    findings = evaluate_unbacked_exec_images(XP_MALFIND + [injected, injected, mapped], vads)
    assert [(f.rule_id, f.entity) for f in findings] == [("MEM_UNBACKED_EXEC_IMAGE", "explorer.exe (PID 1516)")]

    p_mal, _ = Plugin.objects.get_or_create(name="windows.malfind.Malfind", defaults={"operating_system": "Windows"})
    p_vad, _ = Plugin.objects.get_or_create(name="windows.vadinfo.VadInfo", defaults={"operating_system": "Windows"})
    p_mod, _ = Plugin.objects.get_or_create(name="windows.modules.Modules", defaults={"operating_system": "Windows"})
    p_drv, _ = Plugin.objects.get_or_create(
        name="windows.driverscan.DriverScan", defaults={"operating_system": "Windows"}
    )
    r_mal = Result.objects.create(dump=dump, plugin=p_mal, result=RESULT_STATUS_SUCCESS)
    Value.objects.bulk_create([Value(result=r_mal, value=v) for v in XP_MALFIND + [injected]])
    r_vad = Result.objects.create(dump=dump, plugin=p_vad, result=RESULT_STATUS_SUCCESS)
    Value.objects.bulk_create([Value(result=r_vad, value=v) for v in vads])
    r_mod = Result.objects.create(dump=dump, plugin=p_mod, result=RESULT_STATUS_SUCCESS)
    Value.objects.bulk_create([Value(result=r_mod, value=v) for v in XP_MODULES])
    r_drv = Result.objects.create(dump=dump, plugin=p_drv, result=RESULT_STATUS_SUCCESS)
    Value.objects.bulk_create([Value(result=r_drv, value=v) for v in XP_DRIVERS])

    report = evaluate_dump_triage(dump)
    regions = [(f.rule_id, f.entity) for f in report["findings"] if f.entity == "explorer.exe (PID 1516)"]
    # The generic malfind finding for the same PID + start address is replaced, the heap regions stay
    assert regions == [("MEM_UNBACKED_EXEC_IMAGE", "explorer.exe (PID 1516)")]
    assert {f.rule_id for f in report["findings"]} == {"MEM_UNBACKED_EXEC_IMAGE", "INJ_MALFIND_EXEC_REGION"}


def test_triage_unbacked_pe_detected_from_disasm_or_hexdump_spelling():
    """Rows that spell the hexdump column ``HexDump`` or carry only the disassembly still show the MZ header."""
    vads = [{"PID": 1337, "Start VPN": 0x1A400000000, "Protection": "PAGE_EXECUTE_READWRITE", "File": None}]
    base = {
        "PID": 1337,
        "Process": "powershell.exe",
        "Start VPN": 0x1A400000000,
        "Protection": "PAGE_EXECUTE_READWRITE",
    }
    for extra in (
        {"HexDump": "4d 5a 90 00 03 00 00 00  MZ......"},
        {"Disasm": "0x1a400000000: dec ebp\n0x1a400000001: pop edx\n0x1a400000002: nop"},
    ):
        assert [f.rule_id for f in evaluate_unbacked_exec_images([base | extra], vads)] == ["MEM_UNBACKED_EXEC_IMAGE"]
    # Without VadInfo the malfind row (private memory by construction) is still enough
    assert len(evaluate_unbacked_exec_images([base | {"Hexdump": "4d 5a 90 00"}], [])) == 1
    # Read-execute memory is not writable: not this signal
    ro = base | {"Protection": "PAGE_EXECUTE_READ", "Hexdump": "4d 5a 90 00"}
    assert evaluate_unbacked_exec_images([ro], [dict(vads[0], Protection="PAGE_EXECUTE_READ")]) == []
