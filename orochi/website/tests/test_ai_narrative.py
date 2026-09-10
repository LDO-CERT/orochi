from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.ai_narrative import (
    extract_dump_forensic_context,
    generate_dump_narrative,
    verify_and_sanitize_narrative,
)
from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import (
    Dump,
    DumpNarrative,
    DumpSecret,
    Plugin,
    Result,
    TriageFinding,
    Value,
)
from orochi.website.roles import ROLE_ANALYST, ROLE_READONLY, set_user_role

pytestmark = pytest.mark.django_db
User = get_user_model()


@pytest.fixture
def analyst_user():
    user = User.objects.create_user("analyst_test", "analyst@test.com", "Password123!")
    set_user_role(user, ROLE_ANALYST)
    return user


@pytest.fixture
def readonly_user():
    user = User.objects.create_user("ro_test", "ro@test.com", "Password123!")
    set_user_role(user, ROLE_READONLY)
    return user


@pytest.fixture
def forensic_dump(admin):
    dump = Dump.objects.create(
        index="test_dump_ai_123",
        name="incident_alpha.raw",
        author=admin,
        operating_system="Windows",
        color="#3b82f6",
    )
    assign_perm("website.can_see", admin, dump)

    # 1. Add Triage Finding
    TriageFinding.objects.create(
        dump=dump,
        rule_id="PROC_001",
        rule_name="Anomalous svchost.exe Parent",
        category="Process Tree",
        severity="Critical",
        score=25,
        mitre_technique="T1055",
        entity="svchost.exe (PID 1024)",
        description="svchost.exe spawned by cmd.exe instead of services.exe",
        evidence_snippet="cmd.exe (PID 888) -> svchost.exe (PID 1024)",
        raw_data={"PID": 1024, "PPID": 888, "Offset": "0x7ffd1000"},
    )

    # 2. Add Dump Secret
    DumpSecret.objects.create(
        dump=dump,
        category="aws",
        rule_name="Secret_AWS_Access_Key",
        matched_data="AKIAIOSFODNN7EXAMPLE",
        masked_data="AKIAIOSFOD********",
        offset="0x400010",
        pid=1024,
        process_name="svchost.exe",
    )

    # 3. Add PsList Result & Value
    p_pslist = Plugin.objects.create(name="windows.pslist.PsList", operating_system="Windows")
    res_pslist = Result.objects.create(dump=dump, plugin=p_pslist, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res_pslist,
        value={
            "ImageFileName": "svchost.exe",
            "PID": 1024,
            "PPID": 888,
            "Offset": "0x7ffd1000",
            "Args": "svchost.exe -k netsvcs",
        },
    )

    # 4. Add NetScan Result & Value
    p_netscan = Plugin.objects.create(name="windows.netscan.NetScan", operating_system="Windows")
    res_netscan = Result.objects.create(dump=dump, plugin=p_netscan, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res_netscan,
        value={
            "Proto": "TCP",
            "LocalAddr": "192.168.1.50",
            "LocalPort": 49152,
            "ForeignAddr": "198.51.100.25",
            "ForeignPort": 4444,
            "State": "ESTABLISHED",
            "PID": 1024,
            "Owner": "svchost.exe",
        },
    )

    # 5. Add Malfind Result & Value
    p_malfind = Plugin.objects.create(name="windows.malfind.Malfind", operating_system="Windows")
    res_malfind = Result.objects.create(dump=dump, plugin=p_malfind, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res_malfind,
        value={
            "Process": "svchost.exe",
            "PID": 1024,
            "Start": "0x7ffd1000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "HexDump": "4d 5a 90 00",
        },
    )

    return dump


def test_extract_dump_forensic_context(forensic_dump):
    """Test forensic evidence extraction correctly indexes PIDs, offsets, and citation tags."""
    evidence_text, valid_pids, valid_offsets, citation_registry = extract_dump_forensic_context(forensic_dump)

    # Assert valid PIDs and offsets
    assert 1024 in valid_pids
    assert 888 in valid_pids
    assert "0x7ffd1000" in valid_offsets or "0x7FFD1000" in valid_offsets
    assert "0x400010" in valid_offsets or "0x400010" in valid_offsets

    # Assert citation registry entries
    assert any("TriageFinding" in k for k in citation_registry)
    assert any("DumpSecret" in k for k in citation_registry)
    assert any("Value" in k for k in citation_registry)

    # Assert evidence text structure
    assert "BEHAVIORAL TRIAGE FINDINGS" in evidence_text
    assert "Anomalous svchost.exe Parent" in evidence_text
    assert "DETECTED MEMORY SECRETS" in evidence_text
    assert "AKIAIOSFOD" in evidence_text
    assert "PROCESS EXECUTION ARTIFACTS" in evidence_text
    assert "NETWORK COMMUNICATIONS" in evidence_text
    assert "198.51.100.25:4444" in evidence_text
    assert "SUSPICIOUS MEMORY INJECTIONS" in evidence_text


def test_verify_and_sanitize_clean_narrative():
    """Test that valid PIDs and offsets with proper citations pass verification cleanly."""
    valid_pids = {1024, 888}
    valid_offsets = {"0x7ffd1000", "0X7FFD1000", "0x400010"}
    citation_registry = {
        "TriageFinding:1": {"type": "triage", "id": 1, "label": "Anomalous Parent"},
        "Value:42": {"type": "value", "id": 42, "label": "svchost.exe (PID 1024)"},
    }

    raw_text = (
        "## Executive Triage Summary\n"
        "Observed anomalous process execution for PID 1024 spawned by PID 888 [TriageFinding:1]. "
        "Injected memory detected at offset 0x7ffd1000 [Value:42]."
    )

    formatted_html, check, cited = verify_and_sanitize_narrative(raw_text, valid_pids, valid_offsets, citation_registry)

    assert check["is_clean"] is True
    assert check["unverified_pids"] == []
    assert check["unverified_offsets"] == []
    assert 1024 in check["verified_pids"]
    assert 888 in check["verified_pids"]
    assert len(cited) == 2
    assert "citation-pill" in formatted_html
    assert "TriageFinding:1" in formatted_html


def test_verify_and_sanitize_hallucination_detection():
    """Test that fabricated PIDs, offsets, external IPs, and hashes are identified and marked with warning badges."""
    valid_pids = {1024}
    valid_offsets = {"0x7ffd1000"}
    citation_registry = {
        "__meta__": {
            "valid_ips": {"192.168.1.50"},
            "valid_hashes": {"5d41402abc4b2a76b9719d911017c592"},
        }
    }

    raw_text = (
        "Investigation revealed suspicious activity in PID 9999 communicating with C2 at 203.0.113.88. "
        "Also observed memory payload injected at offset 0xdeadbeef with hash 0123456789abcdef0123456789abcdef."
    )

    formatted_html, check, _ = verify_and_sanitize_narrative(raw_text, valid_pids, valid_offsets, citation_registry)

    assert check["is_clean"] is False
    assert 9999 in check["unverified_pids"]
    assert "0xdeadbeef" in check["unverified_offsets"]
    assert "203.0.113.88" in check["unverified_ips"]
    assert "0123456789abcdef0123456789abcdef" in check["unverified_hashes"]
    assert "⚠️ Unverified PID: 9999" in formatted_html
    assert "⚠️ Unverified Offset: 0xdeadbeef" in formatted_html
    assert "⚠️ Unverified IP: 203.0.113.88" in formatted_html
    assert "⚠️ Unverified Hash: 01234567..." in formatted_html


def test_generate_dump_narrative_with_mock_ollama(forensic_dump, admin):
    """Test full coordinator function creates and saves DumpNarrative record with mock Ollama."""
    tf = forensic_dump.triage_findings.first()
    sec = forensic_dump.secrets.first()
    val = Value.objects.filter(result__dump=forensic_dump).first()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": (
            "## Executive Triage Summary\n"
            f"Forensic analysis of the memory image revealed an anomalous execution of svchost.exe (PID 1024) [TriageFinding:{tf.pk}].\n"
            f"An active C2 connection was observed targeting 198.51.100.25 on port 4444 [Value:{val.pk}].\n"
            f"Additionally, exposed AWS credentials were identified in process memory [DumpSecret:{sec.pk}]."
        )
    }

    with patch("requests.post", return_value=mock_resp):
        narrative = generate_dump_narrative(forensic_dump, author=admin, model_name="llama3.2:1b")

        assert narrative.pk is not None
        assert narrative.dump == forensic_dump
        assert narrative.author == admin
        assert narrative.model_name == "llama3.2:1b"
        assert narrative.evidence_hash is not None
        assert narrative.hallucination_check["is_clean"] is True
        assert 1024 in narrative.hallucination_check["verified_pids"]
        assert len(narrative.citations) == 3


def test_dump_narrative_view_get_and_post(client, admin, forensic_dump):
    """Test dump narrative modal view GET (empty state) and POST (generation)."""
    client.force_login(admin)
    url = reverse("website:dump_narrative", kwargs={"index": forensic_dump.index})

    # 1. Initial GET -> empty initiation card
    resp_get = client.get(url)
    assert resp_get.status_code == 200
    content_get = resp_get.content.decode()
    assert "AI Forensic Triage Narrative" in content_get
    assert "Generate First-Pass Forensic Triage Narrative" in content_get

    # 2. POST -> Generates narrative
    tf = forensic_dump.triage_findings.first()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": (f"## Executive Triage Summary\nTriage completed for PID 1024 [TriageFinding:{tf.pk}].")
    }

    with patch("requests.post", return_value=mock_resp):
        resp_post = client.post(url, {"model_name": "llama3.2:1b"})
        assert resp_post.status_code == 200
        content_post = resp_post.content.decode()
        assert "Forensic Guardrails Active" in content_post
        assert "Triage completed for PID 1024" in content_post
        assert "Export Markdown" in content_post

    # Verify DB persistence
    assert forensic_dump.narratives.count() == 1


def test_dump_narrative_export_view(client, admin, forensic_dump):
    """Test exporting generated narrative as a Markdown file."""
    client.force_login(admin)
    narrative = DumpNarrative.objects.create(
        dump=forensic_dump,
        author=admin,
        model_name="llama3.2:1b",
        raw_narrative="## Executive Summary\nClean forensic test narrative.",
        formatted_narrative="<p>Clean forensic test narrative.</p>",
        evidence_hash="a1b2c3d4e5f6",
        citations=[],
        hallucination_check={
            "is_clean": True,
            "verified_pids": [],
            "unverified_pids": [],
        },
    )

    url_export = reverse(
        "website:dump_narrative_export",
        kwargs={"index": forensic_dump.index, "narrative_id": narrative.pk},
    )
    resp = client.get(url_export)
    assert resp.status_code == 200
    assert resp["Content-Type"].startswith("text/markdown")
    assert "AI FORENSIC FIRST-PASS TRIAGE REPORT" in resp.content.decode()
    assert "incident_alpha.raw" in resp.content.decode()
    assert "a1b2c3d4e5f6" in resp.content.decode()


def test_dump_narrative_permissions(client, analyst_user, readonly_user, forensic_dump):
    """Test permission boundaries for AI narrative views."""
    # Assign can_see to analyst and readonly
    assign_perm("website.can_see", analyst_user, forensic_dump)
    assign_perm("website.can_see", readonly_user, forensic_dump)

    url = reverse("website:dump_narrative", kwargs={"index": forensic_dump.index})

    # ReadOnly user can GET
    client.force_login(readonly_user)
    resp_ro_get = client.get(url)
    assert resp_ro_get.status_code == 200

    # ReadOnly user cannot POST
    resp_ro_post = client.post(url, {"model_name": "llama3.2:1b"})
    assert resp_ro_post.status_code == 403

    # Analyst user can GET and POST
    client.force_login(analyst_user)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "Narrative generated for analyst."}
    with patch("requests.post", return_value=mock_resp):
        resp_analyst_post = client.post(url, {"model_name": "llama3.2:1b"})
        assert resp_analyst_post.status_code == 200


def test_api_dump_narrative_endpoints(client, admin, forensic_dump):
    """Test REST API endpoints GET and POST for dump narratives."""
    client.force_login(admin)

    # 1. GET narrative when none exists -> 404
    resp_get_404 = client.get(f"/api/dumps/{forensic_dump.index}/narrative")
    assert resp_get_404.status_code == 404

    # 2. POST to generate narrative
    tf = forensic_dump.triage_findings.first()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": (f"## Executive Triage Summary\nSuspicious process PID 1024 observed [TriageFinding:{tf.pk}].")
    }

    with patch("requests.post", return_value=mock_resp):
        resp_post = client.post(f"/api/dumps/{forensic_dump.index}/narrative/generate")
        assert resp_post.status_code == 201
        data = resp_post.json()
        assert data["dump_index"] == forensic_dump.index
        assert data["model_name"] == "llama3.2:1b"
        assert data["evidence_hash"] is not None
        assert data["hallucination_check"]["is_clean"] is True

    # 3. GET narrative now -> 200
    resp_get_200 = client.get(f"/api/dumps/{forensic_dump.index}/narrative")
    assert resp_get_200.status_code == 200
    get_data = resp_get_200.json()
    assert get_data["id"] == data["id"]
    assert "Suspicious process PID 1024" in get_data["raw_narrative"]
