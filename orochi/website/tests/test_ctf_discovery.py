"""Comprehensive tests for CTF Discovery (Ground Truth), IR scoring, Golden Case, YAML I/O, UI, API, and WebSockets."""

import base64
import json

import pytest
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse

from orochi.website import ctf
from orochi.website.consumers import CTFLeaderboardConsumer
from orochi.website.ctf_matcher import build_criteria_from_evidence, extract_canonical_entity, matches_objective
from orochi.website.models import Case, CTFDiscoverySubmission, Evidence, Finding

pytestmark = pytest.mark.django_db

User = get_user_model()


# ------------------------------------------------------------------ Canonical Entity Matcher Unit Tests


def test_canonical_entity_cross_plugin_process_matching():
    """Discovering PID 4820 in pstree or cmdline must match a ground-truth objective authored from pslist."""
    entity_type, criteria = build_criteria_from_evidence(
        "windows.pslist.PsList",
        {"PID": 4820, "PPID": 892, "ImageFileName": "svchost.exe"},
    )
    assert entity_type == "process"
    assert criteria == {"pid": 4820, "name": "svchost.exe"}

    # Match from pstree
    assert matches_objective(
        entity_type,
        criteria,
        "windows.pstree.PsTree",
        {"PID": "4820", "ImageFileName": "SVCHOST.EXE"},
    )
    # Match from cmdline
    assert matches_objective(
        entity_type,
        criteria,
        "windows.cmdline.CmdLine",
        {"PID": 4820, "Process": "svchost.exe", "Args": "svchost.exe -k evil"},
    )
    # Benign process must NOT match
    assert not matches_objective(
        entity_type,
        criteria,
        "windows.pslist.PsList",
        {"PID": 1200, "ImageFileName": "explorer.exe"},
    )


def test_canonical_entity_network_injection_registry_yara_regex():
    # Network: netstat matches netscan objective
    assert matches_objective(
        "network",
        {"foreign_ip": "198.51.100.23", "foreign_port": 4444},
        "windows.netstat.NetStat",
        {"ForeignAddr": "198.51.100.23", "ForeignPort": "4444", "Proto": "TCPv4"},
    )

    # Injection: hex normalization (int vs 0x-string)
    assert matches_objective(
        "injection",
        {"pid": 4820, "base_address": "0x7ffd0000"},
        "windows.malfind.Malfind",
        {"PID": 4820, "Start VPN": 0x7FFD0000, "Protection": "PAGE_EXECUTE_READWRITE"},
    )

    # Registry wildcard path
    assert matches_objective(
        "registry",
        {"key_path": "*\\currentversion\\run", "value_name": "updater"},
        "windows.registry.printkey.PrintKey",
        {"Key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Name": "Updater", "Data": "C:\\bad.exe"},
    )

    # YARA rule match
    assert matches_objective(
        "yara",
        {"rule": "cobaltstrike_beacon", "pid": 4820},
        "yarascan.YaraScan",
        {"Rule": "CobaltStrike_Beacon", "PID": 4820, "Offset": "0x401000"},
    )

    # Generic regex match
    assert matches_objective(
        "generic",
        {"regex": r"flag\{[a-z0-9_]+\}"},
        "linux.bash.Bash",
        {"Command": "echo flag{mem_forensics_2026}"},
    )

    # File entity extraction
    ent = extract_canonical_entity(
        "windows.filescan.FileScan", {"Name": "\\Users\\evil.exe"}, extracted_file="evil.exe"
    )
    assert ent["entity_type"] == "file"
    assert ent["name"] == "\\users\\evil.exe"


# ------------------------------------------------------------------ Scoring, IR Metrics, MITRE, First Blood, Dynamic


@pytest.fixture
def discovery_case(user, analyst_user):
    case = Case.objects.create(
        name="APT29 Discovery CTF",
        user=user,
        is_ctf=True,
        ctf_fp_penalty=20,
        ctf_first_blood_bonus=10,
        ctf_dynamic_scoring=True,
    )
    case.collaborators.add(analyst_user)
    return case


def test_discovery_scoring_ir_metrics_mitre_first_blood_and_dynamic(discovery_case, analyst_user, readonly_user):
    discovery_case.collaborators.add(readonly_user)
    obj1 = ctf.create_objective(
        discovery_case,
        title="Injected svchost",
        entity_type="process",
        criteria={"pid": 4820, "name": "svchost.exe"},
        points=100,
        required_mitre="T1055",
        mitre_bonus=25,
        order=1,
    )
    ctf.create_objective(
        discovery_case,
        title="C2 Channel",
        entity_type="network",
        criteria={"foreign_ip": "198.51.100.23", "foreign_port": 4444},
        points=100,
        order=2,
    )

    # 1. Analyst discovers obj1 via pstree (cross-plugin!) with sub-technique T1055.001 -> First Blood (+10%) + MITRE (+25)
    r1 = ctf.submit_discovery(
        discovery_case,
        analyst_user,
        plugin="windows.pstree.PsTree",
        result_row={"PID": 4820, "ImageFileName": "svchost.exe"},
        submitted_mitre="T1055.001",
    )
    assert r1.is_tp is True
    assert r1.is_first_blood is True
    assert r1.mitre_matched is True
    assert r1.awarded_points == 135  # 100 base + 10 FB + 25 MITRE
    assert r1.objective_id == obj1.pk

    # 2. Analyst submits same process from cmdline -> Duplicate (0 pts, no FP penalty)
    r_dup = ctf.submit_discovery(
        discovery_case,
        analyst_user,
        plugin="windows.cmdline.CmdLine",
        result_row={"PID": 4820, "Process": "svchost.exe"},
    )
    assert r_dup.is_duplicate is True
    assert r_dup.is_tp is False
    assert r_dup.is_fp is False
    assert r_dup.awarded_points == 0

    # 3. Analyst submits benign explorer.exe -> False Positive (-20 pts)
    r_fp = ctf.submit_discovery(
        discovery_case,
        analyst_user,
        plugin="windows.pslist.PsList",
        result_row={"PID": 1200, "ImageFileName": "explorer.exe"},
    )
    assert r_fp.is_fp is True
    assert r_fp.awarded_points == -20

    # 4. IR Metrics check: TP=1, FP=1, FN=1 => Precision=0.5, Recall=0.5, F1=0.5
    metrics = ctf.user_discovery_metrics(discovery_case, analyst_user)
    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["duplicates"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1_score"] == 0.5
    assert metrics["discovery_points"] == 115  # 135 - 20
    assert metrics["first_blood_count"] == 1
    assert metrics["mitre_bonus_count"] == 1

    # 5. Second solver solves obj1 -> Dynamic scoring decay (< 100), no First Blood
    r2 = ctf.submit_discovery(
        discovery_case,
        readonly_user,
        plugin="windows.pslist.PsList",
        result_row={"PID": 4820, "ImageFileName": "svchost.exe"},
    )
    assert r2.is_tp is True
    assert r2.is_first_blood is False
    assert r2.awarded_points < 100  # Decayed from 100 to ~93

    # 6. Leaderboard ranks analyst_user #1 over readonly_user
    board = ctf.leaderboard(discovery_case)
    assert len(board) == 2
    assert board[0]["username"] == analyst_user.username
    assert board[0]["total_points"] == 115
    assert board[0]["precision"] == 0.5
    assert board[0]["first_blood_count"] == 1
    assert board[1]["username"] == readonly_user.username


# ------------------------------------------------------------------ Golden Case Authoring


def test_golden_case_promotes_evidences_and_mitre_to_objectives(user):
    case = Case.objects.create(name="Golden Lab", user=user, is_ctf=True)
    ev = Evidence.objects.create(
        case=case,
        name="Malicious Process",
        plugin="windows.pslist.PsList",
        result_row={"PID": 31337, "ImageFileName": "beacon.exe"},
    )
    Finding.objects.create(case=case, evidence=ev, severity="Critical", mitre_attack_technique="T1055")

    created = ctf.promote_evidences_to_objectives(case, points=150, mitre_bonus=30)
    assert len(created) == 1
    assert created[0].entity_type == "process"
    assert created[0].criteria == {"pid": 31337, "name": "beacon.exe"}
    assert created[0].required_mitre == "T1055"
    assert created[0].points == 150

    # Running again is idempotent (no duplicates)
    assert ctf.promote_evidences_to_objectives(case) == []


# ------------------------------------------------------------------ YAML & JSON Scenario Import/Export


def test_scenario_yaml_and_json_roundtrip(user):
    src = Case.objects.create(
        name="Source Scenario",
        user=user,
        is_ctf=True,
        ctf_mode=Case.CTF_MODE_COMPETITION,
        ctf_fp_penalty=25,
        ctf_first_blood_bonus=15,
        ctf_dynamic_scoring=True,
    )
    ctf.create_objective(
        src,
        title="C2 Socket",
        entity_type="network",
        criteria={"foreign_ip": "10.10.10.5", "foreign_port": 8443},
        points=120,
        required_mitre="T1071",
    )
    ctf.create_question(src, "What is the hostname?", "WORKSTATION-01", points=80, hints=[("Check envars", 15)])

    yaml_text = ctf.export_scenario(src, fmt="yaml")
    json_text = ctf.export_scenario(src, fmt="json")
    assert "C2 Socket" in yaml_text
    assert json.loads(json_text)["settings"]["fp_penalty"] == 25

    dst = Case.objects.create(name="Imported Scenario", user=user)
    summary = ctf.import_scenario(dst, yaml_text)
    assert summary == {"objectives_created": 1, "questions_created": 1}
    dst.refresh_from_db()
    assert dst.is_ctf is True
    assert dst.ctf_mode == Case.CTF_MODE_COMPETITION
    assert dst.ctf_fp_penalty == 25
    assert dst.ctf_first_blood_bonus == 15
    assert dst.ctf_dynamic_scoring is True
    assert dst.ctf_objectives.count() == 1
    assert dst.ctf_questions.get().check_answer("workstation-01")

    with pytest.raises(ctf.ScenarioImportError):
        ctf.import_scenario(dst, "not: [valid: yaml")


# ------------------------------------------------------------------ Practice vs Competition (Blind) Mode & Web UI


def test_competition_blind_mode_hides_verdicts_and_leaderboard_from_solvers(client, user, analyst_user):
    case = Case.objects.create(name="Exam CTF", user=user, is_ctf=True, ctf_mode=Case.CTF_MODE_COMPETITION)
    case.collaborators.add(analyst_user)
    ctf.create_objective(
        case,
        title="Hidden Malware",
        entity_type="process",
        criteria={"pid": 999, "name": "evil.exe"},
        points=100,
    )

    client.force_login(analyst_user)
    resp = client.post(
        reverse("website:case_ctf_discovery_submit", args=[case.pk]),
        {"plugin": "windows.pslist.PsList", "result_row": json.dumps({"PID": 999, "ImageFileName": "evil.exe"})},
    )
    body = resp.content.decode()
    assert "Competition mode: evaluation hidden" in body
    assert "Blind grading active" in body
    assert "Discovered +" not in body

    # Instructor still sees full leaderboard & criteria
    client.force_login(user)
    inst_body = client.get(reverse("website:case_ctf", args=[case.pk])).content.decode()
    assert analyst_user.username in inst_body
    assert "&quot;pid&quot;: 999" in inst_body


def test_row_action_ctf_discovery_modal_and_ui_management(client, user, analyst_user):
    case = Case.objects.create(name="Live Triage CTF", user=user, is_ctf=True)
    case.collaborators.add(analyst_user)

    # Instructor adds objective + updates settings via UI
    client.force_login(user)
    resp = client.post(
        reverse("website:case_ctf_objective_create", args=[case.pk]),
        {
            "title": "Malicious C2",
            "entity_type": "network",
            "criteria": json.dumps({"foreign_ip": "203.0.113.5", "foreign_port": 443}),
            "points": 100,
            "required_mitre": "T1071",
            "mitre_bonus": 25,
            "order": 1,
        },
    )
    assert "Discovery objective &#x27;Malicious C2&#x27; added." in resp.content.decode()

    resp = client.post(
        reverse("website:case_ctf_settings", args=[case.pk]),
        {"ctf_mode": "practice", "ctf_fp_penalty": 10, "ctf_first_blood_bonus": 15, "ctf_dynamic_scoring": "on"},
    )
    assert "CTF challenge settings updated." in resp.content.decode()
    case.refresh_from_db()
    assert case.ctf_fp_penalty == 10
    assert case.ctf_first_blood_bonus == 15
    assert case.ctf_dynamic_scoring is True

    # Student opens modal from Volatility row action (base64-encoded row) and submits
    client.force_login(analyst_user)
    row_b64 = base64.b64encode(json.dumps({"ForeignAddr": "203.0.113.5", "ForeignPort": 443}).encode()).decode()
    modal_get = client.get(
        reverse("website:ctf_discovery_modal"),
        {"plugin": "windows.netscan.NetScan", "result_row": row_b64},
    )
    assert modal_get.status_code == 200
    assert "Submit Artifact as CTF Discovery" in modal_get.content.decode()

    modal_post = client.post(
        reverse("website:ctf_discovery_modal"),
        {
            "case": case.pk,
            "plugin": "windows.netscan.NetScan",
            "result_row": row_b64,
            "submitted_mitre": "T1071.001",
        },
    )
    html = modal_post.content.decode()
    assert "Match! Discovered &#x27;Malicious C2&#x27;" in html
    assert "MITRE bonus" in html
    assert "First Blood!" in html
    assert CTFDiscoverySubmission.objects.filter(case=case, user=analyst_user, is_tp=True).count() == 1


# ------------------------------------------------------------------ REST API Tests


def test_ctf_discovery_rest_api_full_flow(client, user, analyst_user, readonly_user):
    case = Case.objects.create(name="API CTF", user=user, is_ctf=True)
    case.collaborators.add(analyst_user)
    ev = Evidence.objects.create(
        case=case,
        name="Injected VAD",
        plugin="windows.malfind.Malfind",
        result_row={"PID": 5000, "Start VPN": "0x10000000"},
    )
    Finding.objects.create(case=case, evidence=ev, severity="High", mitre_attack_technique="T1055")

    # Collaborator forbidden from promoting Golden Case or changing settings
    client.force_login(analyst_user)
    assert client.post(f"/api/cases/{case.pk}/ctf/objectives/from-evidences").status_code == 403
    assert (
        client.patch(
            f"/api/cases/{case.pk}/ctf/settings",
            {"ctf_fp_penalty": 5},
            content_type="application/json",
        ).status_code
        == 403
    )

    # Outsider gets 404
    client.force_login(readonly_user)
    assert client.get(f"/api/cases/{case.pk}/ctf/objectives").status_code == 404

    # Owner promotes Golden Case + exports YAML
    client.force_login(user)
    promo = client.post(f"/api/cases/{case.pk}/ctf/objectives/from-evidences")
    assert promo.status_code == 201
    assert promo.json()["created_count"] == 1

    exp = client.get(f"/api/cases/{case.pk}/ctf/scenario/export?format=yaml")
    assert exp.status_code == 200
    assert "Injected VAD" in exp.json()["content"]

    # Analyst lists objectives (criteria must be hidden!) and submits discovery
    client.force_login(analyst_user)
    objs = client.get(f"/api/cases/{case.pk}/ctf/objectives").json()
    assert len(objs) == 1
    assert objs[0]["criteria"] is None

    sub = client.post(
        f"/api/cases/{case.pk}/ctf/discoveries/submit",
        {
            "plugin": "windows.malfind.Malfind",
            "result_row": {"PID": 5000, "Start VPN": 0x10000000},
            "submitted_mitre": "T1055",
        },
        content_type="application/json",
    )
    assert sub.status_code == 200
    data = sub.json()
    assert data["is_tp"] is True
    assert data["mitre_matched"] is True
    assert data["awarded_points"] == 125

    metrics = client.get(f"/api/cases/{case.pk}/ctf/metrics").json()
    assert metrics["tp"] == 1
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0


# ------------------------------------------------------------------ WebSocket Consumer Tests


def test_ctf_leaderboard_websocket_auth_and_broadcast(user, analyst_user, readonly_user):
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    case = Case.objects.create(name="WS CTF", user=user, is_ctf=True)
    case.collaborators.add(analyst_user)

    async def _run():
        # 1. Anonymous user rejected (4401)
        comm_anon = WebsocketCommunicator(CTFLeaderboardConsumer.as_asgi(), f"/ws/case/{case.pk}/ctf/")
        comm_anon.scope["user"] = AnonymousUser()
        comm_anon.scope["url_route"] = {"kwargs": {"case_id": str(case.pk)}}
        connected, close_code = await comm_anon.connect()
        assert not connected
        assert close_code == 4401

        # 2. Outsider rejected (4403)
        comm_out = WebsocketCommunicator(CTFLeaderboardConsumer.as_asgi(), f"/ws/case/{case.pk}/ctf/")
        comm_out.scope["user"] = readonly_user
        comm_out.scope["url_route"] = {"kwargs": {"case_id": str(case.pk)}}
        connected, close_code = await comm_out.connect()
        assert not connected
        assert close_code == 4403

        # 3. Collaborator connects and receives live leaderboard broadcast
        comm = WebsocketCommunicator(CTFLeaderboardConsumer.as_asgi(), f"/ws/case/{case.pk}/ctf/")
        comm.scope["user"] = analyst_user
        comm.scope["url_route"] = {"kwargs": {"case_id": str(case.pk)}}
        connected, _ = await comm.connect()
        assert connected

        layer = get_channel_layer()
        await layer.group_send(
            f"ctf_case_{case.pk}",
            {
                "type": "ctf_leaderboard_update",
                "case_id": case.pk,
                "leaderboard": [{"rank": 1, "username": analyst_user.username, "total_points": 125}],
            },
        )
        msg = await comm.receive_json_from()
        assert msg["type"] == "ctf_leaderboard_update"
        assert msg["leaderboard"][0]["total_points"] == 125
        await comm.disconnect()

    async_to_sync(_run)()
