"""CTF challenge lifecycle: objective hints, ATT&CK progress, private participant cases and scoreboard."""

import pytest
import yaml
from asgiref.sync import async_to_sync
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.urls import reverse
from guardian.shortcuts import get_objects_for_user

from orochi.website import ctf
from orochi.website.consumers import CTFLeaderboardConsumer
from orochi.website.models import Case, CTFObjectiveHint, Dump, Evidence

pytestmark = pytest.mark.django_db

PROCESS_ROW = {"PID": 4820, "ImageFileName": "svchost.exe"}


@pytest.fixture
def challenge(user):
    case = Case.objects.create(name="Operation Ghost Memory", user=user, is_ctf=True, ctf_fp_penalty=15)
    ctf.create_objective(
        case,
        title="Injected process",
        entity_type="process",
        criteria={"pid": 4820, "name": "svchost.exe"},
        points=150,
        required_mitre="T1055",
        mitre_bonus=50,
        hints=[("Look at malfind", 25), ("PID above 4000", 10)],
    )
    ctf.create_objective(
        case,
        title="C2 channel",
        entity_type="network",
        criteria={"foreign_ip": "198.51.100.23", "foreign_port": 4444},
        points=100,
        required_mitre="T1071",
    )
    # Golden evidence the participants must never see
    Evidence.objects.create(case=case, plugin="windows.pslist.PsList", result_row=PROCESS_ROW, name="GOLDEN-ANSWER")
    return case


# ------------------------------------------------------------------ Objective hints


def test_objective_hint_cost_is_deducted_from_discovery(challenge, analyst_user):
    challenge.collaborators.add(analyst_user)
    obj = challenge.ctf_objectives.get(title="Injected process")
    assert obj.hints.count() == 2

    listed = {o["title"]: o for o in ctf.objectives_for_user(challenge, analyst_user)}
    assert all(h["hint_text"] is None for h in listed["Injected process"]["hints"])

    hint = obj.hints.get(cost=25)
    ctf.unlock_objective_hint(hint, analyst_user)
    listed = {o["title"]: o for o in ctf.objectives_for_user(challenge, analyst_user)}
    unlocked = [h for h in listed["Injected process"]["hints"] if h["unlocked"]]
    assert [h["hint_text"] for h in unlocked] == ["Look at malfind"]

    res = ctf.submit_discovery(
        challenge, analyst_user, plugin="windows.pstree.PsTree", result_row=PROCESS_ROW, submitted_mitre="T1055.012"
    )
    assert res.is_tp and res.mitre_matched
    assert res.awarded_points == 150 + 50 - 25

    ctf.reset_submissions(challenge)
    assert not hint.unlocked_by.exists()


def test_objective_hint_never_makes_points_negative(challenge, analyst_user):
    challenge.collaborators.add(analyst_user)
    obj = challenge.ctf_objectives.get(title="C2 channel")
    CTFObjectiveHint.objects.create(objective=obj, hint_text="Expensive", cost=500)
    ctf.unlock_objective_hint(obj.hints.get(), analyst_user)
    res = ctf.submit_discovery(
        challenge,
        analyst_user,
        plugin="windows.netscan.NetScan",
        result_row={"ForeignAddr": "198.51.100.23", "ForeignPort": 4444},
    )
    assert res.is_tp
    assert res.awarded_points == 0


def test_scenario_roundtrip_keeps_objective_hints(challenge, user):
    exported = yaml.safe_load(ctf.export_scenario(challenge))
    obj = next(o for o in exported["objectives"] if o["title"] == "Injected process")
    assert {"hint_text": "Look at malfind", "cost": 25} in obj["hints"]

    target = Case.objects.create(name="Imported", user=user)
    raw = ctf.export_scenario(challenge)
    raw += "\n" if not raw.endswith("\n") else ""
    summary = ctf.import_scenario(target, raw)
    assert summary["objectives_created"] == 2
    assert target.ctf_objectives.get(title="Injected process").hints.count() == 2

    # Plain string hints, as in the hand-written scenario format
    other = Case.objects.create(name="Hand written", user=user)
    ctf.import_scenario(
        other,
        yaml.safe_dump(
            {
                "objectives": [
                    {
                        "title": "C2",
                        "entity_type": "network",
                        "canonical_match": {"foreign_ip": "198.51.100.23"},
                        "hints": ["Check netscan", {"text": "High ports", "cost": 25}],
                    }
                ]
            }
        ),
    )
    hints = list(other.ctf_objectives.get().hints.values_list("hint_text", "cost"))
    assert sorted(hints) == [("Check netscan", 10), ("High ports", 25)]

    with pytest.raises(ctf.ScenarioImportError):
        ctf.import_scenario(
            other,
            yaml.safe_dump(
                {"objectives": [{"title": "x", "criteria": {"a": 1}, "hints": [{"cost": -5, "text": "neg"}]}]}
            ),
        )


# ------------------------------------------------------------------ ATT&CK progress


def test_attack_progress_hides_unattributed_techniques_from_participants(challenge, analyst_user, user):
    challenge.collaborators.add(analyst_user)

    manager_view = ctf.attack_progress(challenge, user)
    manager_ids = {t["id"] for tac in manager_view["tactics"] for t in tac["techniques"]}
    assert manager_ids == {"T1055", "T1071"}
    assert manager_view["total"] == 2

    before = ctf.attack_progress(challenge, analyst_user)
    assert before["total"] == 2 and before["attributed"] == 0
    assert before["tactics"] == []

    ctf.submit_discovery(
        challenge, analyst_user, plugin="windows.pslist.PsList", result_row=PROCESS_ROW, submitted_mitre="T1055"
    )
    after = ctf.attack_progress(challenge, analyst_user)
    assert after["attributed"] == 1 and after["pct"] == 50.0
    assert {t["id"] for tac in after["tactics"] for t in tac["techniques"]} == {"T1055"}

    solves = {
        t["id"]: t["solves"] for tac in ctf.attack_progress(challenge, user)["tactics"] for t in tac["techniques"]
    }
    assert solves["T1055"] == 1


# ------------------------------------------------------------------ Private participant cases


def test_start_challenge_creates_private_case_and_shares_dumps(challenge, analyst_user, dump):
    with pytest.raises(PermissionError):
        ctf.start_challenge(challenge, analyst_user)

    ctf.update_settings(challenge, ctf_published=True, ctf_dumps=[dump])
    assert dump not in get_objects_for_user(analyst_user, "website.can_see", klass=Dump)

    private = ctf.start_challenge(challenge, analyst_user)
    assert private.user == analyst_user
    assert private.ctf_template == challenge
    assert private.is_ctf
    assert dump in get_objects_for_user(analyst_user, "website.can_see", klass=Dump)
    # Idempotent: starting again returns the same private case
    assert ctf.start_challenge(challenge, analyst_user).pk == private.pk
    # The owner never gets a copy
    assert ctf.start_challenge(challenge, challenge.user).pk == challenge.pk

    # Participants reach the challenge for CTF purposes only
    assert ctf.get_ctf_case_for_user(private.pk, analyst_user) == challenge
    assert ctf.get_ctf_case_for_user(challenge.pk, analyst_user) == challenge
    assert ctf.get_case_for_user(challenge.pk, analyst_user) is None
    assert not ctf.can_manage(challenge, analyst_user)
    assert ctf.workspace_case_for_user(challenge, analyst_user) == private

    with pytest.raises(ValueError):
        ctf.update_settings(private, ctf_published=True)


def test_start_challenge_avoids_case_name_collisions(challenge, analyst_user):
    Case.objects.create(name=f"{challenge.name} - CTF", user=analyst_user)
    ctf.update_settings(challenge, ctf_published=True)
    private = ctf.start_challenge(challenge, analyst_user)
    assert private.name == f"{challenge.name} - CTF (2)"


def test_participant_panel_uses_private_evidence_and_scores_on_challenge(
    client, challenge, analyst_user, readonly_user
):
    ctf.update_settings(challenge, ctf_published=True)
    private = ctf.start_challenge(challenge, analyst_user)
    own = Evidence.objects.create(
        case=private, plugin="windows.pstree.PsTree", result_row=PROCESS_ROW, name="MY-OWN-EVIDENCE"
    )

    client.force_login(analyst_user)
    # The challenge case itself stays private
    assert client.get(reverse("website:case_detail", args=[challenge.pk])).status_code == 404

    body = client.get(reverse("website:case_ctf", args=[private.pk])).content.decode()
    assert "Injected process" in body
    assert "MY-OWN-EVIDENCE" in body
    assert "GOLDEN-ANSWER" not in body
    assert "Look at malfind" not in body

    resp = client.post(
        reverse("website:case_ctf_discovery_submit", args=[challenge.pk]),
        {"evidence_id": own.pk, "submitted_mitre": "T1055"},
    )
    assert resp.status_code == 200
    assert "Match!" in resp.content.decode()
    assert challenge.ctf_discovery_submissions.filter(user=analyst_user, is_tp=True).count() == 1

    # Golden evidence of the challenge cannot be submitted by id
    golden = challenge.evidences.get(name="GOLDEN-ANSWER")
    resp = client.post(reverse("website:case_ctf_discovery_submit", args=[challenge.pk]), {"evidence_id": golden.pk})
    assert resp.status_code == 404

    hint = challenge.ctf_objectives.get(title="C2 channel")
    hint = CTFObjectiveHint.objects.create(objective=hint, hint_text="netscan", cost=5)
    resp = client.post(reverse("website:case_ctf_objective_unlock", args=[private.pk, hint.pk]))
    assert resp.status_code == 200
    assert hint.unlocked_by.filter(pk=analyst_user.pk).exists()

    # A collaborator of the private case sees the student's evidence, never the Golden Case
    user_b = get_user_model().objects.create_user("buddy", "buddy@example.com", "password")
    private.collaborators.add(user_b)
    client.force_login(user_b)
    body = client.get(reverse("website:case_ctf", args=[private.pk])).content.decode()
    assert "MY-OWN-EVIDENCE" in body and "GOLDEN-ANSWER" not in body

    # An outsider without a private case sees nothing
    client.force_login(readonly_user)
    assert client.get(reverse("website:case_ctf", args=[challenge.pk])).status_code == 404
    assert client.get(reverse("website:case_ctf_scoreboard", args=[challenge.pk])).status_code == 404


def test_challenge_list_start_and_scoreboard_views(client, challenge, analyst_user, user):
    client.force_login(analyst_user)
    assert challenge.name not in client.get(reverse("website:ctf_challenges")).content.decode()
    assert client.post(reverse("website:ctf_challenge_start", args=[challenge.pk])).status_code == 404

    ctf.update_settings(challenge, ctf_published=True)
    page = client.get(reverse("website:ctf_challenges")).content.decode()
    assert challenge.name in page and "Start challenge" in page

    resp = client.post(reverse("website:ctf_challenge_start", args=[challenge.pk]))
    private = Case.objects.get(user=analyst_user, ctf_template=challenge)
    assert resp.status_code == 302
    assert resp.url == reverse("website:case_detail", args=[private.pk])
    assert "Continue" in client.get(reverse("website:ctf_challenges")).content.decode()

    ctf.submit_discovery(challenge, analyst_user, plugin="windows.pslist.PsList", result_row=PROCESS_ROW)
    board = client.get(reverse("website:case_ctf_scoreboard", args=[challenge.pk]))
    assert board.status_code == 200
    text = board.content.decode()
    assert analyst_user.username in text and "Injected process" in text
    assert 'data-testid="ctf-solve-timeline"' in text

    ctf.update_settings(challenge, ctf_mode=Case.CTF_MODE_COMPETITION)
    blind = client.get(reverse("website:case_ctf_scoreboard", args=[challenge.pk])).content.decode()
    assert "Competition mode is active" in blind
    assert 'data-testid="ctf-solve-timeline"' not in blind

    client.force_login(user)
    inst = client.get(reverse("website:case_ctf_scoreboard", args=[challenge.pk])).content.decode()
    assert 'data-testid="ctf-solve-timeline"' in inst


def test_settings_view_publishes_and_selects_dumps(client, challenge, user, dump):
    client.force_login(user)
    resp = client.post(
        reverse("website:case_ctf_settings", args=[challenge.pk]),
        {
            "ctf_mode": "practice",
            "ctf_fp_penalty": 15,
            "ctf_first_blood_bonus": 0,
            "ctf_published": "on",
            "ctf_dumps": [dump.pk],
        },
    )
    assert resp.status_code == 200
    challenge.refresh_from_db()
    # The instructor cannot see the admin's dump, so it is not attached
    assert challenge.ctf_published
    assert not challenge.ctf_dumps.exists()


def test_participant_websocket_and_rest_api(client, challenge, analyst_user):
    ctf.update_settings(challenge, ctf_published=True)

    client.force_login(analyst_user)
    listed = client.get("/api/cases/ctf/challenges").json()
    assert [c["id"] for c in listed] == [challenge.pk]
    assert listed[0]["private_case_id"] is None

    started = client.post(f"/api/cases/ctf/challenges/{challenge.pk}/start")
    assert started.status_code == 201
    private_id = started.json()["case_id"]
    assert client.get("/api/cases/ctf/challenges").json()[0]["private_case_id"] == private_id

    objs = client.get(f"/api/cases/{private_id}/ctf/objectives").json()
    hint_id = next(o for o in objs if o["title"] == "Injected process")["hints"][0]["id"]
    unlocked = client.post(f"/api/cases/{private_id}/ctf/objective-hints/{hint_id}/unlock")
    assert unlocked.status_code == 200 and unlocked.json()["unlocked"]

    progress = client.get(f"/api/cases/{private_id}/ctf/attack-progress").json()
    assert progress["total"] == 2 and progress["tactics"] == []

    async def _run():
        comm = WebsocketCommunicator(CTFLeaderboardConsumer.as_asgi(), f"/ws/case/{challenge.pk}/ctf/")
        comm.scope["user"] = analyst_user
        comm.scope["url_route"] = {"kwargs": {"case_id": str(challenge.pk)}}
        connected, _ = await comm.connect()
        assert connected
        await comm.disconnect()

    async_to_sync(_run)()
