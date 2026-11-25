from pathlib import Path

import pytest
from django.conf import settings
from django.urls import reverse

from orochi.website import ctf
from orochi.website.defaults import SERVICE_CAPE
from orochi.website.forms import CTFQuestionForm
from orochi.website.models import Case, CTFHint, CTFQuestion, CTFSubmission, Evidence, Service

pytestmark = pytest.mark.django_db


# ------------------------------------------------------------------ CTF panel
@pytest.fixture
def ctf_case(user, analyst_user):
    case = Case.objects.create(name="Training", user=user, is_ctf=True)
    case.collaborators.add(analyst_user)
    return case


@pytest.fixture
def question(ctf_case):
    q = ctf.create_question(ctf_case, "Which IP is the C2?", "10.0.0.5", points=100, hints=[("netscan", 30)])
    return q


def _panel(client, case):
    return client.get(reverse("website:case_ctf", args=[case.pk])).content.decode()


def test_case_page_loads_ctf_panel_only_for_ctf_cases(client, user, ctf_case):
    client.force_login(user)
    detail = reverse("website:case_detail", args=[ctf_case.pk])
    assert (
        reverse("website:case_ctf", args=[ctf_case.pk]) in client.get(detail, HTTP_HX_REQUEST="true").content.decode()
    )

    ctf_case.is_ctf = False
    ctf_case.save()
    assert (
        reverse("website:case_ctf", args=[ctf_case.pk])
        not in client.get(detail, HTTP_HX_REQUEST="true").content.decode()
    )


def test_student_view(client, analyst_user, ctf_case, question):
    client.force_login(analyst_user)
    page = _panel(client, ctf_case)
    assert "Which IP is the C2?" in page
    assert reverse("website:case_ctf_submit", args=[ctf_case.pk, question.pk]) in page
    assert "Unlock hint 1 (-30 pts)" in page
    assert "netscan" not in page  # hint text hidden until unlocked
    assert "Add question" not in page
    assert "0</span> / 100 pts" in page


def test_instructor_view(client, user, ctf_case, question):
    client.force_login(user)
    page = _panel(client, ctf_case)
    assert "Instructor view" in page
    assert "netscan" in page
    assert "Add question" in page
    assert reverse("website:case_ctf_question_delete", args=[ctf_case.pk, question.pk]) in page
    assert reverse("website:case_ctf_submit", args=[ctf_case.pk, question.pk]) not in page


def test_student_solves_after_hint(client, analyst_user, ctf_case, question):
    client.force_login(analyst_user)
    hint = question.hints.get()

    page = client.post(reverse("website:case_ctf_unlock", args=[ctf_case.pk, hint.pk])).content.decode()
    assert "netscan" in page

    submit = reverse("website:case_ctf_submit", args=[ctf_case.pk, question.pk])
    page = client.post(submit, {"answer": "10.0.0.9"}).content.decode()
    assert "Wrong answer for Q1." in page

    page = client.post(submit, {"answer": " 10.0.0.5 "}).content.decode()
    assert "Correct! +70 points." in page
    assert "Solved +70" in page
    assert analyst_user.username in page  # leaderboard

    page = client.post(submit, {"answer": "10.0.0.5"}).content.decode()
    assert "Q1 was already solved." in page
    assert CTFSubmission.objects.filter(user=analyst_user, is_correct=True).count() == 1


def test_empty_answer_and_throttling(client, analyst_user, ctf_case, question):
    client.force_login(analyst_user)
    submit = reverse("website:case_ctf_submit", args=[ctf_case.pk, question.pk])
    assert "Type an answer first." in client.post(submit, {"answer": "  "}).content.decode()
    for _ in range(ctf.MAX_WRONG_ATTEMPTS_PER_MINUTE):
        client.post(submit, {"answer": "nope"})
    assert "Too many wrong answers" in client.post(submit, {"answer": "10.0.0.5"}).content.decode()


def test_instructor_creates_and_deletes_question(client, user, ctf_case):
    client.force_login(user)
    url = reverse("website:case_ctf_question_create", args=[ctf_case.pk])
    page = client.post(
        url,
        {
            "question_text": "Malicious PID?",
            "answer": "4242",
            "points": 50,
            "order": 2,
            "hints": "pslist\n25 | parent is winword",
        },
    ).content.decode()
    assert "Question Q2 added." in page
    question = CTFQuestion.objects.get(case=ctf_case)
    assert question.check_answer("4242")
    assert sorted((h.hint_text, h.cost) for h in question.hints.all()) == [("parent is winword", 25), ("pslist", 10)]

    page = client.post(reverse("website:case_ctf_question_delete", args=[ctf_case.pk, question.pk])).content.decode()
    assert "Question Q2 deleted." in page
    assert not CTFQuestion.objects.filter(case=ctf_case).exists()


def test_invalid_question_keeps_form_open_with_errors(client, user, ctf_case):
    client.force_login(user)
    page = client.post(
        reverse("website:case_ctf_question_create", args=[ctf_case.pk]),
        {"question_text": "Q", "answer": "  ", "points": 10, "order": 1},
    ).content.decode()
    assert "The question was not saved" in page
    assert "This field is required." in page
    assert "<details" in page and "open>" in page
    assert not CTFQuestion.objects.exists()


@pytest.mark.parametrize(
    ("hints", "valid"),
    [("a\nb", True), ("5 | a", True), ("x | a", False), ("-1 | a", False), ("5 |  ", False)],
)
def test_question_form_hint_parsing(hints, valid):
    form = CTFQuestionForm({"question_text": "Q", "answer": "a", "points": 1, "order": 1, "hints": hints})
    assert form.is_valid() is valid


def test_collaborator_cannot_manage(client, analyst_user, ctf_case, question):
    client.force_login(analyst_user)
    create = reverse("website:case_ctf_question_create", args=[ctf_case.pk])
    assert client.post(create, {"question_text": "Q", "answer": "a", "points": 1, "order": 1}).status_code == 403
    delete = reverse("website:case_ctf_question_delete", args=[ctf_case.pk, question.pk])
    assert client.post(delete).status_code == 403
    assert CTFQuestion.objects.filter(pk=question.pk).exists()


def test_outsider_gets_404(client, readonly_user, ctf_case, question):
    client.force_login(readonly_user)
    assert client.get(reverse("website:case_ctf", args=[ctf_case.pk])).status_code == 404
    submit = reverse("website:case_ctf_submit", args=[ctf_case.pk, question.pk])
    assert client.post(submit, {"answer": "10.0.0.5"}).status_code == 404
    hint = CTFHint.objects.get(question=question)
    assert client.post(reverse("website:case_ctf_unlock", args=[ctf_case.pk, hint.pk])).status_code == 404


# ------------------------------------------------------------------ Sandbox
@pytest.fixture
def cape(db):
    return Service.objects.create(name=SERVICE_CAPE, url="https://cape.local/apiv2", key="token")


@pytest.fixture
def extracted(dump):
    path = Path(settings.MEDIA_ROOT) / str(dump.index) / "windows.pslist" / "pid.4242.exe"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"MZ")
    return path


class FakeResponse:
    status_code = 201
    content = b"{}"

    @staticmethod
    def json():
        return {"data": {"task_ids": [77]}}


def test_sandbox_modal_and_submission(client, admin, dump, cape, extracted, monkeypatch):
    sent = {}

    def fake_post(url, **kwargs):
        sent.update(url=url, data=kwargs["data"])
        return FakeResponse()

    monkeypatch.setattr("orochi.website.integrations.requests.post", fake_post)
    client.force_login(admin)
    url = reverse("website:sandbox_submit")

    modal = client.get(url, {"index": dump.index, "path": str(extracted)}).content.decode()
    assert "pid.4242.exe" in modal and "Send to Sandbox" in modal

    page = client.post(
        url, {"index": dump.index, "path": str(extracted), "machine": "win10", "tags": "x64"}
    ).content.decode()
    assert "Sandbox task <strong>#77</strong> created." in page
    assert "https://cape.local/submit/status/77/" in page
    assert sent["url"] == "https://cape.local/apiv2/tasks/create/file/"
    assert sent["data"]["machine"] == "win10"


def test_sandbox_rejects_files_outside_dump(client, admin, dump, cape, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("x")
    client.force_login(admin)
    page = client.post(reverse("website:sandbox_submit"), {"index": dump.index, "path": str(secret)}).content.decode()
    assert "only files extracted from this dump" in page


def test_sandbox_requires_service_visibility_and_role(
    client, admin, analyst_user, readonly_user, dump, extracted, cape
):
    url = reverse("website:sandbox_submit")
    params = {"index": dump.index, "path": str(extracted)}

    client.force_login(analyst_user)  # cannot see the dump
    assert client.get(url, params).status_code == 404

    client.force_login(readonly_user)
    assert client.get(url, params).status_code == 403

    cape.delete()
    client.force_login(admin)
    assert client.get(url, params).status_code == 400


def test_evidence_shows_sandbox_button_only_when_configured(client, user, dump, extracted):
    case = Case.objects.create(name="IR", user=user)
    Evidence.objects.create(case=case, dump=dump, name="dropper", extracted_file=str(extracted))
    client.force_login(user)
    detail = reverse("website:case_detail", args=[case.pk])

    page = client.get(detail, HTTP_HX_REQUEST="true").content.decode()
    assert "pid.4242.exe" in page
    assert reverse("website:sandbox_submit") not in page

    Service.objects.create(name=SERVICE_CAPE, url="https://cape.local", key="k")
    page = client.get(detail, HTTP_HX_REQUEST="true").content.decode()
    assert reverse("website:sandbox_submit") in page


def test_sandbox_network_error_is_readable(client, admin, dump, cape, extracted, monkeypatch):
    import requests

    def unreachable(url, **kwargs):
        raise requests.ConnectionError("HTTPSConnectionPool(host='cape.local'): Max retries exceeded")

    monkeypatch.setattr("orochi.website.integrations.requests.post", unreachable)
    client.force_login(admin)
    page = client.post(
        reverse("website:sandbox_submit"), {"index": dump.index, "path": str(extracted)}
    ).content.decode()
    assert "Cannot reach the sandbox at https://cape.local/apiv2" in page
    assert "Max retries" not in page


def test_row_actions_render_sandbox_button():
    from django.template.loader import render_to_string

    ctx = {"down_path": "/media/abc/windows.pslist/pid.1.exe", "dump": "abc", "plugin": "windows.pslist"}
    assert reverse("website:sandbox_submit") not in render_to_string("website/row_actions.html", ctx)
    html = render_to_string("website/row_actions.html", {**ctx, "sandbox_configured": True})
    assert reverse("website:sandbox_submit") in html
    assert '"path": "/media/abc/windows.pslist/pid.1.exe"' in html
    # No sandbox button for rows without an extracted file
    assert reverse("website:sandbox_submit") not in render_to_string(
        "website/row_actions.html", {**ctx, "down_path": None, "sandbox_configured": True}
    )
