import pytest
from django.db import IntegrityError, transaction

from orochi.website.models import Case, CTFHint, CTFQuestion, CTFSubmission

pytestmark = pytest.mark.django_db


@pytest.fixture
def ctf_case(user, analyst_user):
    case = Case.objects.create(name="Training", user=user)
    case.collaborators.add(analyst_user)
    return case


@pytest.fixture
def question(ctf_case):
    q = CTFQuestion(case=ctf_case, question_text="C2 IP?", points=100)
    q.set_answer(" 10.0.0.5 ")
    q.save()
    return q


def _url(case, suffix=""):
    return f"/api/cases/{case.pk}/ctf/{suffix}"


def test_answer_is_hashed_and_normalized(question):
    assert "10.0.0.5" not in question.answer_hash
    assert question.check_answer("10.0.0.5")
    assert question.check_answer("  10.0.0.5\n")
    assert not question.check_answer("10.0.0.6")
    assert CTFQuestion.normalize_answer("ABC") == CTFQuestion.normalize_answer("abc")


def test_owner_creates_question_and_case_becomes_ctf(client, user, ctf_case):
    client.force_login(user)
    resp = client.post(
        _url(ctf_case, "questions"),
        {"question_text": "Malicious PID?", "answer": "4242", "points": 50, "hints": [{"hint_text": "pslist"}]},
        content_type="application/json",
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["points"] == 50
    assert body["hints"][0]["cost"] == 10
    assert "answer" not in body
    ctf_case.refresh_from_db()
    assert ctf_case.is_ctf


@pytest.mark.parametrize(
    "payload",
    [
        {"question_text": "Q", "answer": "   "},
        {"question_text": "", "answer": "x"},
        {"question_text": "Q", "answer": "x", "points": -1},
        {"question_text": "Q", "answer": "x", "points": "many"},
        {"question_text": "Q", "answer": "x", "hints": [{"hint_text": "h", "cost": -5}]},
    ],
)
def test_create_question_validation(client, user, ctf_case, payload):
    client.force_login(user)
    resp = client.post(_url(ctf_case, "questions"), payload, content_type="application/json")
    assert resp.status_code in (400, 422)
    assert not CTFQuestion.objects.filter(case=ctf_case).exists()


def test_collaborator_cannot_manage_questions(client, analyst_user, ctf_case, question):
    client.force_login(analyst_user)
    resp = client.post(
        _url(ctf_case, "questions"), {"question_text": "Q", "answer": "x"}, content_type="application/json"
    )
    assert resp.status_code == 403
    resp = client.delete(_url(ctf_case, f"questions/{question.pk}"))
    assert resp.status_code == 403
    assert CTFQuestion.objects.filter(pk=question.pk).exists()


def test_owner_deletes_question(client, user, ctf_case, question):
    client.force_login(user)
    assert client.delete(_url(ctf_case, f"questions/{question.pk}")).status_code == 200
    assert not CTFQuestion.objects.filter(pk=question.pk).exists()
    assert client.delete(_url(ctf_case, f"questions/{question.pk}")).status_code == 404


def test_outsider_cannot_see_case(client, readonly_user, ctf_case, question):
    client.force_login(readonly_user)
    assert client.get(_url(ctf_case, "questions")).status_code == 404
    resp = client.post(
        _url(ctf_case, f"questions/{question.pk}/submit"), {"answer": "10.0.0.5"}, content_type="application/json"
    )
    assert resp.status_code == 404


def test_hints_hidden_until_unlocked_and_penalty_applied(client, analyst_user, ctf_case, question):
    hint = CTFHint.objects.create(question=question, hint_text="look at netscan", cost=30)
    client.force_login(analyst_user)

    listed = client.get(_url(ctf_case, "questions")).json()
    assert listed[0]["hints"][0] == {"id": hint.pk, "cost": 30, "unlocked": False, "hint_text": None}

    unlocked = client.post(_url(ctf_case, f"hints/{hint.pk}/unlock")).json()
    assert unlocked["hint_text"] == "look at netscan"

    resp = client.post(
        _url(ctf_case, f"questions/{question.pk}/submit"), {"answer": "10.0.0.5"}, content_type="application/json"
    ).json()
    assert resp["is_correct"] is True
    assert resp["awarded_points"] == 70

    again = client.post(
        _url(ctf_case, f"questions/{question.pk}/submit"), {"answer": "10.0.0.5"}, content_type="application/json"
    ).json()
    assert again == {"is_correct": True, "already_solved": True, "awarded_points": 70}
    assert CTFSubmission.objects.filter(question=question, is_correct=True).count() == 1


def test_wrong_answers_are_throttled(client, analyst_user, ctf_case, question):
    client.force_login(analyst_user)
    url = _url(ctf_case, f"questions/{question.pk}/submit")
    for _ in range(10):
        resp = client.post(url, {"answer": "nope"}, content_type="application/json")
        assert resp.json()["is_correct"] is False
    assert client.post(url, {"answer": "10.0.0.5"}, content_type="application/json").status_code == 429


def test_single_correct_submission_enforced_by_database(question, analyst_user):
    CTFSubmission.objects.create(
        question=question, user=analyst_user, submitted_answer="x", is_correct=True, awarded_points=100
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        CTFSubmission.objects.create(
            question=question, user=analyst_user, submitted_answer="x", is_correct=True, awarded_points=100
        )
    # Wrong answers are not limited by the constraint
    CTFSubmission.objects.create(question=question, user=analyst_user, submitted_answer="y", is_correct=False)
    CTFSubmission.objects.create(question=question, user=analyst_user, submitted_answer="z", is_correct=False)


def test_leaderboard_ranking(client, user, analyst_user, reviewer_user, ctf_case, question):
    ctf_case.collaborators.add(reviewer_user)
    q2 = CTFQuestion(case=ctf_case, question_text="PID?", points=50, order=2)
    q2.set_answer("4242")
    q2.save()

    CTFSubmission.objects.create(
        question=question, user=analyst_user, submitted_answer="a", is_correct=True, awarded_points=100
    )
    CTFSubmission.objects.create(
        question=q2, user=analyst_user, submitted_answer="b", is_correct=True, awarded_points=50
    )
    CTFSubmission.objects.create(
        question=question, user=reviewer_user, submitted_answer="a", is_correct=True, awarded_points=70
    )
    CTFSubmission.objects.create(question=q2, user=reviewer_user, submitted_answer="c", is_correct=False)

    client.force_login(user)
    board = client.get(_url(ctf_case, "leaderboard")).json()
    assert [(row["rank"], row["username"], row["total_points"], row["solved_count"]) for row in board] == [
        (1, analyst_user.username, 150, 2),
        (2, reviewer_user.username, 70, 1),
    ]
