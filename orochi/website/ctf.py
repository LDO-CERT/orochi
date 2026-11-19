"""Graded exercise / CTF mode (#1542): rules shared by the REST API and the case page."""

from dataclasses import dataclass
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.db.models import Count, Max, Q, Sum
from django.utils import timezone

from orochi.website.models import Case, CTFHint, CTFQuestion, CTFSubmission

MAX_WRONG_ATTEMPTS_PER_MINUTE = 10


class TooManyAttempts(Exception):
    """Raised when a user submits too many wrong answers to the same question."""


@dataclass
class SubmissionResult:
    is_correct: bool
    already_solved: bool
    awarded_points: int
    submission_id: int | None = None


def get_case_for_user(case_id: int, user) -> Case | None:
    """Case visible to the user: owner, collaborator or superuser."""
    cases = Case.objects.all() if user.is_superuser else Case.objects.filter(Q(user=user) | Q(collaborators=user))
    return cases.filter(pk=case_id).distinct().first()


def can_manage(case: Case, user) -> bool:
    """Only the case owner (the instructor) or a superuser defines questions and sees all hints."""
    return user.is_superuser or case.user_id == user.pk


def questions_for_user(case: Case, user) -> list[dict]:
    """Questions with solve state and hints; hint text is hidden until unlocked (except for managers)."""
    manager = can_manage(case, user)
    solved = {
        s.question_id: s.awarded_points
        for s in CTFSubmission.objects.filter(question__case=case, user=user, is_correct=True)
    }
    unlocked_ids = set(CTFHint.objects.filter(question__case=case, unlocked_by=user).values_list("pk", flat=True))

    out = []
    for q in CTFQuestion.objects.filter(case=case).prefetch_related("hints"):
        hints = []
        for h in q.hints.all():
            unlocked = manager or h.pk in unlocked_ids
            hints.append(
                {"id": h.pk, "cost": h.cost, "unlocked": unlocked, "hint_text": h.hint_text if unlocked else None}
            )
        out.append(
            {
                "id": q.pk,
                "order": q.order,
                "question_text": q.question_text,
                "points": q.points,
                "solved": q.pk in solved,
                "awarded_points": solved.get(q.pk),
                "hints": hints,
            }
        )
    return out


def create_question(
    case: Case, question_text: str, answer: str, points: int = 100, order: int = 1, hints=()
) -> CTFQuestion:
    """Create a question (storing only the answer hash) and turn the case into CTF mode.

    hints: iterable of (hint_text, cost) pairs.
    """
    with transaction.atomic():
        if not case.is_ctf:
            case.is_ctf = True
            case.save(update_fields=["is_ctf"])
        question = CTFQuestion(case=case, question_text=question_text, points=points, order=order)
        question.set_answer(answer)
        question.save()
        for hint_text, cost in hints:
            CTFHint.objects.create(question=question, hint_text=hint_text, cost=cost)
    return question


def submit_answer(question: CTFQuestion, user, answer: str) -> SubmissionResult:
    """Score an answer once per user, net of the hints unlocked before solving."""
    if solved := CTFSubmission.objects.filter(question=question, user=user, is_correct=True).first():
        return SubmissionResult(True, True, solved.awarded_points)

    # Throttle brute forcing of short answers (IPs, PIDs, ports, ...)
    recent_wrong = CTFSubmission.objects.filter(
        question=question,
        user=user,
        is_correct=False,
        submitted_at__gte=timezone.now() - timedelta(minutes=1),
    ).count()
    if recent_wrong >= MAX_WRONG_ATTEMPTS_PER_MINUTE:
        raise TooManyAttempts("Too many wrong answers, retry in a minute")

    answer = answer.strip()
    is_correct = question.check_answer(answer)
    awarded_points = 0
    if is_correct:
        hint_penalty = sum(h.cost for h in question.hints.filter(unlocked_by=user))
        awarded_points = max(0, question.points - hint_penalty)

    try:
        with transaction.atomic():
            submission = CTFSubmission.objects.create(
                question=question,
                user=user,
                submitted_answer=answer,
                is_correct=is_correct,
                awarded_points=awarded_points,
            )
    except IntegrityError:
        # A concurrent request already scored this question for the user
        solved = CTFSubmission.objects.get(question=question, user=user, is_correct=True)
        return SubmissionResult(True, True, solved.awarded_points)
    return SubmissionResult(is_correct, False, awarded_points, submission.pk)


def unlock_hint(hint: CTFHint, user) -> None:
    hint.unlocked_by.add(user)


def leaderboard(case: Case) -> list[dict]:
    """Users ranked by points, then solved questions, then earliest last solve."""
    rows = (
        CTFSubmission.objects.filter(question__case=case, is_correct=True)
        .values("user_id", "user__username")
        .annotate(
            total_points=Sum("awarded_points"),
            solved_count=Count("question", distinct=True),
            last_solve_at=Max("submitted_at"),
        )
        .order_by("-total_points", "-solved_count", "last_solve_at")
    )
    return [
        {
            "rank": idx,
            "user_id": row["user_id"],
            "username": row["user__username"],
            "total_points": row["total_points"],
            "solved_count": row["solved_count"],
            "last_solve_at": row["last_solve_at"],
        }
        for idx, row in enumerate(rows, start=1)
    ]
