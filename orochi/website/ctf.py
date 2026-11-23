"""Graded exercise / CTF mode (#1542): Jeopardy + Forensic Discovery engine shared by Web UI, REST API, and Channels."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import yaml
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.utils import timezone

from orochi.website.attack import parse_technique_ids
from orochi.website.ctf_matcher import (
    build_criteria_from_evidence,
    extract_canonical_entity,
    matches_objective,
)
from orochi.website.models import (
    Case,
    CTFDiscoverySubmission,
    CTFHint,
    CTFObjective,
    CTFQuestion,
    CTFSubmission,
    Evidence,
)

logger = logging.getLogger(__name__)

MAX_WRONG_ATTEMPTS_PER_MINUTE = 10
DYNAMIC_SCORING_MIN_RATIO = 0.5
DYNAMIC_SCORING_DECAY = 0.85


class TooManyAttempts(Exception):
    """Raised when a user submits too many wrong answers to the same question."""


class ScenarioImportError(Exception):
    """Raised when a YAML/JSON CTF scenario payload is invalid."""


@dataclass
class SubmissionResult:
    is_correct: bool
    already_solved: bool
    awarded_points: int
    submission_id: int | None = None
    is_first_blood: bool = False


@dataclass
class DiscoverySubmissionResult:
    is_tp: bool
    is_fp: bool
    is_duplicate: bool
    is_first_blood: bool
    mitre_matched: bool
    awarded_points: int
    objective_id: int | None = None
    objective_title: str | None = None
    submission_id: int | None = None
    blind: bool = False


def get_case_for_user(case_id: int, user) -> Case | None:
    """Case visible to the user: owner, collaborator or superuser."""
    cases = Case.objects.all() if user.is_superuser else Case.objects.filter(Q(user=user) | Q(collaborators=user))
    return cases.filter(pk=case_id).distinct().first()


def can_manage(case: Case, user) -> bool:
    """Only the case owner (the instructor) or a superuser defines questions/objectives and sees all hints."""
    return user.is_superuser or case.user_id == user.pk


def compute_effective_points(base_points: int, prior_solves: int, dynamic_scoring: bool) -> int:
    """Compute effective base points with optional CTFd-style decay as more analysts solve the item."""
    if not dynamic_scoring or prior_solves <= 0 or base_points <= 0:
        return base_points
    ratio = DYNAMIC_SCORING_MIN_RATIO + (1.0 - DYNAMIC_SCORING_MIN_RATIO) * (DYNAMIC_SCORING_DECAY**prior_solves)
    return max(1, round(base_points * ratio))


def compute_first_blood_bonus(base_points: int, bonus_pct: int, prior_solves: int) -> tuple[bool, int]:
    """Return (is_first_blood, bonus_points) when the user is the first solver and bonus_pct > 0."""
    if prior_solves == 0 and bonus_pct > 0 and base_points > 0:
        return True, round(base_points * bonus_pct / 100)
    return False, 0


def _mitre_matches(required_mitre: str, submitted_mitre: str) -> bool:
    """Check whether submitted MITRE ATT&CK technique(s) satisfy required_mitre (supports sub-technique match)."""
    req_ids = parse_technique_ids(required_mitre)
    if not req_ids:
        return False
    sub_ids = parse_technique_ids(submitted_mitre)
    if not sub_ids:
        return False
    for req in req_ids:
        for sub in sub_ids:
            if sub == req or sub.startswith(f"{req}."):
                return True
    return False


def broadcast_ctf_leaderboard(case: Case) -> None:
    """Push a real-time leaderboard refresh event to connected CTF WebSocket clients."""
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return
        rows = leaderboard(case)
        serialized = [
            {
                **row,
                "last_solve_at": row["last_solve_at"].isoformat() if row.get("last_solve_at") else None,
            }
            for row in rows
        ]
        async_to_sync(channel_layer.group_send)(
            f"ctf_case_{case.pk}",
            {
                "type": "ctf_leaderboard_update",
                "case_id": case.pk,
                "leaderboard": serialized,
            },
        )
    except Exception:
        logger.debug("CTF WebSocket broadcast skipped for case %s", case.pk, exc_info=True)


# ------------------------------------------------------------------ Jeopardy Questions


def questions_for_user(case: Case, user) -> list[dict]:
    """Questions with solve state and hints; hint text is hidden until unlocked (except for managers)."""
    manager = can_manage(case, user)
    blind = case.ctf_mode == Case.CTF_MODE_COMPETITION and not manager
    solved = {
        s.question_id: s.awarded_points
        for s in CTFSubmission.objects.filter(question__case=case, user=user, is_correct=True)
    }
    attempted_ids = set(
        CTFSubmission.objects.filter(question__case=case, user=user).values_list("question_id", flat=True)
    )
    unlocked_ids = set(CTFHint.objects.filter(question__case=case, unlocked_by=user).values_list("pk", flat=True))

    wrong_counts = {}
    unlock_counts = {}
    if manager:
        wrong_counts = dict(
            CTFSubmission.objects.filter(question__case=case, is_correct=False)
            .values_list("question_id")
            .annotate(c=Count("id"))
        )
        unlock_counts = dict(
            CTFHint.objects.filter(question__case=case)
            .values("question_id")
            .annotate(c=Count("unlocked_by"))
            .values_list("question_id", "c")
        )

    out = []
    for q in CTFQuestion.objects.filter(case=case).prefetch_related("hints"):
        hints = []
        hints_lines = []
        for h in q.hints.all():
            unlocked = manager or h.pk in unlocked_ids
            hints.append(
                {"id": h.pk, "cost": h.cost, "unlocked": unlocked, "hint_text": h.hint_text if unlocked else None}
            )
            if manager:
                hints_lines.append(f"{h.cost} | {h.hint_text}")
        out.append(
            {
                "id": q.pk,
                "order": q.order,
                "question_text": q.question_text,
                "points": q.points,
                "solved": False if blind else (q.pk in solved),
                "attempted": q.pk in attempted_ids,
                "awarded_points": None if blind else solved.get(q.pk),
                "hints": hints,
                "hints_text": "\n".join(hints_lines),
                "wrong_attempts_count": wrong_counts.get(q.pk, 0),
                "hint_unlocks_count": unlock_counts.get(q.pk, 0),
            }
        )
    return out


def update_question(
    question: CTFQuestion,
    *,
    question_text: str,
    points: int,
    order: int,
    answer: str | None = None,
    hints=None,
) -> CTFQuestion:
    """Update an existing CTF question's text, points, order, optional answer, and optional hints."""
    with transaction.atomic():
        question.question_text = question_text
        question.points = points
        question.order = order
        if answer:
            question.set_answer(answer)
        question.save()
        if hints is not None:
            question.hints.all().delete()
            for hint_text, cost in hints:
                CTFHint.objects.create(question=question, hint_text=hint_text, cost=cost)
    return question


def reset_submissions(case: Case) -> int:
    """Clear all CTF submissions (Jeopardy + Discovery) and hint unlocks for a case."""
    with transaction.atomic():
        deleted_q, _ = CTFSubmission.objects.filter(question__case=case).delete()
        deleted_d, _ = CTFDiscoverySubmission.objects.filter(case=case).delete()
        for hint in CTFHint.objects.filter(question__case=case):
            hint.unlocked_by.clear()
    broadcast_ctf_leaderboard(case)
    return deleted_q + deleted_d


def create_question(
    case: Case, question_text: str, answer: str, points: int = 100, order: int = 1, hints=()
) -> CTFQuestion:
    """Create a question (storing only the answer hash) and turn the case into CTF mode."""
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
    """Score a Jeopardy answer once per user, net of unlocked hints, with optional dynamic scoring & First Blood."""
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
    is_first_blood = False
    case = question.case
    if is_correct:
        prior_solves = CTFSubmission.objects.filter(question=question, is_correct=True).count()
        effective_base = compute_effective_points(question.points, prior_solves, case.ctf_dynamic_scoring)
        is_first_blood, fb_bonus = compute_first_blood_bonus(effective_base, case.ctf_first_blood_bonus, prior_solves)
        hint_penalty = sum(h.cost for h in question.hints.filter(unlocked_by=user))
        awarded_points = max(0, effective_base + fb_bonus - hint_penalty)

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
        solved = CTFSubmission.objects.get(question=question, user=user, is_correct=True)
        return SubmissionResult(True, True, solved.awarded_points)

    if is_correct:
        broadcast_ctf_leaderboard(case)
    return SubmissionResult(is_correct, False, awarded_points, submission.pk, is_first_blood=is_first_blood)


def unlock_hint(hint: CTFHint, user) -> None:
    hint.unlocked_by.add(user)


# ------------------------------------------------------------------ Forensic Discovery (Ground Truth)


def create_objective(
    case: Case,
    *,
    title: str,
    entity_type: str = CTFObjective.ENTITY_GENERIC,
    criteria: dict[str, Any] | None = None,
    description: str = "",
    points: int = 100,
    required_mitre: str = "",
    mitre_bonus: int = 25,
    order: int = 1,
    source_evidence: Evidence | None = None,
) -> CTFObjective:
    """Create a ground-truth forensic discovery objective and enable CTF mode on the case."""
    with transaction.atomic():
        if not case.is_ctf:
            case.is_ctf = True
            case.save(update_fields=["is_ctf"])
        return CTFObjective.objects.create(
            case=case,
            title=title.strip(),
            description=(description or "").strip(),
            entity_type=entity_type or CTFObjective.ENTITY_GENERIC,
            criteria=criteria or {},
            points=points,
            required_mitre=(required_mitre or "").strip().upper(),
            mitre_bonus=mitre_bonus,
            order=order,
            source_evidence=source_evidence,
        )


def promote_evidences_to_objectives(
    case: Case,
    *,
    points: int = 100,
    mitre_bonus: int = 25,
) -> list[CTFObjective]:
    """Golden Case authoring: convert existing Case Evidences (and linked Finding MITRE IDs) into CTFObjectives."""
    created: list[CTFObjective] = []
    existing_evidence_ids = set(
        CTFObjective.objects.filter(case=case, source_evidence__isnull=False).values_list(
            "source_evidence_id", flat=True
        )
    )
    next_order = (CTFObjective.objects.filter(case=case).count()) + 1

    for ev in case.evidences.prefetch_related("findings").all():
        if ev.pk in existing_evidence_ids:
            continue
        row = ev.result_row if isinstance(ev.result_row, dict) else {}
        plugin_name = ev.plugin or ""
        extracted_file = ev.extracted_file or ""
        if not row and not extracted_file:
            continue
        entity_type, criteria = build_criteria_from_evidence(plugin_name, row, extracted_file=extracted_file)
        if not criteria:
            continue

        # Pull first MITRE technique from any linked Finding
        required_mitre = ""
        for finding in ev.findings.all():
            techs = parse_technique_ids(finding.mitre_attack_technique)
            if techs:
                required_mitre = techs[0]
                break

        title = ev.name or f"Discover {entity_type} artifact ({plugin_name or 'evidence'})"
        obj = create_objective(
            case,
            title=title,
            description=ev.description or "",
            entity_type=entity_type,
            criteria=criteria,
            points=points,
            required_mitre=required_mitre,
            mitre_bonus=mitre_bonus,
            order=next_order,
            source_evidence=ev,
        )
        created.append(obj)
        next_order += 1

    return created


def objectives_for_user(case: Case, user) -> list[dict]:
    """Return CTF discovery objectives with solve state; hides ground-truth criteria from non-managers."""
    manager = can_manage(case, user)
    blind = case.ctf_mode == Case.CTF_MODE_COMPETITION and not manager
    solved_map = {
        s.objective_id: s
        for s in CTFDiscoverySubmission.objects.filter(case=case, user=user, is_tp=True, objective__isnull=False)
    }
    solve_counts = dict(
        CTFDiscoverySubmission.objects.filter(case=case, is_tp=True, objective__isnull=False)
        .values_list("objective_id")
        .annotate(c=Count("user_id", distinct=True))
    )

    out = []
    for obj in CTFObjective.objects.filter(case=case):
        sub = solved_map.get(obj.pk)
        out.append(
            {
                "id": obj.pk,
                "order": obj.order,
                "title": obj.title,
                "description": obj.description,
                "entity_type": obj.entity_type,
                "points": obj.points,
                "required_mitre": obj.required_mitre if (manager or (sub and not blind)) else "",
                "has_mitre_bonus": bool(obj.required_mitre),
                "mitre_bonus": obj.mitre_bonus if obj.required_mitre else 0,
                "criteria": obj.criteria if manager else None,
                "criteria_json": json.dumps(obj.criteria, sort_keys=True) if manager else "",
                "solved": False if blind else (sub is not None),
                "awarded_points": None if blind else (sub.awarded_points if sub else None),
                "mitre_matched": False if blind else (sub.mitre_matched if sub else False),
                "is_first_blood": False if blind else (sub.is_first_blood if sub else False),
                "solves_count": solve_counts.get(obj.pk, 0),
            }
        )
    return out


def submit_discovery(
    case: Case,
    user,
    *,
    plugin: str = "",
    result_row: dict[str, Any] | None = None,
    extracted_file: str = "",
    submitted_mitre: str = "",
    evidence: Evidence | None = None,
) -> DiscoverySubmissionResult:
    """Evaluate a submitted forensic artifact against the case's ground-truth CTFObjectives."""
    row = result_row if isinstance(result_row, dict) else {}
    canonical = extract_canonical_entity(plugin, row, extracted_file=extracted_file)
    mitre_clean = (submitted_mitre or "").strip().upper()
    blind = case.ctf_mode == Case.CTF_MODE_COMPETITION and not can_manage(case, user)

    objectives = list(CTFObjective.objects.filter(case=case))
    matched_obj: CTFObjective | None = None
    for obj in objectives:
        if matches_objective(
            obj.entity_type,
            obj.criteria,
            plugin,
            row,
            extracted_file=extracted_file,
            canonical_entity=canonical,
        ):
            matched_obj = obj
            break

    with transaction.atomic():
        if matched_obj is not None:
            already = CTFDiscoverySubmission.objects.filter(
                case=case, user=user, objective=matched_obj, is_tp=True
            ).exists()
            if already:
                sub = CTFDiscoverySubmission.objects.create(
                    case=case,
                    user=user,
                    objective=matched_obj,
                    evidence=evidence,
                    plugin=plugin,
                    result_row=row,
                    canonical_entity=canonical,
                    submitted_mitre=mitre_clean,
                    is_tp=False,
                    is_fp=False,
                    is_duplicate=True,
                    awarded_points=0,
                )
                return DiscoverySubmissionResult(
                    is_tp=False,
                    is_fp=False,
                    is_duplicate=True,
                    is_first_blood=False,
                    mitre_matched=False,
                    awarded_points=0,
                    objective_id=matched_obj.pk,
                    objective_title=matched_obj.title,
                    submission_id=sub.pk,
                    blind=blind,
                )

            prior_solves = CTFDiscoverySubmission.objects.filter(case=case, objective=matched_obj, is_tp=True).count()
            effective_base = compute_effective_points(matched_obj.points, prior_solves, case.ctf_dynamic_scoring)
            is_fb, fb_bonus = compute_first_blood_bonus(effective_base, case.ctf_first_blood_bonus, prior_solves)
            mitre_ok = _mitre_matches(matched_obj.required_mitre, mitre_clean)
            mitre_pts = matched_obj.mitre_bonus if mitre_ok else 0
            total_awarded = effective_base + fb_bonus + mitre_pts

            sub = CTFDiscoverySubmission.objects.create(
                case=case,
                user=user,
                objective=matched_obj,
                evidence=evidence,
                plugin=plugin,
                result_row=row,
                canonical_entity=canonical,
                submitted_mitre=mitre_clean,
                is_tp=True,
                is_fp=False,
                is_duplicate=False,
                is_first_blood=is_fb,
                mitre_matched=mitre_ok,
                awarded_points=total_awarded,
            )
            broadcast_ctf_leaderboard(case)
            return DiscoverySubmissionResult(
                is_tp=True,
                is_fp=False,
                is_duplicate=False,
                is_first_blood=is_fb,
                mitre_matched=mitre_ok,
                awarded_points=total_awarded,
                objective_id=matched_obj.pk,
                objective_title=matched_obj.title,
                submission_id=sub.pk,
                blind=blind,
            )

        # No match -> False Positive penalty
        penalty = -int(case.ctf_fp_penalty) if case.ctf_fp_penalty else 0
        sub = CTFDiscoverySubmission.objects.create(
            case=case,
            user=user,
            objective=None,
            evidence=evidence,
            plugin=plugin,
            result_row=row,
            canonical_entity=canonical,
            submitted_mitre=mitre_clean,
            is_tp=False,
            is_fp=True,
            is_duplicate=False,
            awarded_points=penalty,
        )

    broadcast_ctf_leaderboard(case)
    return DiscoverySubmissionResult(
        is_tp=False,
        is_fp=True,
        is_duplicate=False,
        is_first_blood=False,
        mitre_matched=False,
        awarded_points=penalty,
        submission_id=sub.pk,
        blind=blind,
    )


def user_discovery_metrics(case: Case, user) -> dict[str, Any]:
    """Compute IR quality metrics (TP, FP, FN, Precision, Recall, F1) for a user on a CTF case."""
    total_objectives = CTFObjective.objects.filter(case=case).count()
    subs = list(CTFDiscoverySubmission.objects.filter(case=case, user=user))
    tp = sum(1 for s in subs if s.is_tp)
    fp = sum(1 for s in subs if s.is_fp)
    duplicates = sum(1 for s in subs if s.is_duplicate)
    fn = max(0, total_objectives - tp)
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
    raw_points = sum(s.awarded_points for s in subs)
    return {
        "total_objectives": total_objectives,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "duplicates": duplicates,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "precision_pct": round(precision * 100, 1),
        "recall_pct": round(recall * 100, 1),
        "f1_pct": round(f1 * 100, 1),
        "discovery_points": max(0, raw_points),
        "raw_discovery_points": raw_points,
        "first_blood_count": sum(1 for s in subs if s.is_first_blood),
        "mitre_bonus_count": sum(1 for s in subs if s.mitre_matched),
    }


# ------------------------------------------------------------------ Combined Leaderboard


def leaderboard(case: Case) -> list[dict]:
    """Users ranked by combined (Jeopardy + Discovery) points, solved count, and earliest last solve."""
    total_objectives = CTFObjective.objects.filter(case=case).count()
    stats: dict[int, dict[str, Any]] = {}

    def _entry(uid: int, username: str) -> dict[str, Any]:
        if uid not in stats:
            stats[uid] = {
                "user_id": uid,
                "username": username,
                "question_points": 0,
                "discovery_points_raw": 0,
                "solved_questions": 0,
                "tp_count": 0,
                "fp_count": 0,
                "first_blood_count": 0,
                "mitre_bonus_count": 0,
                "last_solve_at": None,
            }
        return stats[uid]

    # 1. Jeopardy correct submissions
    q_subs = CTFSubmission.objects.filter(question__case=case, is_correct=True).select_related("user")
    for s in q_subs:
        entry = _entry(s.user_id, s.user.username)
        entry["question_points"] += s.awarded_points
        entry["solved_questions"] += 1
        if entry["last_solve_at"] is None or s.submitted_at > entry["last_solve_at"]:
            entry["last_solve_at"] = s.submitted_at

    # 2. Discovery submissions
    d_subs = CTFDiscoverySubmission.objects.filter(case=case).select_related("user")
    for s in d_subs:
        entry = _entry(s.user_id, s.user.username)
        entry["discovery_points_raw"] += s.awarded_points
        if s.is_tp:
            entry["tp_count"] += 1
            if entry["last_solve_at"] is None or s.submitted_at > entry["last_solve_at"]:
                entry["last_solve_at"] = s.submitted_at
        elif s.is_fp:
            entry["fp_count"] += 1
        if s.is_first_blood:
            entry["first_blood_count"] += 1
        if s.mitre_matched:
            entry["mitre_bonus_count"] += 1

    # Fallback timestamp for users who only submitted FPs
    now = timezone.now()
    rows = []
    for entry in stats.values():
        tp = entry["tp_count"]
        fp = entry["fp_count"]
        fn = max(0, total_objectives - tp)
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0
        total_pts = max(0, entry["question_points"] + entry["discovery_points_raw"])
        solved_count = entry["solved_questions"] + tp
        rows.append(
            {
                "user_id": entry["user_id"],
                "username": entry["username"],
                "total_points": total_pts,
                "question_points": entry["question_points"],
                "discovery_points": max(0, entry["discovery_points_raw"]),
                "solved_count": solved_count,
                "tp_count": tp,
                "fp_count": fp,
                "fn_count": fn,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "precision_pct": round(precision * 100, 1),
                "recall_pct": round(recall * 100, 1),
                "f1_pct": round(f1 * 100, 1),
                "first_blood_count": entry["first_blood_count"],
                "mitre_bonus_count": entry["mitre_bonus_count"],
                "last_solve_at": entry["last_solve_at"] or now,
            }
        )

    rows.sort(key=lambda r: (-r["total_points"], -r["solved_count"], r["last_solve_at"]))
    for idx, row in enumerate(rows, start=1):
        row["rank"] = idx
    return rows


# ------------------------------------------------------------------ Settings & YAML/JSON Scenario I/O


def update_settings(
    case: Case,
    *,
    ctf_mode: str | None = None,
    ctf_fp_penalty: int | None = None,
    ctf_first_blood_bonus: int | None = None,
    ctf_dynamic_scoring: bool | None = None,
) -> Case:
    """Update CTF grading settings on a Case."""
    valid_modes = {Case.CTF_MODE_PRACTICE, Case.CTF_MODE_COMPETITION}
    if ctf_mode is not None:
        if ctf_mode not in valid_modes:
            raise ValueError(f"Invalid CTF mode '{ctf_mode}'. Must be one of {sorted(valid_modes)}.")
        case.ctf_mode = ctf_mode
    if ctf_fp_penalty is not None:
        if ctf_fp_penalty < 0:
            raise ValueError("False positive penalty must be >= 0.")
        case.ctf_fp_penalty = int(ctf_fp_penalty)
    if ctf_first_blood_bonus is not None:
        if ctf_first_blood_bonus < 0 or ctf_first_blood_bonus > 200:
            raise ValueError("First blood bonus percentage must be between 0 and 200.")
        case.ctf_first_blood_bonus = int(ctf_first_blood_bonus)
    if ctf_dynamic_scoring is not None:
        case.ctf_dynamic_scoring = bool(ctf_dynamic_scoring)
    if not case.is_ctf:
        case.is_ctf = True
    case.save(
        update_fields=[
            "is_ctf",
            "ctf_mode",
            "ctf_fp_penalty",
            "ctf_first_blood_bonus",
            "ctf_dynamic_scoring",
        ]
    )
    return case


def export_scenario(case: Case, fmt: str = "yaml") -> str:
    """Export a Case's CTF configuration, questions (with hashes), and discovery objectives to YAML or JSON."""
    payload = {
        "schema_version": 1,
        "title": case.name,
        "description": case.description or "",
        "settings": {
            "mode": case.ctf_mode,
            "fp_penalty": case.ctf_fp_penalty,
            "first_blood_bonus": case.ctf_first_blood_bonus,
            "dynamic_scoring": case.ctf_dynamic_scoring,
        },
        "objectives": [
            {
                "order": obj.order,
                "title": obj.title,
                "description": obj.description,
                "entity_type": obj.entity_type,
                "criteria": obj.criteria,
                "points": obj.points,
                "required_mitre": obj.required_mitre,
                "mitre_bonus": obj.mitre_bonus,
            }
            for obj in CTFObjective.objects.filter(case=case)
        ],
        "questions": [
            {
                "order": q.order,
                "question_text": q.question_text,
                "answer_hash": q.answer_hash,
                "points": q.points,
                "hints": [{"hint_text": h.hint_text, "cost": h.cost} for h in q.hints.all()],
            }
            for q in CTFQuestion.objects.filter(case=case).prefetch_related("hints")
        ],
    }
    if fmt.lower() == "json":
        return json.dumps(payload, indent=2)
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def import_scenario(case: Case, raw_content: str, *, replace_existing: bool = False) -> dict[str, int]:
    """Import a YAML or JSON CTF scenario definition into a Case."""
    if not raw_content or not raw_content.strip():
        raise ScenarioImportError("Scenario payload is empty.")
    try:
        data = yaml.safe_load(raw_content)
    except yaml.YAMLError as exc:
        raise ScenarioImportError(f"Invalid YAML/JSON syntax: {exc}") from exc

    if not isinstance(data, dict):
        raise ScenarioImportError("Scenario root must be a YAML/JSON mapping.")

    valid_entity_types = {choice[0] for choice in CTFObjective.ENTITY_TYPE_CHOICES}
    objectives_created = 0
    questions_created = 0

    with transaction.atomic():
        if replace_existing:
            CTFObjective.objects.filter(case=case).delete()
            CTFQuestion.objects.filter(case=case).delete()

        settings_data = data.get("settings") or {}
        if isinstance(settings_data, dict):
            try:
                update_settings(
                    case,
                    ctf_mode=settings_data.get("mode"),
                    ctf_fp_penalty=settings_data.get("fp_penalty"),
                    ctf_first_blood_bonus=settings_data.get("first_blood_bonus"),
                    ctf_dynamic_scoring=settings_data.get("dynamic_scoring"),
                )
            except ValueError as exc:
                raise ScenarioImportError(str(exc)) from exc
        elif not case.is_ctf:
            case.is_ctf = True
            case.save(update_fields=["is_ctf"])

        for idx, item in enumerate(data.get("objectives") or [], start=1):
            if not isinstance(item, dict) or not item.get("title"):
                raise ScenarioImportError(f"Objective #{idx} must be a mapping with a 'title'.")
            entity_type = str(item.get("entity_type") or CTFObjective.ENTITY_GENERIC).lower()
            if entity_type not in valid_entity_types:
                raise ScenarioImportError(f"Objective #{idx} has invalid entity_type '{entity_type}'.")
            criteria = item.get("criteria") or item.get("canonical_match") or {}
            if not isinstance(criteria, dict):
                raise ScenarioImportError(f"Objective #{idx} criteria must be a mapping.")
            create_objective(
                case,
                title=str(item["title"]),
                description=str(item.get("description") or ""),
                entity_type=entity_type,
                criteria=criteria,
                points=int(item.get("points", 100)),
                required_mitre=str(item.get("required_mitre") or ""),
                mitre_bonus=int(item.get("mitre_bonus", 25)),
                order=int(item.get("order", idx)),
            )
            objectives_created += 1

        for idx, item in enumerate(data.get("questions") or [], start=1):
            if not isinstance(item, dict) or not item.get("question_text"):
                raise ScenarioImportError(f"Question #{idx} must be a mapping with 'question_text'.")
            hints_list = []
            for h in item.get("hints") or []:
                if isinstance(h, dict) and h.get("hint_text"):
                    hints_list.append((str(h["hint_text"]), int(h.get("cost", 10))))
            if item.get("answer"):
                create_question(
                    case,
                    question_text=str(item["question_text"]),
                    answer=str(item["answer"]),
                    points=int(item.get("points", 100)),
                    order=int(item.get("order", idx)),
                    hints=hints_list,
                )
                questions_created += 1
            elif item.get("answer_hash"):
                q = CTFQuestion.objects.create(
                    case=case,
                    question_text=str(item["question_text"]),
                    answer_hash=str(item["answer_hash"]).strip().lower(),
                    points=int(item.get("points", 100)),
                    order=int(item.get("order", idx)),
                )
                for hint_text, cost in hints_list:
                    CTFHint.objects.create(question=q, hint_text=hint_text, cost=cost)
                questions_created += 1
            else:
                raise ScenarioImportError(f"Question #{idx} requires either 'answer' or 'answer_hash'.")

    return {"objectives_created": objectives_created, "questions_created": questions_created}


__all__ = [
    "MAX_WRONG_ATTEMPTS_PER_MINUTE",
    "DiscoverySubmissionResult",
    "ScenarioImportError",
    "SubmissionResult",
    "TooManyAttempts",
    "broadcast_ctf_leaderboard",
    "can_manage",
    "compute_effective_points",
    "compute_first_blood_bonus",
    "create_objective",
    "create_question",
    "export_scenario",
    "get_case_for_user",
    "import_scenario",
    "leaderboard",
    "objectives_for_user",
    "promote_evidences_to_objectives",
    "questions_for_user",
    "reset_submissions",
    "submit_answer",
    "submit_discovery",
    "unlock_hint",
    "update_question",
    "update_settings",
    "user_discovery_metrics",
    "get_user_model",
]
