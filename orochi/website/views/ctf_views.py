"""CTF views of a case: questions, hints, discovery objectives, scoring settings, scenarios, scoreboard and
published challenges."""

import json
import logging

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponseBadRequest
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.text import slugify
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user

from orochi.website import ctf
from orochi.website.forms import (
    CTFObjectiveForm,
    CTFQuestionForm,
)
from orochi.website.models import (
    Case,
    CTFHint,
    CTFObjective,
    CTFObjectiveHint,
    CTFQuestion,
    Dump,
    Evidence,
)
from orochi.website.views.cases import _accessible_cases_qs
from orochi.website.views.common import (
    is_not_readonly,
    role_required,
)

logger = logging.getLogger(__name__)


def _ctf_panel(request, case, message=None, level="info", form=None, objective_form=None):
    """Render the CTF panel of a challenge for the requesting user.

    Builds questions, objectives, IR metrics, leaderboard and ATT&CK progress, hiding verdicts in Competition
    mode for non-managers. ``case_evidences`` comes from the user's workspace (their private copy), never from
    the challenge Golden Case. ``message``/``level`` show a feedback banner; ``form``/``objective_form`` keep a
    form with validation errors.
    """
    questions = ctf.questions_for_user(case, request.user)
    objectives = ctf.objectives_for_user(case, request.user)
    can_manage = ctf.can_manage(case, request.user)
    is_blind = case.ctf_mode == Case.CTF_MODE_COMPETITION and not can_manage
    workspace = ctf.workspace_case_for_user(case, request.user)
    metrics = ctf.user_discovery_metrics(case, request.user)
    q_points = sum(q["awarded_points"] or 0 for q in questions)
    my_points = max(0, q_points + metrics["raw_discovery_points"]) if not is_blind else 0
    solved_count = (sum(1 for q in questions if q["solved"]) + metrics["tp"]) if not is_blind else 0
    context = {
        "case": case,
        "questions": questions,
        "objectives": objectives,
        "metrics": metrics,
        "is_blind": is_blind,
        "leaderboard": ctf.leaderboard(case),
        "can_manage": can_manage,
        "total_points": sum(q["points"] for q in questions) + sum(o["points"] for o in objectives),
        "my_points": my_points,
        "solved_count": solved_count,
        "total_items": len(questions) + len(objectives),
        "case_evidences": workspace.evidences.all() if workspace else Evidence.objects.none(),
        "workspace_case": workspace,
        "attack_progress": None if is_blind else ctf.attack_progress(case, request.user),
        "participants_count": case.ctf_participant_cases.count() if can_manage else 0,
        "available_dumps": (
            get_objects_for_user(request.user, "website.can_see", klass=Dump).order_by("name") if can_manage else []
        ),
        "selected_dump_ids": set(case.ctf_dumps.values_list("pk", flat=True)) if can_manage else set(),
        "message": message,
        "message_level": level,
        "form": form or CTFQuestionForm(initial={"order": max((q["order"] for q in questions), default=0) + 1}),
        "objective_form": objective_form
        or CTFObjectiveForm(initial={"order": max((o["order"] for o in objectives), default=0) + 1}),
    }
    return render(request, "website/partial_case_ctf.html", context)


def _get_ctf_case(request, pk):
    """Challenge case for a CTF request (a private copy resolves to its challenge) or 404."""
    case = ctf.get_ctf_case_for_user(pk, request.user)
    if case is None:
        raise Http404("Case not found")
    return case


@login_required
@require_http_methods(["GET"])
def case_ctf(request, pk):
    """CTF panel of a case (loaded by HTMX from the case page)."""
    return _ctf_panel(request, _get_ctf_case(request, pk))


@login_required
@require_http_methods(["POST"])
def case_ctf_submit(request, pk, question_id):
    """Grade a Jeopardy answer and re-render the panel with the verdict (hidden in Competition mode)."""
    case = _get_ctf_case(request, pk)
    question = get_object_or_404(CTFQuestion, case=case, pk=question_id)
    answer = request.POST.get("answer", "").strip()
    if not answer:
        return _ctf_panel(request, case, "Type an answer first.", "warning")
    try:
        result = ctf.submit_answer(question, request.user, answer)
    except ctf.TooManyAttempts as exc:
        return _ctf_panel(request, case, str(exc), "error")
    if case.ctf_mode == Case.CTF_MODE_COMPETITION and not ctf.can_manage(case, request.user):
        return _ctf_panel(
            request, case, f"Answer recorded for Q{question.order} (Competition mode: results hidden).", "info"
        )
    if result.already_solved:
        return _ctf_panel(request, case, f"Q{question.order} was already solved.", "info")
    if result.is_correct:
        fb_tag = " (First Blood!)" if result.is_first_blood else ""
        return _ctf_panel(request, case, f"Correct! +{result.awarded_points} points.{fb_tag}", "success")
    return _ctf_panel(request, case, f"Wrong answer for Q{question.order}.", "error")


@login_required
@require_http_methods(["POST"])
def case_ctf_unlock(request, pk, hint_id):
    """Unlock a question hint for the user; its cost is deducted when the question is solved."""
    case = _get_ctf_case(request, pk)
    hint = get_object_or_404(CTFHint, question__case=case, pk=hint_id)
    ctf.unlock_hint(hint, request.user)
    return _ctf_panel(request, case, f"Hint unlocked: -{hint.cost} points if you solve the question now.", "info")


@login_required
@require_http_methods(["POST"])
def case_ctf_objective_unlock(request, pk, hint_id):
    """Unlock a discovery objective hint; its cost is deducted when the objective is discovered."""
    case = _get_ctf_case(request, pk)
    hint = get_object_or_404(CTFObjectiveHint, objective__case=case, pk=hint_id)
    ctf.unlock_objective_hint(hint, request.user)
    return _ctf_panel(
        request, case, f"Hint unlocked: -{hint.cost} points if you discover '{hint.objective.title}' now.", "info"
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_question_create(request, pk):
    """Instructor only: add a question (answer stored as hash) with optional hints."""
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    form = CTFQuestionForm(request.POST)
    if not form.is_valid():
        return _ctf_panel(request, case, "The question was not saved: check the form.", "error", form=form)
    data = form.cleaned_data
    question = ctf.create_question(
        case,
        question_text=data["question_text"],
        answer=data["answer"],
        points=data["points"],
        order=data["order"],
        hints=data["hints"],
    )
    return _ctf_panel(request, case, f"Question Q{question.order} added.", "success")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_question_delete(request, pk, question_id):
    """Instructor only: delete a question with its hints and submissions."""
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    question = get_object_or_404(CTFQuestion, case=case, pk=question_id)
    question.delete()
    return _ctf_panel(request, case, f"Question Q{question.order} deleted.", "success")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_question_edit(request, pk, question_id):
    """Instructor only: update text, points, order, optional new answer and hints of a question.

    Hints are posted one per line as ``cost | text``; a line without cost uses 10 points.
    """
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    question = get_object_or_404(CTFQuestion, case=case, pk=question_id)
    question_text = (request.POST.get("question_text") or "").strip()
    if not question_text:
        return _ctf_panel(request, case, f"Q{question.order} not updated: question text cannot be empty.", "error")
    try:
        points = int(request.POST.get("points", question.points))
        order = int(request.POST.get("order", question.order))
        if points < 0 or order < 1:
            raise ValueError
    except (TypeError, ValueError):
        return _ctf_panel(request, case, f"Q{question.order} not updated: invalid points or order.", "error")

    raw_answer = (request.POST.get("answer") or "").strip()
    hints_raw = request.POST.get("hints")
    parsed_hints = None
    if hints_raw is not None:
        parsed_hints = []
        for line in hints_raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if "|" in line:
                cost_str, text = line.split("|", 1)
                try:
                    cost = int(cost_str.strip())
                    if cost < 0:
                        raise ValueError
                except ValueError:
                    return _ctf_panel(
                        request,
                        case,
                        f"Q{question.order} not updated: invalid hint cost '{cost_str.strip()}'.",
                        "error",
                    )
                text = text.strip()
            else:
                cost, text = 10, line
            if not text:
                return _ctf_panel(request, case, f"Q{question.order} not updated: hint text cannot be empty.", "error")
            parsed_hints.append((text, cost))

    ctf.update_question(
        question,
        question_text=question_text,
        points=points,
        order=order,
        answer=raw_answer or None,
        hints=parsed_hints,
    )
    return _ctf_panel(request, case, f"Question Q{question.order} updated.", "success")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_reset(request, pk):
    """Instructor only: delete every submission and hint unlock of the challenge."""
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    count = ctf.reset_submissions(case)
    return _ctf_panel(request, case, f"CTF submissions and hint unlocks reset ({count} submissions cleared).", "info")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_settings(request, pk):
    """Instructor only: save mode, FP penalty, First Blood bonus, dynamic scoring, publication and dumps.

    Only dumps the instructor can see are kept in the challenge dump list.
    """
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    ctf_mode = request.POST.get("ctf_mode", case.ctf_mode)
    dynamic = request.POST.get("ctf_dynamic_scoring") in ("on", "true", "1", "yes")
    published = request.POST.get("ctf_published") in ("on", "true", "1", "yes")
    dump_ids = [d for d in request.POST.getlist("ctf_dumps") if str(d).isdigit()]
    dumps = get_objects_for_user(request.user, "website.can_see", klass=Dump).filter(pk__in=dump_ids)
    try:
        fp_penalty = int(request.POST.get("ctf_fp_penalty", case.ctf_fp_penalty))
        fb_bonus = int(request.POST.get("ctf_first_blood_bonus", case.ctf_first_blood_bonus))
        ctf.update_settings(
            case,
            ctf_mode=ctf_mode,
            ctf_fp_penalty=fp_penalty,
            ctf_first_blood_bonus=fb_bonus,
            ctf_dynamic_scoring=dynamic,
            ctf_published=published,
            ctf_dumps=dumps,
        )
    except (TypeError, ValueError) as exc:
        return _ctf_panel(request, case, f"Invalid CTF settings: {exc}", "error")
    return _ctf_panel(request, case, "CTF challenge settings updated.", "success")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_objective_create(request, pk):
    """Instructor only: add a ground-truth discovery objective with optional hints."""
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    obj_form = CTFObjectiveForm(request.POST)
    if not obj_form.is_valid():
        return _ctf_panel(
            request,
            case,
            "The discovery objective was not saved: check the form.",
            "error",
            objective_form=obj_form,
        )
    data = obj_form.cleaned_data
    obj = ctf.create_objective(
        case,
        title=data["title"],
        description=data["description"],
        entity_type=data["entity_type"],
        criteria=data["criteria"],
        points=data["points"],
        required_mitre=data["required_mitre"],
        mitre_bonus=data["mitre_bonus"],
        order=data["order"],
        hints=data["hints"],
    )
    return _ctf_panel(request, case, f"Discovery objective '{obj.title}' added.", "success")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_objective_delete(request, pk, objective_id):
    """Instructor only: delete a discovery objective."""
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    obj = get_object_or_404(CTFObjective, case=case, pk=objective_id)
    title = obj.title
    obj.delete()
    return _ctf_panel(request, case, f"Discovery objective '{title}' deleted.", "success")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_promote_evidences(request, pk):
    """Instructor only: Golden Case, turn the case Evidence (and Finding MITRE IDs) into objectives."""
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    created = ctf.promote_evidences_to_objectives(case)
    if not created:
        return _ctf_panel(
            request,
            case,
            "No new discovery objectives created (add Evidence with plugin rows first, or all evidences are already promoted).",
            "warning",
        )
    return _ctf_panel(
        request,
        case,
        f"Golden Case promoted: {len(created)} discovery objective(s) created from Case Evidence.",
        "success",
    )


def _format_discovery_feedback(res: ctf.DiscoverySubmissionResult) -> tuple[str, str]:
    """Return the ``(message, level)`` banner for a discovery verdict."""
    if res.blind:
        return "Discovery recorded (Competition mode: evaluation hidden until grading).", "info"
    if res.is_tp:
        extras = []
        if res.mitre_matched:
            extras.append("MITRE bonus")
        if res.is_first_blood:
            extras.append("First Blood!")
        extra_str = f" ({', '.join(extras)})" if extras else ""
        return f"Match! Discovered '{res.objective_title}' (+{res.awarded_points} pts){extra_str}.", "success"
    if res.is_duplicate:
        return f"Already discovered '{res.objective_title}' (duplicate: 0 pts, no penalty).", "info"
    penalty_str = f" ({res.awarded_points} pts)" if res.awarded_points < 0 else ""
    return f"False positive: artifact does not match any ground-truth objective{penalty_str}.", "error"


@login_required
@require_http_methods(["POST"])
def case_ctf_discovery_submit(request, pk):
    """Grade a discovery from the panel.

    The artifact is either an Evidence of the user's workspace (``evidence_id``, with the MITRE ID of its first
    Finding as default) or a plugin row posted as JSON or base64 JSON (``result_row``).
    """
    case = _get_ctf_case(request, pk)
    evidence_id = (request.POST.get("evidence_id") or "").strip()
    submitted_mitre = (request.POST.get("submitted_mitre") or "").strip()
    evidence = None
    plugin = (request.POST.get("plugin") or "").strip()
    extracted_file = (request.POST.get("extracted_file") or "").strip()
    result_row = {}

    if evidence_id:
        workspace = ctf.workspace_case_for_user(case, request.user)
        if workspace is None:
            raise Http404("Evidence not found")
        evidence = get_object_or_404(Evidence, case=workspace, pk=evidence_id)
        plugin = evidence.plugin or plugin
        extracted_file = evidence.extracted_file or extracted_file
        if isinstance(evidence.result_row, dict):
            result_row = evidence.result_row
        if not submitted_mitre:
            first_finding = (
                evidence.findings.exclude(mitre_attack_technique__isnull=True)
                .exclude(mitre_attack_technique="")
                .first()
            )
            if first_finding:
                submitted_mitre = first_finding.mitre_attack_technique
    else:
        raw_row = (request.POST.get("result_row") or "").strip()
        if raw_row:
            try:
                parsed = json.loads(raw_row)
                if isinstance(parsed, dict):
                    result_row = parsed
            except json.JSONDecodeError:
                import base64

                try:
                    decoded = base64.b64decode(raw_row).decode("utf-8")
                    parsed = json.loads(decoded)
                    if isinstance(parsed, dict):
                        result_row = parsed
                except Exception:
                    return _ctf_panel(request, case, "Invalid JSON in submitted artifact row.", "error")

    if not result_row and not extracted_file:
        return _ctf_panel(request, case, "Select an Evidence item or provide an artifact JSON row first.", "warning")

    res = ctf.submit_discovery(
        case,
        request.user,
        plugin=plugin,
        result_row=result_row,
        extracted_file=extracted_file,
        submitted_mitre=submitted_mitre,
        evidence=evidence,
    )
    msg, level = _format_discovery_feedback(res)
    return _ctf_panel(request, case, msg, level)


@login_required
@require_http_methods(["GET", "POST"])
def ctf_discovery_modal(request):
    """Modal opened from Volatility plugin row actions to submit a row directly to a CTF Case."""
    ctf_cases = _accessible_cases_qs(request.user).filter(is_ctf=True).order_by("-created_at")

    if request.method == "POST":
        case_id = request.POST.get("case")
        case = ctf.get_ctf_case_for_user(int(case_id), request.user) if case_id and str(case_id).isdigit() else None
        if case is None or not case.is_ctf:
            return render(
                request,
                "website/partial_ctf_discovery_modal.html",
                {
                    "ctf_cases": ctf_cases,
                    "plugin": request.POST.get("plugin", ""),
                    "result_row": request.POST.get("result_row", ""),
                    "extracted_file": request.POST.get("extracted_file", ""),
                    "submitted_mitre": request.POST.get("submitted_mitre", ""),
                    "error": "Please select a valid CTF case.",
                },
            )
        raw_row = (request.POST.get("result_row") or "").strip()
        row_dict = {}
        if raw_row:
            try:
                row_dict = json.loads(raw_row)
            except json.JSONDecodeError:
                import base64

                try:
                    row_dict = json.loads(base64.b64decode(raw_row).decode("utf-8"))
                except Exception:
                    row_dict = {}
        res = ctf.submit_discovery(
            case,
            request.user,
            plugin=(request.POST.get("plugin") or "").strip(),
            result_row=row_dict if isinstance(row_dict, dict) else {},
            extracted_file=(request.POST.get("extracted_file") or "").strip(),
            submitted_mitre=(request.POST.get("submitted_mitre") or "").strip(),
        )
        msg, level = _format_discovery_feedback(res)
        return render(
            request,
            "website/partial_ctf_discovery_modal.html",
            {
                "ctf_cases": ctf_cases,
                "selected_case": case,
                "plugin": request.POST.get("plugin", ""),
                "result_row": raw_row,
                "extracted_file": request.POST.get("extracted_file", ""),
                "submitted_mitre": request.POST.get("submitted_mitre", ""),
                "result": res,
                "feedback_message": msg,
                "feedback_level": level,
            },
        )

    raw_row = request.GET.get("result_row", "")
    decoded_row = raw_row
    if raw_row and not raw_row.strip().startswith("{"):
        import base64

        try:
            decoded_row = base64.b64decode(raw_row).decode("utf-8")
        except Exception:
            decoded_row = raw_row

    return render(
        request,
        "website/partial_ctf_discovery_modal.html",
        {
            "ctf_cases": ctf_cases,
            "selected_case_id": request.GET.get("case", ""),
            "plugin": request.GET.get("plugin", ""),
            "result_row": decoded_row,
            "extracted_file": request.GET.get("extracted_file", ""),
        },
    )


@login_required
@require_http_methods(["GET"])
def case_ctf_scoreboard(request, pk):
    """Full-page scoreboard: standings, solve timeline and per-objective solve counts."""
    case = _get_ctf_case(request, pk)
    can_manage = ctf.can_manage(case, request.user)
    is_blind = case.ctf_mode == Case.CTF_MODE_COMPETITION and not can_manage
    objectives = ctf.objectives_for_user(case, request.user)
    context = {
        "case": case,
        "can_manage": can_manage,
        "is_blind": is_blind,
        "leaderboard": [] if is_blind else ctf.leaderboard(case),
        "timeline": [] if is_blind else ctf.solve_timeline(case),
        "objectives": objectives,
        "questions_count": CTFQuestion.objects.filter(case=case).count(),
        "attack_progress": None if is_blind else ctf.attack_progress(case, request.user),
        "workspace_case": ctf.workspace_case_for_user(case, request.user) or case,
    }
    if getattr(request, "htmx", False) and request.headers.get("HX-Target") == "ctf-scoreboard-body":
        return TemplateResponse(request, "website/partial_ctf_scoreboard.html", context)
    return TemplateResponse(request, "website/ctf_scoreboard.html", context)


@login_required
@require_http_methods(["GET"])
def ctf_challenges(request):
    """Published CTF challenges, the user's own challenges and the private copies they started."""
    started = {
        c.ctf_template_id: c for c in Case.objects.filter(user=request.user, ctf_template__isnull=False).order_by("pk")
    }
    published = list(ctf.published_challenges().order_by("-created_at"))
    owned = list(
        Case.objects.filter(user=request.user, is_ctf=True, ctf_template__isnull=True)
        .exclude(pk__in=[c.pk for c in published])
        .order_by("-created_at")
    )
    rows = []
    for challenge in published + owned:
        rows.append(
            {
                "case": challenge,
                "is_owner": challenge.user_id == request.user.pk,
                "private_case": started.get(challenge.pk),
                "objectives_count": challenge.ctf_objectives.count(),
                "questions_count": challenge.ctf_questions.count(),
                "participants_count": challenge.ctf_participant_cases.count(),
            }
        )
    return TemplateResponse(request, "website/ctf_challenges.html", {"challenges": rows})


@login_required
@require_http_methods(["POST"])
def ctf_challenge_start(request, pk):
    """Start a published challenge: create or reuse the private case and redirect to it.

    HTMX requests get an ``HX-Redirect`` header instead of a 302.
    """
    challenge = ctf.published_challenges().filter(pk=pk).first() or ctf.get_case_for_user(pk, request.user)
    if challenge is None or not challenge.is_ctf or challenge.ctf_template_id:
        raise Http404("Challenge not found")
    try:
        private_case = ctf.start_challenge(challenge, request.user)
    except PermissionError as exc:
        raise PermissionDenied(str(exc)) from exc
    except ValueError as exc:
        return HttpResponseBadRequest(str(exc))
    url = reverse("website:case_detail", args=[private_case.pk])
    if getattr(request, "htmx", False):
        response = HttpResponse(status=204)
        response["HX-Redirect"] = url
        return response
    return redirect(url)


@login_required
@require_http_methods(["GET"])
def case_ctf_scenario_export(request, pk):
    """Instructor only: download the challenge scenario as YAML (default) or JSON (``?format=json``)."""
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    fmt = request.GET.get("format", "yaml").lower()
    if fmt not in ("yaml", "json"):
        fmt = "yaml"
    content = ctf.export_scenario(case, fmt=fmt)
    content_type = "application/json" if fmt == "json" else "application/x-yaml"
    ext = "json" if fmt == "json" else "yaml"
    resp = HttpResponse(content, content_type=content_type)
    resp["Content-Disposition"] = f'attachment; filename="{slugify(case.name) or "ctf"}_scenario.{ext}"'
    return resp


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_scenario_import(request, pk):
    """Instructor only: import a YAML/JSON scenario from the textarea or an uploaded file."""
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    raw = (request.POST.get("scenario_payload") or "").strip()
    if not raw and request.FILES.get("scenario_file"):
        raw = request.FILES["scenario_file"].read().decode("utf-8", errors="replace")
    replace = request.POST.get("replace_existing") in ("on", "true", "1")
    try:
        summary = ctf.import_scenario(case, raw, replace_existing=replace)
    except ctf.ScenarioImportError as exc:
        return _ctf_panel(request, case, f"Scenario import failed: {exc}", "error")
    return _ctf_panel(
        request,
        case,
        f"Scenario imported: {summary['objectives_created']} objective(s), {summary['questions_created']} question(s).",
        "success",
    )
