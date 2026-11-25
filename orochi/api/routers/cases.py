import logging

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from ninja import File, Router, Status, UploadedFile

from orochi.api.models import (
    CaseFullSchema,
    CaseGraphEdgeOut,
    CaseGraphNodeOut,
    CaseGraphOut,
    CaseNoteIn,
    CaseNoteOut,
    CaseNoteUpdateIn,
    CaseSchema,
    CaseTimelineEventIn,
    CaseTimelineItemOut,
    CaseUpdateSchema,
    CTFAnswerIn,
    CTFDiscoveryIn,
    CTFObjectiveIn,
    CTFQuestionIn,
    CTFScenarioImportIn,
    CTFSettingsIn,
    ErrorsOut,
    SuccessResponse,
)
from orochi.api.permissions import ninja_test_required
from orochi.api.security import dual_auth
from orochi.website import ctf
from orochi.website.case_reporting import (
    export_case_to_html,
    export_case_to_markdown,
    export_case_to_pdf,
    export_case_to_stix,
)
from orochi.website.models import (
    Case,
    CaseNote,
    CTFHint,
    CTFObjective,
    CTFObjectiveHint,
    CTFQuestion,
    Evidence,
    ForensicEdge,
    ForensicNode,
    TimelineEvent,
)
from orochi.website.tasks import build_case_forensic_graph

logger = logging.getLogger(__name__)
router = Router()


def _get_case_for_user(case_id: int, user):
    """Retrieve case if accessible by the requesting user."""
    if user.is_superuser:
        return Case.objects.filter(pk=case_id).first()
    return Case.objects.filter(Q(user=user) | Q(collaborators=user), pk=case_id).first()


@router.get("/", auth=dual_auth, response=list[CaseFullSchema])
def list_cases(request):
    """
    Summary:
    Retrieve a list of cases accessible to the user.
    """
    if request.user.is_superuser:
        return Case.objects.all().order_by("name")
    return Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct().order_by("name")


@router.post(
    "/",
    response={201: CaseFullSchema, 200: CaseFullSchema, 400: ErrorsOut},
    auth=dual_auth,
    url_name="case_create",
)
@ninja_test_required("is_not_readonly")
def create_case(request, case_in: CaseSchema):
    """
    Summary:
    Create a new case or return existing case with the provided name for current user.
    """
    name = case_in.name.strip() if case_in.name else ""
    if not name:
        return Status(400, {"errors": "Case name cannot be empty"})
    try:
        defaults = {}
        if case_in.description is not None:
            defaults["description"] = case_in.description
        case, created = Case.objects.get_or_create(name=name, user=request.user, defaults=defaults)
        return Status(201 if created else 200, case)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.patch(
    "/{int:case_id}",
    auth=dual_auth,
    response={200: CaseFullSchema, 400: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def update_case(request, case_id: int, case_in: CaseUpdateSchema):
    """
    Summary:
    Update case attributes (status, collaborators, name, description, is_ctf).
    """
    try:
        case = _get_case_for_user(case_id, request.user)
        if not case:
            return Status(404, {"errors": "Case not found"})

        if case_in.name is not None:
            if name := case_in.name.strip():
                case.name = name
            else:
                return Status(400, {"errors": "Case name cannot be empty"})
        if case_in.description is not None:
            case.description = case_in.description
        if case_in.status is not None:
            valid_statuses = [choice[0] for choice in Case.STATUS_CHOICES]
            if case_in.status not in valid_statuses:
                return Status(400, {"errors": f"Invalid status. Must be one of {valid_statuses}"})
            case.status = case_in.status
        if case_in.is_ctf is not None:
            case.is_ctf = case_in.is_ctf

        case.save()

        if case_in.collaborators is not None:
            User = get_user_model()
            users = User.objects.filter(pk__in=case_in.collaborators).exclude(pk=case.user.pk)
            case.collaborators.set(users)

        return Status(200, case)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete(
    "/{int:case_id}",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def delete_case(request, case_id: int):
    """
    Summary:
    Delete a case by ID if authorized.
    """
    try:
        if request.user.is_superuser:
            case = Case.objects.filter(pk=case_id).first()
        else:
            case = Case.objects.filter(pk=case_id, user=request.user).first()
        if not case:
            return Status(404, {"errors": "Case not found"})
        case.delete()
        return Status(200, {"message": "Case deleted successfully"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


###################################################
# Feature 2: Forensic Graph & Timeline
###################################################
@router.get(
    "/{int:case_id}/graph/",
    auth=dual_auth,
    response={200: CaseGraphOut, 404: ErrorsOut},
)
def get_case_graph(
    request,
    case_id: int,
    min_score: int = 0,
    include_benign: bool = True,
):
    """
    Summary:
    Retrieve the multi-host forensic entity graph (processes, network connections, memory injections).
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    nodes = ForensicNode.objects.filter(case=case)
    if not include_benign:
        nodes = nodes.filter(is_malicious=True)

    edges = ForensicEdge.objects.filter(case=case, source__in=nodes, target__in=nodes)

    return Status(
        200,
        {
            "nodes": [
                CaseGraphNodeOut(
                    id=n.canonical_id,
                    label=n.label,
                    type=n.node_type,
                    attributes=n.attributes or {},
                    first_seen=n.first_seen,
                    is_malicious=n.is_malicious,
                )
                for n in nodes
            ],
            "edges": [
                CaseGraphEdgeOut(
                    source=e.source.canonical_id,
                    target=e.target.canonical_id,
                    type=e.edge_type,
                    timestamp=e.timestamp,
                    metadata=e.metadata or {},
                )
                for e in edges
            ],
        },
    )


@router.post(
    "/{int:case_id}/graph/build",
    auth=dual_auth,
    response={200: CaseGraphOut, 404: ErrorsOut, 400: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def build_case_graph(request, case_id: int):
    """
    Summary:
    Extract and build multi-host forensic graph nodes and edges from all dumps in this case.
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    try:
        if hasattr(build_case_forensic_graph, "call"):
            build_case_forensic_graph.call(case_pk=case.pk)
        elif hasattr(build_case_forensic_graph, "func"):
            build_case_forensic_graph.func(case_pk=case.pk)
        else:
            build_case_forensic_graph(case_pk=case.pk)
        return get_case_graph(request, case_id=case.pk, include_benign=True)
    except Exception as excp:
        return Status(400, {"errors": f"Failed to build forensic graph: {excp}"})


@router.get(
    "/{int:case_id}/timeline/",
    auth=dual_auth,
    response={200: list[CaseTimelineItemOut], 404: ErrorsOut},
)
def get_case_timeline(request, case_id: int):
    """
    Summary:
    Retrieve unified temporal forensic timeline across all dumps, evidence, findings, and graph events.
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    items = []

    # 1. TimelineEvent records (distinguish analyst activity vs manual forensic entries)
    from orochi.website.defaults import ACTIVITY_EVENT_TYPES as activity_types

    for te in TimelineEvent.objects.filter(case=case).select_related("source_evidence", "source_evidence__dump"):
        kind = "activity" if te.event_type in activity_types else "manual"
        items.append(
            CaseTimelineItemOut(
                id=te.pk,
                timestamp=te.timestamp,
                event_type=te.event_type,
                description=te.description,
                source_dump=te.source_evidence.dump.name if (te.source_evidence and te.source_evidence.dump) else None,
                source_plugin=te.source_evidence.plugin if te.source_evidence else None,
                source_evidence_id=te.source_evidence.pk if te.source_evidence else None,
                metadata={"timeline_kind": kind},
            )
        )

    # 2. Forensic Nodes with first_seen
    for node in ForensicNode.objects.filter(case=case, first_seen__isnull=False).select_related("dump"):
        attrs = dict(node.attributes or {})
        attrs["timeline_kind"] = "artefact"
        items.append(
            CaseTimelineItemOut(
                timestamp=node.first_seen,
                event_type=f"Artifact First Seen ({node.node_type})",
                description=f"{node.label} observed in dump {node.dump.name if node.dump else 'unknown'}",
                source_dump=node.dump.name if node.dump else None,
                metadata=attrs,
            )
        )

    # 3. Forensic Edges with timestamp
    for edge in ForensicEdge.objects.filter(case=case, timestamp__isnull=False).select_related("source", "target"):
        meta = dict(edge.metadata or {})
        meta["timeline_kind"] = "artefact"
        items.append(
            CaseTimelineItemOut(
                timestamp=edge.timestamp,
                event_type=f"Graph Relation ({edge.edge_type})",
                description=f"{edge.source.label} -> {edge.edge_type} -> {edge.target.label}",
                metadata=meta,
            )
        )

    items.sort(key=lambda x: x.timestamp)
    return Status(200, items)


@router.post(
    "/{int:case_id}/timeline/",
    auth=dual_auth,
    response={201: CaseTimelineItemOut, 400: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def create_case_timeline_event(request, case_id: int, payload: CaseTimelineEventIn):
    """Create a manual forensic timeline event on a case (Issue #1538)."""
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not (payload.description or "").strip():
        return Status(400, {"errors": "Description is required"})

    te = TimelineEvent.objects.create(
        case=case,
        timestamp=payload.timestamp,
        event_type=(payload.event_type or "Manual Entry").strip(),
        description=payload.description.strip(),
    )
    return Status(
        201,
        CaseTimelineItemOut(
            id=te.pk,
            timestamp=te.timestamp,
            event_type=te.event_type,
            description=te.description,
            metadata={"timeline_kind": "manual"},
        ),
    )


@router.delete(
    "/{int:case_id}/timeline/{int:event_id}/",
    auth=dual_auth,
    response={200: SuccessResponse, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def delete_case_timeline_event(request, case_id: int, event_id: int):
    """Delete a manual timeline event from a case (Issue #1538); activity events are custody records and stay."""
    from orochi.website.defaults import ACTIVITY_EVENT_TYPES

    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    deleted, _ = (
        TimelineEvent.objects.filter(case=case, pk=event_id).exclude(event_type__in=ACTIVITY_EVENT_TYPES).delete()
    )
    if not deleted:
        return Status(404, {"errors": "Timeline event not found"})
    return Status(200, {"message": "Timeline event deleted"})


###################################################
# Feature 4: Collaborative Case Notes & Reporting
###################################################
@router.get(
    "/{int:case_id}/notes/",
    auth=dual_auth,
    response={200: list[CaseNoteOut], 404: ErrorsOut},
)
def list_case_notes(request, case_id: int):
    """
    Summary:
    Retrieve all collaborative notes for a specific case.
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    notes = CaseNote.objects.filter(case=case).select_related("author", "case").order_by("-created_at")
    return Status(200, list(notes))


@router.post(
    "/{int:case_id}/notes/",
    auth=dual_auth,
    response={201: CaseNoteOut, 400: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def create_case_note(request, case_id: int, payload: CaseNoteIn):
    """
    Summary:
    Create a new collaborative note under the case.
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    title = payload.title.strip() if payload.title else ""
    if not title:
        return Status(400, {"errors": "Note title cannot be empty"})

    note = CaseNote.objects.create(
        case=case,
        author=request.user,
        title=title,
        content=payload.content or "",
    )
    return Status(201, note)


@router.patch(
    "/{int:case_id}/notes/{int:note_id}",
    auth=dual_auth,
    response={200: CaseNoteOut, 400: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def update_case_note(request, case_id: int, note_id: int, payload: CaseNoteUpdateIn):
    """
    Summary:
    Update an existing collaborative note.
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    note = CaseNote.objects.filter(case=case, pk=note_id).first()
    if not note:
        return Status(404, {"errors": "Note not found"})

    # Only author, case owner or superuser can edit
    if not (request.user.is_superuser or note.author == request.user or case.user == request.user):
        return Status(400, {"errors": "Not authorized to edit this note"})

    if payload.title is not None:
        title = payload.title.strip()
        if not title:
            return Status(400, {"errors": "Note title cannot be empty"})
        note.title = title

    if payload.content is not None:
        note.content = payload.content

    note.save()
    return Status(200, note)


@router.delete(
    "/{int:case_id}/notes/{int:note_id}",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def delete_case_note(request, case_id: int, note_id: int):
    """
    Summary:
    Delete a collaborative case note.
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    note = CaseNote.objects.filter(case=case, pk=note_id).first()
    if not note:
        return Status(404, {"errors": "Note not found"})

    if not (request.user.is_superuser or note.author == request.user or case.user == request.user):
        return Status(400, {"errors": "Not authorized to delete this note"})

    note.delete()
    return Status(200, {"message": "Case note deleted successfully"})


@router.get(
    "/{int:case_id}/bundle",
    auth=dual_auth,
    url_name="case_export_bundle",
    response={200: None, 404: ErrorsOut},
)
def export_case_bundle_api(request, case_id: int):
    """Export a portable, SHA-256-verified .orochi.zip Case Bundle (Issue #1539)."""
    from orochi.website.case_bundle import export_case_bundle

    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    bundle_bytes = export_case_bundle(case)
    resp = HttpResponse(bundle_bytes, content_type="application/zip")
    resp["Content-Disposition"] = f'attachment; filename="case_{case.pk}.orochi.zip"'
    return resp


@router.post(
    "/import-bundle",
    auth=dual_auth,
    url_name="case_import_bundle",
    response={201: CaseFullSchema, 400: ErrorsOut, 403: ErrorsOut},
)
def import_case_bundle_api(request, bundle: UploadedFile = File(...), name: str | None = None):
    """Verify SHA-256 manifest and import a .orochi.zip Case Bundle (Issue #1539)."""
    from orochi.website.case_bundle import BundleIntegrityError, import_case_bundle
    from orochi.website.views.common import is_not_readonly

    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot import case bundles."})
    try:
        new_case = import_case_bundle(bundle.read(), request.user, name_override=name)
        return Status(201, new_case)
    except BundleIntegrityError as excp:
        return Status(400, {"errors": str(excp)})
    except Exception as excp:
        return Status(400, {"errors": f"Failed to import case bundle: {excp}"})


@router.get(
    "/{int:case_id}/export",
    auth=dual_auth,
)
def export_case_report(request, case_id: int, format: str = "markdown"):
    """
    Summary:
    Export comprehensive Case incident report in Markdown, HTML, PDF (WeasyPrint), or STIX 2.1 JSON.
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return HttpResponse(b'{"errors": "Case not found"}', status=404, content_type="application/json")

    fmt = format.lower().strip()
    if fmt in ("md", "markdown"):
        content = export_case_to_markdown(case)
        resp = HttpResponse(content, content_type="text/markdown; charset=utf-8")
        resp["Content-Disposition"] = f'attachment; filename="case_{case.pk}_report.md"'
        return resp
    elif fmt == "html":
        content = export_case_to_html(case)
        resp = HttpResponse(content, content_type="text/html; charset=utf-8")
        resp["Content-Disposition"] = f'attachment; filename="case_{case.pk}_report.html"'
        return resp
    elif fmt == "pdf":
        try:
            pdf_bytes = export_case_to_pdf(case)
            resp = HttpResponse(pdf_bytes, content_type="application/pdf")
            resp["Content-Disposition"] = f'attachment; filename="case_{case.pk}_report.pdf"'
            return resp
        except Exception:
            logger.exception("PDF export failed for case %s", case.pk)
            return JsonResponse({"errors": "PDF compilation failed, check the server logs for details."}, status=400)
    elif fmt in ("stix", "stix2"):
        try:
            stix_json = export_case_to_stix(case)
            resp = HttpResponse(stix_json, content_type="application/json; charset=utf-8")
            resp["Content-Disposition"] = f'attachment; filename="case_{case.pk}_stix2.json"'
            return resp
        except Exception:
            logger.exception("STIX export failed for case %s", case.pk)
            return JsonResponse({"errors": "STIX export failed, check the server logs for details."}, status=400)
    else:
        return HttpResponse(
            f'{{"errors": "Unsupported export format \'{format}\'. Use markdown, html, pdf, or stix."}}'.encode(),
            status=400,
            content_type="application/json",
        )


###################################################
# Feature 5: External Integrations (SIEM & TheHive)
###################################################
@router.post(
    "/{int:case_id}/siem/forward",
    auth=dual_auth,
    response={200: dict, 400: ErrorsOut, 404: ErrorsOut, 502: ErrorsOut},
    url_name="case_siem_forward",
)
@ninja_test_required("is_not_readonly")
def case_siem_forward(request, case_id: int, provider: str | None = None):
    """
    Summary:
    Forward Case findings, timeline summary, and extracted IOCs to SIEM (Splunk HEC / Elastic / Sentinel) (#1568).
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    from orochi.website.integrations import forward_case_to_siem

    try:
        res = forward_case_to_siem(case, provider=provider)
    except Exception as exc:
        return Status(400, {"errors": str(exc)})
    if not res["success"]:
        return Status(502, {"errors": f"SIEM returned HTTP {res['status_code']}"})
    return Status(200, res)


@router.post(
    "/{int:case_id}/export/thehive",
    auth=dual_auth,
    response={200: dict, 400: ErrorsOut, 404: ErrorsOut},
    url_name="case_export_thehive",
)
@ninja_test_required("is_not_readonly")
def case_export_thehive(request, case_id: int, push: bool = True):
    """
    Summary:
    Export Case, Findings (as Tasks), and IOCs (as Observables) to TheHive v4/v5 (#1550).
    """
    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    from orochi.website.integrations import export_case_to_thehive

    try:
        res = export_case_to_thehive(case, push=push)
        return Status(200, res)
    except Exception as exc:
        return Status(400, {"errors": str(exc)})


@router.post(
    "/{int:case_id}/cortex/analyze",
    auth=dual_auth,
    url_name="case_cortex_analyze",
    response={200: dict, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def case_cortex_analyze(
    request,
    case_id: int,
    evidence_id: int,
    analyzer_id: str,
):
    """Run a Cortex analyzer on an extracted file attached to a Case Evidence (Issue #1550).

    The Cortex URL and API key come only from the administrator's Cortex service: a caller-supplied URL would
    receive the stored key.
    """
    from orochi.website.integrations import run_cortex_analyzer

    case = _get_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    ev = Evidence.objects.filter(case=case, pk=evidence_id).select_related("dump").first()
    if not ev or not ev.dump:
        return Status(404, {"errors": "Evidence with linked dump not found in this case."})

    filepath = ev.extracted_file or (ev.result_row.get("down_path") if isinstance(ev.result_row, dict) else None)
    if not filepath:
        return Status(400, {"errors": "Selected evidence does not reference an extracted file."})

    try:
        res = run_cortex_analyzer(ev.dump, filepath, analyzer_id)
        return Status(200, res)
    except Exception as exc:
        return Status(400, {"errors": f"Cortex analysis failed: {exc}"})


###################################################
# Feature 6: Graded Exercise / CTF Mode (#1542)
###################################################
@router.get(
    "/{int:case_id}/ctf/questions",
    auth=dual_auth,
    response={200: list[dict], 404: ErrorsOut},
    url_name="ctf_list_questions",
)
def ctf_list_questions(request, case_id: int):
    """List CTF challenge questions, hints (with unlock status), and user solve state for a Case (#1542)."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    return Status(
        200,
        [{k: v for k, v in q.items() if k != "awarded_points"} for q in ctf.questions_for_user(case, request.user)],
    )


@router.post(
    "/{int:case_id}/ctf/questions",
    auth=dual_auth,
    response={201: dict, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_create_question",
)
@ninja_test_required("is_not_readonly")
def ctf_create_question(request, case_id: int, payload: CTFQuestionIn):
    """Create a CTF challenge question (with optional hints) for a Case (#1542).

    Only the SHA-256 of the normalized answer is stored.
    """
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not ctf.can_manage(case, request.user):
        return Status(403, {"errors": "Only the case owner or superuser can create CTF questions"})

    question = ctf.create_question(
        case,
        question_text=payload.question_text,
        answer=payload.answer,
        points=payload.points,
        order=payload.order,
        hints=[(h.hint_text, h.cost) for h in payload.hints],
    )
    return Status(
        201,
        {
            "id": question.pk,
            "order": question.order,
            "question_text": question.question_text,
            "points": question.points,
            "hints": [{"id": h.pk, "cost": h.cost, "hint_text": h.hint_text} for h in question.hints.all()],
        },
    )


@router.delete(
    "/{int:case_id}/ctf/questions/{int:question_id}",
    auth=dual_auth,
    response={200: SuccessResponse, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_delete_question",
)
@ninja_test_required("is_not_readonly")
def ctf_delete_question(request, case_id: int, question_id: int):
    """Delete a CTF question with its hints and submissions (#1542)."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not ctf.can_manage(case, request.user):
        return Status(403, {"errors": "Only the case owner or superuser can delete CTF questions"})
    deleted, _ = CTFQuestion.objects.filter(case=case, pk=question_id).delete()
    if not deleted:
        return Status(404, {"errors": "CTF question not found"})
    return Status(200, {"message": "CTF question deleted"})


@router.post(
    "/{int:case_id}/ctf/questions/{int:question_id}/submit",
    auth=dual_auth,
    response={200: dict, 404: ErrorsOut, 429: ErrorsOut},
    url_name="ctf_submit_answer",
)
def ctf_submit_answer(request, case_id: int, question_id: int, payload: CTFAnswerIn):
    """Submit an answer to a CTF question and compute score net of unlocked hint costs (#1542)."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    question = CTFQuestion.objects.filter(case=case, pk=question_id).first()
    if not question:
        return Status(404, {"errors": "CTF question not found"})

    try:
        result = ctf.submit_answer(question, request.user, payload.answer)
    except ctf.TooManyAttempts as exc:
        return Status(429, {"errors": str(exc)})

    body = {
        "is_correct": result.is_correct,
        "already_solved": result.already_solved,
        "awarded_points": result.awarded_points,
    }
    if result.submission_id is not None:
        body["submission_id"] = result.submission_id
    return Status(200, body)


@router.post(
    "/{int:case_id}/ctf/hints/{int:hint_id}/unlock",
    auth=dual_auth,
    response={200: dict, 404: ErrorsOut},
    url_name="ctf_unlock_hint",
)
def ctf_unlock_hint(request, case_id: int, hint_id: int):
    """Unlock a CTF hint for the requesting user (#1542).

    The hint cost is subtracted from the points awarded when the question is solved afterwards.
    """
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    hint = CTFHint.objects.filter(question__case=case, pk=hint_id).first()
    if not hint:
        return Status(404, {"errors": "Hint not found"})
    ctf.unlock_hint(hint, request.user)
    return Status(200, {"id": hint.pk, "cost": hint.cost, "hint_text": hint.hint_text, "unlocked": True})


@router.post(
    "/{int:case_id}/ctf/objective-hints/{int:hint_id}/unlock",
    auth=dual_auth,
    response={200: dict, 404: ErrorsOut},
    url_name="ctf_unlock_objective_hint",
)
def ctf_unlock_objective_hint(request, case_id: int, hint_id: int):
    """Unlock a discovery objective hint; its cost is subtracted when the objective is discovered afterwards."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    hint = CTFObjectiveHint.objects.filter(objective__case=case, pk=hint_id).first()
    if not hint:
        return Status(404, {"errors": "Hint not found"})
    ctf.unlock_objective_hint(hint, request.user)
    return Status(200, {"id": hint.pk, "cost": hint.cost, "hint_text": hint.hint_text, "unlocked": True})


@router.get(
    "/{int:case_id}/ctf/attack-progress",
    auth=dual_auth,
    response={200: dict, 404: ErrorsOut},
    url_name="ctf_attack_progress",
)
def ctf_attack_progress(request, case_id: int):
    """ATT&CK coverage of the challenge objectives (participants only see the techniques they attributed)."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if case.ctf_mode == Case.CTF_MODE_COMPETITION and not ctf.can_manage(case, request.user):
        return Status(200, {"blind": True})
    return Status(200, ctf.attack_progress(case, request.user))


@router.get(
    "/ctf/challenges",
    auth=dual_auth,
    response={200: list[dict]},
    url_name="ctf_list_challenges",
)
def ctf_list_challenges(request):
    """Published CTF challenges, with the requesting user's private case id when already started."""
    started = dict(
        Case.objects.filter(user=request.user, ctf_template__isnull=False).values_list("ctf_template_id", "pk")
    )
    return Status(
        200,
        [
            {
                "id": c.pk,
                "name": c.name,
                "description": c.description or "",
                "owner": c.user.username,
                "mode": c.ctf_mode,
                "private_case_id": started.get(c.pk),
            }
            for c in ctf.published_challenges().order_by("-created_at")
        ],
    )


@router.post(
    "/ctf/challenges/{int:case_id}/start",
    auth=dual_auth,
    response={201: dict, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_start_challenge",
)
def ctf_start_challenge(request, case_id: int):
    """Start a published challenge: create (or return) the user's private CTF case and grant dump access."""
    challenge = ctf.published_challenges().filter(pk=case_id).first() or _get_case_for_user(case_id, request.user)
    if challenge is None or not challenge.is_ctf or challenge.ctf_template_id:
        return Status(404, {"errors": "Challenge not found"})
    try:
        private_case = ctf.start_challenge(challenge, request.user)
    except PermissionError as exc:
        return Status(403, {"errors": str(exc)})
    return Status(201, {"case_id": private_case.pk, "name": private_case.name, "challenge_id": challenge.pk})


@router.get(
    "/{int:case_id}/ctf/leaderboard",
    auth=dual_auth,
    response={200: list[dict], 404: ErrorsOut},
    url_name="ctf_leaderboard",
)
def ctf_leaderboard(request, case_id: int):
    """Compute CTF leaderboard for a Case ordered by total score descending and earliest solve time (#1542)."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if case.ctf_mode == Case.CTF_MODE_COMPETITION and not ctf.can_manage(case, request.user):
        return Status(200, [])
    return Status(200, [{**row, "last_solve_at": row["last_solve_at"].isoformat()} for row in ctf.leaderboard(case)])


@router.get(
    "/{int:case_id}/ctf/objectives",
    auth=dual_auth,
    response={200: list[dict], 404: ErrorsOut},
    url_name="ctf_list_objectives",
)
def ctf_list_objectives(request, case_id: int):
    """List forensic discovery ground-truth objectives for a Case (criteria hidden from non-managers)."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    return Status(200, ctf.objectives_for_user(case, request.user))


@router.post(
    "/{int:case_id}/ctf/objectives",
    auth=dual_auth,
    response={201: dict, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_create_objective",
)
@ninja_test_required("is_not_readonly")
def ctf_create_objective(request, case_id: int, payload: CTFObjectiveIn):
    """Create a ground-truth forensic discovery objective for a Case."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not ctf.can_manage(case, request.user):
        return Status(403, {"errors": "Only the case owner or superuser can create CTF objectives"})
    valid_types = {c[0] for c in CTFObjective.ENTITY_TYPE_CHOICES}
    if payload.entity_type not in valid_types:
        return Status(400, {"errors": f"Invalid entity_type '{payload.entity_type}'"})
    obj = ctf.create_objective(
        case,
        title=payload.title,
        description=payload.description,
        entity_type=payload.entity_type,
        criteria=payload.criteria,
        points=payload.points,
        required_mitre=payload.required_mitre,
        mitre_bonus=payload.mitre_bonus,
        order=payload.order,
        hints=[(h.hint_text, h.cost) for h in payload.hints],
    )
    return Status(
        201,
        {
            "hints": [{"id": h.pk, "cost": h.cost, "hint_text": h.hint_text} for h in obj.hints.all()],
            "id": obj.pk,
            "order": obj.order,
            "title": obj.title,
            "entity_type": obj.entity_type,
            "criteria": obj.criteria,
            "points": obj.points,
            "required_mitre": obj.required_mitre,
            "mitre_bonus": obj.mitre_bonus,
        },
    )


@router.delete(
    "/{int:case_id}/ctf/objectives/{int:objective_id}",
    auth=dual_auth,
    response={200: SuccessResponse, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_delete_objective",
)
@ninja_test_required("is_not_readonly")
def ctf_delete_objective(request, case_id: int, objective_id: int):
    """Delete a CTF discovery objective."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not ctf.can_manage(case, request.user):
        return Status(403, {"errors": "Only the case owner or superuser can delete CTF objectives"})
    deleted, _ = CTFObjective.objects.filter(case=case, pk=objective_id).delete()
    if not deleted:
        return Status(404, {"errors": "CTF objective not found"})
    return Status(200, {"message": "CTF objective deleted"})


@router.post(
    "/{int:case_id}/ctf/objectives/from-evidences",
    auth=dual_auth,
    response={201: dict, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_promote_evidences",
)
@ninja_test_required("is_not_readonly")
def ctf_promote_evidences(request, case_id: int):
    """Golden Case authoring: auto-generate ground-truth CTF objectives from Case Evidences."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not ctf.can_manage(case, request.user):
        return Status(403, {"errors": "Only the case owner or superuser can promote Golden Case evidences"})
    created = ctf.promote_evidences_to_objectives(case)
    return Status(
        201,
        {
            "created_count": len(created),
            "objectives": [
                {
                    "id": o.pk,
                    "title": o.title,
                    "entity_type": o.entity_type,
                    "criteria": o.criteria,
                    "required_mitre": o.required_mitre,
                }
                for o in created
            ],
        },
    )


@router.post(
    "/{int:case_id}/ctf/discoveries/submit",
    auth=dual_auth,
    response={200: dict, 400: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_submit_discovery",
)
def ctf_submit_discovery(request, case_id: int, payload: CTFDiscoveryIn):
    """Submit a Volatility plugin row or Case Evidence for canonical ground-truth evaluation."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})

    evidence = None
    plugin = payload.plugin
    result_row = payload.result_row
    extracted_file = payload.extracted_file
    submitted_mitre = payload.submitted_mitre

    if payload.evidence_id is not None:
        workspace = ctf.workspace_case_for_user(case, request.user)
        evidence = Evidence.objects.filter(case=workspace, pk=payload.evidence_id).first() if workspace else None
        if not evidence:
            return Status(404, {"errors": "Evidence not found in this case"})
        plugin = evidence.plugin or plugin
        extracted_file = evidence.extracted_file or extracted_file
        if isinstance(evidence.result_row, dict):
            result_row = evidence.result_row

    if not result_row and not extracted_file:
        return Status(400, {"errors": "Either result_row, extracted_file, or a valid evidence_id is required"})

    res = ctf.submit_discovery(
        case,
        request.user,
        plugin=plugin,
        result_row=result_row,
        extracted_file=extracted_file,
        submitted_mitre=submitted_mitre,
        evidence=evidence,
    )
    if res.blind:
        return Status(200, {"recorded": True, "blind": True, "submission_id": res.submission_id})
    return Status(
        200,
        {
            "is_tp": res.is_tp,
            "is_fp": res.is_fp,
            "is_duplicate": res.is_duplicate,
            "is_first_blood": res.is_first_blood,
            "mitre_matched": res.mitre_matched,
            "awarded_points": res.awarded_points,
            "objective_id": res.objective_id,
            "objective_title": res.objective_title,
            "submission_id": res.submission_id,
        },
    )


@router.get(
    "/{int:case_id}/ctf/metrics",
    auth=dual_auth,
    response={200: dict, 404: ErrorsOut},
    url_name="ctf_metrics",
)
def ctf_metrics(request, case_id: int):
    """Return IR quality metrics (TP, FP, FN, Precision, Recall, F1) for the requesting user."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if case.ctf_mode == Case.CTF_MODE_COMPETITION and not ctf.can_manage(case, request.user):
        return Status(200, {"blind": True})
    return Status(200, ctf.user_discovery_metrics(case, request.user))


@router.patch(
    "/{int:case_id}/ctf/settings",
    auth=dual_auth,
    response={200: dict, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_update_settings",
)
@ninja_test_required("is_not_readonly")
def ctf_update_settings(request, case_id: int, payload: CTFSettingsIn):
    """Update CTF grading settings (mode, FP penalty, First Blood bonus %, dynamic scoring)."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not ctf.can_manage(case, request.user):
        return Status(403, {"errors": "Only the case owner or superuser can update CTF settings"})
    try:
        ctf.update_settings(
            case,
            ctf_mode=payload.ctf_mode,
            ctf_fp_penalty=payload.ctf_fp_penalty,
            ctf_first_blood_bonus=payload.ctf_first_blood_bonus,
            ctf_dynamic_scoring=payload.ctf_dynamic_scoring,
            ctf_published=payload.ctf_published,
        )
    except ValueError as exc:
        return Status(400, {"errors": str(exc)})
    return Status(
        200,
        {
            "ctf_mode": case.ctf_mode,
            "ctf_fp_penalty": case.ctf_fp_penalty,
            "ctf_first_blood_bonus": case.ctf_first_blood_bonus,
            "ctf_dynamic_scoring": case.ctf_dynamic_scoring,
            "ctf_published": case.ctf_published,
        },
    )


@router.get(
    "/{int:case_id}/ctf/scenario/export",
    auth=dual_auth,
    response={200: dict, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_export_scenario",
)
def ctf_export_scenario(request, case_id: int, format: str = "yaml"):
    """Export CTF scenario (settings, objectives, questions) as YAML or JSON."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not ctf.can_manage(case, request.user):
        return Status(403, {"errors": "Only the case owner or superuser can export CTF scenarios"})
    fmt = format.lower() if format.lower() in ("yaml", "json") else "yaml"
    return Status(200, {"format": fmt, "content": ctf.export_scenario(case, fmt=fmt)})


@router.post(
    "/{int:case_id}/ctf/scenario/import",
    auth=dual_auth,
    response={201: dict, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="ctf_import_scenario",
)
@ninja_test_required("is_not_readonly")
def ctf_import_scenario(request, case_id: int, payload: CTFScenarioImportIn):
    """Import a YAML or JSON CTF scenario into a Case."""
    case = ctf.get_ctf_case_for_user(case_id, request.user)
    if not case:
        return Status(404, {"errors": "Case not found"})
    if not ctf.can_manage(case, request.user):
        return Status(403, {"errors": "Only the case owner or superuser can import CTF scenarios"})
    try:
        summary = ctf.import_scenario(case, payload.payload, replace_existing=payload.replace_existing)
    except ctf.ScenarioImportError as exc:
        return Status(400, {"errors": str(exc)})
    return Status(201, summary)
