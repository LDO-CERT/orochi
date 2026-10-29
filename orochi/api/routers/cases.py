from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import HttpResponse
from ninja import Router, Status

from orochi.api.models import (
    CaseFullSchema,
    CaseGraphEdgeOut,
    CaseGraphNodeOut,
    CaseGraphOut,
    CaseNoteIn,
    CaseNoteOut,
    CaseNoteUpdateIn,
    CaseSchema,
    CaseTimelineItemOut,
    CaseUpdateSchema,
    ErrorsOut,
    SuccessResponse,
)
from orochi.api.permissions import ninja_test_required
from orochi.api.security import dual_auth
from orochi.website.case_reporting import (
    export_case_to_html,
    export_case_to_markdown,
    export_case_to_pdf,
    export_case_to_stix,
)
from orochi.website.models import Case, CaseNote, ForensicEdge, ForensicNode, TimelineEvent
from orochi.website.tasks import build_case_forensic_graph

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
        case, created = Case.objects.get_or_create(name=name, user=request.user)
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

    # 1. TimelineEvent records
    for te in TimelineEvent.objects.filter(case=case).select_related("source_evidence", "source_evidence__dump"):
        items.append(
            CaseTimelineItemOut(
                id=te.pk,
                timestamp=te.timestamp,
                event_type=te.event_type,
                description=te.description,
                source_dump=te.source_evidence.dump.name if (te.source_evidence and te.source_evidence.dump) else None,
                source_plugin=te.source_evidence.plugin if te.source_evidence else None,
                source_evidence_id=te.source_evidence.pk if te.source_evidence else None,
                metadata={},
            )
        )

    # 2. Forensic Nodes with first_seen
    for node in ForensicNode.objects.filter(case=case, first_seen__isnull=False).select_related("dump"):
        items.append(
            CaseTimelineItemOut(
                timestamp=node.first_seen,
                event_type=f"Artifact First Seen ({node.node_type})",
                description=f"{node.label} observed in dump {node.dump.name if node.dump else 'unknown'}",
                source_dump=node.dump.name if node.dump else None,
                metadata=node.attributes or {},
            )
        )

    # 3. Forensic Edges with timestamp
    for edge in ForensicEdge.objects.filter(case=case, timestamp__isnull=False).select_related("source", "target"):
        items.append(
            CaseTimelineItemOut(
                timestamp=edge.timestamp,
                event_type=f"Graph Relation ({edge.edge_type})",
                description=f"{edge.source.label} -> {edge.edge_type} -> {edge.target.label}",
                metadata=edge.metadata or {},
            )
        )

    items.sort(key=lambda x: x.timestamp)
    return Status(200, items)


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
        except Exception as excp:
            return HttpResponse(
                f'{{"errors": "PDF compilation failed: {excp}"}}'.encode(), status=400, content_type="application/json"
            )
    elif fmt in ("stix", "stix2"):
        try:
            stix_json = export_case_to_stix(case)
            resp = HttpResponse(stix_json, content_type="application/json; charset=utf-8")
            resp["Content-Disposition"] = f'attachment; filename="case_{case.pk}_stix2.json"'
            return resp
        except Exception as excp:
            return HttpResponse(
                f'{{"errors": "STIX export failed: {excp}"}}'.encode(), status=400, content_type="application/json"
            )
    else:
        return HttpResponse(
            f'{{"errors": "Unsupported export format \'{format}\'. Use markdown, html, pdf, or stix."}}'.encode(),
            status=400,
            content_type="application/json",
        )
