"""Dump analysis endpoints of the ``/api/dumps/`` router: temporal diff, row annotations, secrets, triage,
AI narrative, timeline, process tree, network, IOCs, MISP export and sandbox submission."""

import logging
from pathlib import Path

from django.conf import settings
from django.db.models import Q
from django.shortcuts import get_object_or_404
from guardian.shortcuts import get_objects_for_user
from ninja import Query, Status

from orochi.api.models import (
    DumpIOCOut,
    DumpIOCReportOut,
    DumpNarrativeOut,
    DumpSecretOut,
    ErrorsOut,
    ExportMISPIn,
    ExportMISPOut,
    NetworkReportOut,
    SuccessResponse,
    TimelineReportOut,
    TriageReportOut,
    ValueAnnotationIn,
    ValueAnnotationOut,
)
from orochi.api.permissions import ninja_test_required
from orochi.api.routers.dumps import router
from orochi.api.security import dual_auth
from orochi.utils.timeliner import build_timeline_feed, extract_timeline_entries
from orochi.website.ai_narrative import generate_dump_narrative
from orochi.website.defaults import (
    RESULT_STATUS_SUCCESS,
)
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.models import (
    Dump,
    DumpIOC,
    Result,
    Value,
    ValueAnnotation,
)
from orochi.website.roles import (
    ROLE_READONLY,
    get_user_role,
)
from orochi.website.secrets_scanner import scan_dump_for_secrets
from orochi.website.views import is_not_readonly

logger = logging.getLogger(__name__)


@router.get(
    "/temporal_diff/{index_a}/{index_b}",
    url_name="dump_temporal_diff",
    auth=dual_auth,
    response={200: dict, 403: dict, 404: dict},
)
def dump_temporal_diff(request, index_a: str, index_b: str, reverse: bool = False):
    """
    Summary:
    Compute temporal delta (processes, injected regions, connections, common plugins)
    between two memory dumps (same host T1 vs T2).
    """
    dump_a = Dump.objects.filter(index=index_a).first()
    dump_b = Dump.objects.filter(index=index_b).first()
    if not dump_a or not dump_b:
        return Status(404, {"message": "Dump not found"})

    user_dumps = get_objects_for_user(request.user, "website.can_see")
    if dump_a not in user_dumps or dump_b not in user_dumps:
        return Status(403, {"message": "Unauthorized"})

    from orochi.website.temporal import compute_temporal_diff

    diff_data = compute_temporal_diff(dump_a, dump_b, reverse=reverse)

    t1 = diff_data["t1"]
    t2 = diff_data["t2"]
    meta = diff_data["meta"]

    response_data = {
        "meta": {
            "is_same_host": meta["is_same_host"],
            "host_name": meta["host_name"],
            "time_delta_display": meta["time_delta_display"],
            "delta_seconds": meta["delta_seconds"],
            "is_reversed": meta["is_reversed"],
        },
        "t1": {
            "name": t1.name,
            "index": t1.index,
            "created_at": t1.created_at.isoformat() if t1.created_at else None,
            "operating_system": t1.operating_system,
            "color": t1.color,
            "host": t1.host.name if t1.host else None,
        },
        "t2": {
            "name": t2.name,
            "index": t2.index,
            "created_at": t2.created_at.isoformat() if t2.created_at else None,
            "operating_system": t2.operating_system,
            "color": t2.color,
            "host": t2.host.name if t2.host else None,
        },
        "summary": diff_data["summary"],
        "processes": {
            "available": diff_data["processes"]["available"],
            "plugin_t1": diff_data["processes"]["plugin_t1"],
            "plugin_t2": diff_data["processes"]["plugin_t2"],
            "total_t1": diff_data["processes"]["total_t1"],
            "total_t2": diff_data["processes"]["total_t2"],
            "new_count": diff_data["processes"]["new_count"],
            "terminated_count": diff_data["processes"]["terminated_count"],
            "persisted_count": diff_data["processes"]["persisted_count"],
            "new": diff_data["processes"]["new"],
            "terminated": diff_data["processes"]["terminated"],
            "persisted": diff_data["processes"]["persisted"],
        },
        "injected": {
            "available": diff_data["injected"]["available"],
            "plugin_t1": diff_data["injected"]["plugin_t1"],
            "plugin_t2": diff_data["injected"]["plugin_t2"],
            "total_t1": diff_data["injected"]["total_t1"],
            "total_t2": diff_data["injected"]["total_t2"],
            "new_count": diff_data["injected"]["new_count"],
            "terminated_count": diff_data["injected"]["terminated_count"],
            "persisted_count": diff_data["injected"]["persisted_count"],
            "new": diff_data["injected"]["new"],
            "terminated": diff_data["injected"]["terminated"],
            "persisted": diff_data["injected"]["persisted"],
        },
        "network": {
            "available": diff_data["network"]["available"],
            "plugin_t1": diff_data["network"]["plugin_t1"],
            "plugin_t2": diff_data["network"]["plugin_t2"],
            "total_t1": diff_data["network"]["total_t1"],
            "total_t2": diff_data["network"]["total_t2"],
            "new_count": diff_data["network"]["new_count"],
            "closed_count": diff_data["network"]["closed_count"],
            "persisted_count": diff_data["network"]["persisted_count"],
            "new": diff_data["network"]["new"],
            "closed": diff_data["network"]["closed"],
            "persisted": diff_data["network"]["persisted"],
        },
        "common_plugins": diff_data["common_plugins"],
    }
    return Status(200, response_data)


@router.get(
    "/values/{int:value_id}/annotations",
    response={200: list[ValueAnnotationOut], 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="get_value_annotations",
)
def get_value_annotations(request, value_id: int):
    """
    Get all annotations for a specific Value row.
    """
    try:
        val = Value.objects.select_related("result__dump").get(pk=value_id)
    except Value.DoesNotExist:
        return Status(404, {"errors": "Value not found."})

    dump = val.result.dump
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view annotations for this dump."})

    annotations = list(val.annotations.select_related("user").order_by("created_at"))
    replies_by_parent: dict[int, list[dict]] = {}
    top_level: list[ValueAnnotation] = []
    for a in annotations:
        if a.parent_id:
            replies_by_parent.setdefault(a.parent_id, []).append(
                {
                    "id": a.id,
                    "value_id": a.value_id,
                    "parent_id": a.parent_id,
                    "user": a.user.username,
                    "status": a.status,
                    "comment": a.comment,
                    "created_at": a.created_at.isoformat(),
                    "replies": [],
                }
            )
        else:
            top_level.append(a)

    return Status(
        200,
        [
            {
                "id": a.id,
                "value_id": a.value_id,
                "parent_id": None,
                "user": a.user.username,
                "status": a.status,
                "comment": a.comment,
                "created_at": a.created_at.isoformat(),
                "replies": replies_by_parent.get(a.id, []),
            }
            for a in top_level
        ],
    )


@router.post(
    "/values/{int:value_id}/annotations",
    response={201: ValueAnnotationOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="create_value_annotation",
)
def create_value_annotation(request, value_id: int, payload: ValueAnnotationIn):
    """
    Create a new annotation for a specific Value row.
    """
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot add annotations."})

    try:
        val = Value.objects.select_related("result__dump").get(pk=value_id)
    except Value.DoesNotExist:
        return Status(404, {"errors": "Value not found."})

    dump = val.result.dump
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view annotations for this dump."})

    if not payload.comment or not payload.comment.strip():
        return Status(400, {"errors": "Comment cannot be empty."})

    valid_statuses = [choice[0] for choice in ValueAnnotation.STATUS_CHOICES]
    if payload.status not in valid_statuses:
        return Status(
            400,
            {"errors": f"Invalid status '{payload.status}'. Valid choices: {valid_statuses}."},
        )

    parent = None
    if payload.parent_id is not None:
        parent = ValueAnnotation.objects.filter(pk=payload.parent_id, value=val).first()
        if not parent:
            return Status(400, {"errors": f"Parent annotation {payload.parent_id} not found on this row."})

    annotation = ValueAnnotation.objects.create(
        value=val,
        parent=parent,
        user=request.user,
        status=payload.status,
        comment=payload.comment.strip(),
    )
    return Status(
        201,
        {
            "id": annotation.id,
            "value_id": annotation.value_id,
            "parent_id": annotation.parent_id,
            "user": annotation.user.username,
            "status": annotation.status,
            "comment": annotation.comment,
            "created_at": annotation.created_at.isoformat(),
            "replies": [],
        },
    )


@router.delete(
    "/annotations/{int:annotation_id}",
    response={200: SuccessResponse, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="delete_value_annotation",
)
def delete_value_annotation_api(request, annotation_id: int):
    """
    Delete an annotation by ID (author or superuser only).
    """
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot delete annotations."})

    try:
        annotation = ValueAnnotation.objects.get(pk=annotation_id)
    except ValueAnnotation.DoesNotExist:
        return Status(404, {"errors": "Annotation not found."})

    if annotation.user != request.user and not request.user.is_superuser:
        return Status(403, {"errors": "Cannot delete another user's annotation."})

    annotation.delete()
    return Status(200, {"message": f"Annotation {annotation_id} deleted successfully."})


###################################################
# Secrets & Detection Triage Endpoints
###################################################
def _serialize_secrets(secrets):
    """Serialize DumpSecret rows for the API (masked values only)."""
    return [
        {
            "id": s.id,
            "category": s.category,
            "category_display": s.get_category_display(),
            "rule_name": s.rule_name,
            "masked_data": s.masked_data,
            "offset": s.offset,
            "pid": s.pid,
            "process_name": s.process_name,
            "created_at": s.created_at.isoformat() if s.created_at else "",
        }
        for s in secrets
    ]


def _build_triage_report(dump):
    """Triage summary of a dump for the API: risk score, severity counts and findings."""
    from orochi.website.forensic_utils import compute_dump_triage_summary

    summary = compute_dump_triage_summary(dump)
    findings = summary["findings"]
    return {
        "dump_index": str(dump.index),
        "dump_name": dump.name,
        "risk_score": dump.risk_score,
        "risk_level": summary["risk_level"],
        "total_findings": findings.count(),
        "severity_counts": summary["severity_counts"],
        "mitre_techniques": summary["mitre_techniques"],
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "category": f.category,
                "severity": f.severity,
                "score": f.score,
                "mitre_technique": f.mitre_technique,
                "description": f.description,
                "evidence_snippet": f.evidence_snippet,
                "entity": f.entity,
                "created_at": f.created_at.isoformat() if f.created_at else "",
            }
            for f in findings
        ],
    }


@router.get(
    "/{str:index}/secrets",
    response={200: list[DumpSecretOut], 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="get_dump_secrets",
)
def get_dump_secrets(request, index: str):
    """
    Get all detected secrets for a specific memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    secrets = dump.secrets.all()
    return Status(200, _serialize_secrets(secrets))


@router.post(
    "/{str:index}/secrets/scan",
    response={200: list[DumpSecretOut], 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="scan_dump_secrets",
)
def scan_dump_secrets(request, index: str):
    """
    Trigger a fresh YARA-X secrets scan over the dump's memory and parsed values.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot run secrets scanner."})

    scan_dump_for_secrets(dump)
    secrets = dump.secrets.all()
    return Status(200, _serialize_secrets(secrets))


@router.get(
    "/{str:index}/triage",
    response={200: TriageReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="get_dump_triage",
)
def get_dump_triage(request, index: str):
    """
    Get the forensic behavioral triage report and findings for a memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    report = _build_triage_report(dump)
    return Status(200, report)


@router.post(
    "/{str:index}/triage/evaluate",
    response={200: TriageReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="evaluate_dump_triage",
)
def evaluate_dump_triage_api(request, index: str):
    """
    Re-evaluate behavioral forensic detection rules over structured plugin outputs.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot run triage evaluation."})

    evaluate_dump_triage(dump)
    dump.refresh_from_db()
    report = _build_triage_report(dump)
    return Status(200, report)


@router.get(
    "/{str:index}/timeline",
    response={200: TimelineReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="get_dump_timeline",
)
def get_dump_timeline(request, index: str, limit: int = 5000):
    """
    Get structured forensic timeline feed, activity histogram, and category metrics for a memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    res = Result.objects.filter(dump=dump, plugin__name="timeliner.Timeliner", result=RESULT_STATUS_SUCCESS).first()

    timeline_entries = []
    if res:
        dump_bodyfile_path = Path(res.dump.upload.path).parent / "timeliner.Timeliner/volatility.body"
        if dump_bodyfile_path.exists():
            timeline_entries = extract_timeline_entries(
                file_path=dump_bodyfile_path,
                dump_name=dump.name,
                dump_index=dump.index,
                dump_color=dump.color or "#3b82f6",
            )
        elif db_vals := list(Value.objects.filter(result=res).values("id", "value")):
            timeline_entries = extract_timeline_entries(
                values=db_vals,
                dump_name=dump.name,
                dump_index=dump.index,
                dump_color=dump.color or "#3b82f6",
            )

    triage_findings = list(dump.triage_findings.all())
    dump_secrets = list(dump.secrets.all())
    feed = build_timeline_feed(
        timeline_entries,
        limit=limit,
        threat_findings=triage_findings,
        secrets=dump_secrets,
    )
    return Status(
        200,
        {
            "dump_index": dump.index,
            "dump_name": dump.name,
            "stats": feed["stats"],
            "categories": feed["categories"],
            "histogram": feed["histogram"],
            "events": feed["events"],
        },
    )


@router.get(
    "/{str:index}/narrative",
    response={200: DumpNarrativeOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="get_dump_narrative",
)
def get_dump_narrative(request, index: str):
    """
    Retrieve the latest AI first-pass forensic triage narrative for a memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    if narrative := dump.narratives.first():
        return Status(
            200,
            {
                "id": narrative.pk,
                "dump_index": dump.index,
                "dump_name": dump.name,
                "model_name": narrative.model_name,
                "created_at": narrative.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "evidence_hash": narrative.evidence_hash,
                "raw_narrative": narrative.raw_narrative,
                "formatted_narrative": narrative.formatted_narrative,
                "hallucination_check": narrative.hallucination_check,
                "citations": narrative.citations,
            },
        )
    else:
        return Status(404, {"errors": "No AI narrative generated yet for this dump."})


@router.post(
    "/{str:index}/narrative/generate",
    response={201: DumpNarrativeOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="generate_dump_narrative",
)
def api_generate_dump_narrative(request, index: str, model_name: str | None = Query(None)):
    """
    Generate a new natural-language first-pass triage narrative with local Ollama inference and forensic guardrail verification.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    if get_user_role(request.user) == ROLE_READONLY:
        return Status(403, {"errors": "Read-only users cannot generate AI narratives."})

    try:
        narrative = generate_dump_narrative(dump, author=request.user, model_name=model_name)
    except Exception as e:
        return Status(400, {"errors": f"Failed to generate narrative: {str(e)}"})

    return Status(
        201,
        {
            "id": narrative.pk,
            "dump_index": dump.index,
            "dump_name": dump.name,
            "model_name": narrative.model_name,
            "created_at": narrative.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "evidence_hash": narrative.evidence_hash,
            "raw_narrative": narrative.raw_narrative,
            "formatted_narrative": narrative.formatted_narrative,
            "hallucination_check": narrative.hallucination_check,
            "citations": narrative.citations,
        },
    )


@router.get(
    "/{str:index}/process-tree",
    response={200: dict, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="get_dump_process_tree",
)
def get_dump_process_tree_api(request, index: str):
    """
    Retrieve the complete hierarchical process tree for a memory dump,
    enriched with command line arguments, forensic triage findings,
    extracted secrets, and threat scores.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized access to dump."})

    from orochi.website.process_tree import build_process_tree

    tree_data = build_process_tree(dump)
    return Status(200, tree_data)


def _serialize_ioc(ioc: DumpIOC) -> dict:
    """Serialize a DumpIOC row (type, value, sources, enrichment) for the API."""
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "ioc_type_display": ioc.get_ioc_type_display(),
        "value": ioc.value,
        "source_plugin": ioc.source_plugin,
        "context": ioc.context or {},
        "enrichment": ioc.enrichment or {},
        "is_malicious": ioc.is_malicious,
        "threat_score": ioc.threat_score,
        "created_at": ioc.created_at.isoformat(),
    }


@router.get(
    "/{str:index}/iocs",
    response={200: DumpIOCReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="get_dump_iocs",
)
def get_dump_iocs_api(
    request,
    index: str,
    ioc_type: str | None = None,
    is_malicious: bool | None = None,
    search: str | None = None,
):
    """
    Get all extracted IOCs (IPs, hashes, domains, URLs, YARA matches) for a memory dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    iocs = dump.iocs.all()
    if ioc_type:
        iocs = iocs.filter(ioc_type=ioc_type)
    if is_malicious is not None:
        iocs = iocs.filter(is_malicious=is_malicious)
    if search:
        iocs = iocs.filter(Q(value__icontains=search) | Q(source_plugin__icontains=search))

    total = dump.iocs.count()
    malicious = dump.iocs.filter(is_malicious=True).count()
    type_counts = {
        "ip": dump.iocs.filter(ioc_type="ip").count(),
        "hash_sha256": dump.iocs.filter(ioc_type="hash_sha256").count(),
        "hash_md5": dump.iocs.filter(ioc_type="hash_md5").count(),
        "domain": dump.iocs.filter(ioc_type="domain").count(),
        "url": dump.iocs.filter(ioc_type="url").count(),
        "yara": dump.iocs.filter(ioc_type="yara").count(),
    }

    return Status(
        200,
        {
            "dump_index": dump.index,
            "dump_name": dump.name,
            "total_count": total,
            "malicious_count": malicious,
            "type_counts": type_counts,
            "iocs": [_serialize_ioc(x) for x in iocs],
        },
    )


@router.get(
    "/{str:index}/network",
    response={200: NetworkReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="get_dump_network",
)
def get_dump_network_api(request, index: str):
    """
    Get the network topology graph, socket connections, and geographical IP locations for a dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})

    from orochi.website.network import extract_network_report

    data = extract_network_report(dump)
    return Status(200, data)


@router.post(
    "/{str:index}/iocs/scan",
    response={200: DumpIOCReportOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="scan_dump_iocs",
)
def scan_dump_iocs_api(request, index: str):
    """
    Trigger automated extraction of indicators across network, dumped files, YARA hits, and command lines.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot run IOC extraction."})

    from orochi.website.ioc import extract_dump_iocs

    extract_dump_iocs(dump)
    iocs = dump.iocs.all()
    total = iocs.count()
    malicious = iocs.filter(is_malicious=True).count()
    type_counts = {
        "ip": iocs.filter(ioc_type="ip").count(),
        "hash_sha256": iocs.filter(ioc_type="hash_sha256").count(),
        "hash_md5": iocs.filter(ioc_type="hash_md5").count(),
        "domain": iocs.filter(ioc_type="domain").count(),
        "url": iocs.filter(ioc_type="url").count(),
        "yara": iocs.filter(ioc_type="yara").count(),
    }

    return Status(
        200,
        {
            "dump_index": dump.index,
            "dump_name": dump.name,
            "total_count": total,
            "malicious_count": malicious,
            "type_counts": type_counts,
            "iocs": [_serialize_ioc(x) for x in iocs],
        },
    )


@router.post(
    "/{str:index}/iocs/{int:ioc_id}/enrich",
    response={200: DumpIOCOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="enrich_dump_ioc",
)
def enrich_dump_ioc_api(request, index: str, ioc_id: int):
    """
    Enrich a single IOC using configured threat intel services (AbuseIPDB, OTX, GreyNoise, VirusTotal).
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot run threat enrichment."})

    ioc = get_object_or_404(DumpIOC, id=ioc_id, dump=dump)
    from orochi.website.ioc import enrich_ioc

    enrich_ioc(ioc)
    return Status(200, _serialize_ioc(ioc))


@router.post(
    "/{str:index}/iocs/enrich-all",
    response={200: SuccessResponse, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="enrich_all_dump_iocs",
)
def enrich_all_dump_iocs_api(request, index: str):
    """
    Batch enrich all extracted IOCs for a dump.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to view this dump."})
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot run threat enrichment."})

    from orochi.website.ioc import enrich_iocs

    summary = enrich_iocs(dump.iocs.all())
    return Status(200, {"success": summary["success"], "message": summary["message"]})


@router.post(
    "/{str:index}/export-misp",
    response={200: ExportMISPOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="api_export_misp",
)
def api_export_misp(request, index: str, payload: ExportMISPIn):
    """
    Export dump artifacts or extracted IOCs to MISP.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(403, {"errors": "Unauthorized to access this dump."})
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot export to MISP."})

    from orochi.website.ioc import export_iocs_to_misp

    # Export IOCs if ioc_ids or export_all_iocs specified
    if payload.ioc_ids or payload.export_all_iocs:
        if payload.ioc_ids:
            iocs = list(dump.iocs.filter(id__in=payload.ioc_ids))
        else:
            iocs = list(dump.iocs.all())
        if not iocs:
            return Status(400, {"errors": "No matching IOCs found to export."})

        try:
            res = export_iocs_to_misp(dump, iocs, request.user)
            return Status(200, res)
        except Exception as e:
            return Status(400, {"errors": str(e)})

    # Export file if filepath provided
    if payload.filepath:
        from pymisp import MISPEvent, PyMISP
        from pymisp.tools import FileObject

        from orochi.website.defaults import SERVICE_MISP
        from orochi.website.models import Service

        try:
            misp_info = Service.objects.get(name=SERVICE_MISP)
        except Service.DoesNotExist:
            return Status(400, {"errors": "MISP service is not configured in Admin > Services."})

        filepath = payload.filepath
        p_file = Path(filepath)
        if not p_file.exists():
            cand = Path(settings.MEDIA_ROOT) / filepath.lstrip("/")
            if cand.exists():
                filepath = str(cand)
            else:
                return Status(400, {"errors": f"Extracted file not found on disk at '{filepath}'."})

        proxy_dict = misp_info.proxy if (misp_info.proxy and isinstance(misp_info.proxy, dict)) else None
        try:
            misp = PyMISP(misp_info.url, misp_info.decrypted_key, misp_info.verify_ssl, proxies=proxy_dict)
            event = MISPEvent()
            event.info = f"From orochi API: {dump.name}"
            event.distribution = 0
            event.threat_level_id = 1 if dump.risk_score >= 75 else 2 if dump.risk_score >= 50 else 3
            event.analysis = 2
            event.add_tag("orochi")
            event.add_tag("memory-forensics")

            file_obj = FileObject(filepath)
            event.add_object(file_obj)
            res = misp.add_event(event)
            event_id = res.get("Event", {}).get("id") if isinstance(res, dict) else getattr(event, "id", None)
            event_uuid = res.get("Event", {}).get("uuid") if isinstance(res, dict) else getattr(event, "uuid", None)
            return Status(
                200,
                {
                    "success": True,
                    "message": f"Successfully exported file to MISP (Event ID: {event_id})",
                    "event_id": event_id,
                    "event_uuid": event_uuid,
                    "exported_count": 1,
                },
            )
        except Exception as ex:
            return Status(400, {"errors": str(ex)})

    return Status(400, {"errors": "Must specify either filepath or ioc_ids/export_all_iocs."})


@router.post(
    "/{index}/sandbox/submit",
    auth=dual_auth,
    response={200: dict, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="dump_sandbox_submit",
)
@ninja_test_required("is_not_readonly")
def dump_sandbox_submit(request, index: str, filepath: str, machine: str | None = None, tags: str | None = None):
    """
    Summary:
    Submit an extracted artifact/PE from a dump to CAPE / Cuckoo Sandbox (Issue #1551).
    """
    dump = Dump.objects.filter(index=index).first()
    if not dump:
        return Status(404, {"errors": "Dump not found"})

    if not request.user.is_superuser:
        dumps_ok = get_objects_for_user(request.user, "website.can_see")
        if dump not in dumps_ok:
            return Status(403, {"errors": "Permission denied"})

    from orochi.website.integrations import submit_file_to_sandbox

    try:
        res = submit_file_to_sandbox(dump, filepath=filepath, machine=machine, tags=tags)
        return Status(200, res)
    except Exception as exc:
        return Status(400, {"errors": str(exc)})
