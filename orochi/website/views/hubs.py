import json

import requests
from django.contrib.auth.decorators import login_required
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import F, Q
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, render
from django.utils.text import slugify
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user

from orochi.backends.dask_client import get_dask_client
from orochi.website.ai_narrative import generate_dump_narrative, get_local_ollama_config
from orochi.website.defaults import RESULT_STATUS_RUNNING, RESULT_STATUS_SUCCESS
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.forensic_utils import compute_dump_triage_summary, format_narrative_markdown
from orochi.website.models import (
    Case,
    Dump,
    DumpNarrative,
    DumpSecret,
    Plugin,
    Result,
    Value,
)
from orochi.website.secrets_scanner import scan_dump_for_secrets
from orochi.website.temporal import compute_temporal_diff
from orochi.website.views.common import is_not_readonly


@login_required
def diff_view(request, index_a, index_b, plugin):
    """Compare json views"""
    dump1 = get_object_or_404(Dump, index=index_a)
    dump2 = get_object_or_404(Dump, index=index_b)
    if dump1 not in get_objects_for_user(request.user, "website.can_see") or dump2 not in get_objects_for_user(
        request.user, "website.can_see"
    ):
        raise Http404("404")

    def _collect_rows(target_dump: Dump) -> list[dict]:
        """Successful rows of a plugin on one dump, annotated with plugin and dump metadata."""
        qs = (
            Value.objects.select_related("result__plugin", "result__dump")
            .filter(result__plugin__name=plugin, result__dump=target_dump, result__result=RESULT_STATUS_SUCCESS)
            .annotate(
                orochi_plugin=F("result__plugin__name"),
                orochi_name=F("result__dump__name"),
                orochi_os=F("result__dump__operating_system"),
                orochi_color=F("result__dump__color"),
                orochi_createdAt=F("result__updated_at"),
            )
            .values(
                "orochi_plugin",
                "orochi_name",
                "orochi_os",
                "orochi_color",
                "orochi_createdAt",
                "value",
            )
        )
        rows = []
        for item in qs.iterator(chunk_size=2000):
            tmp = {k: item[k] for k in item.keys() - {"value"}}
            if isinstance(item["value"], dict):
                tmp.update(item["value"])
            rows.append(tmp)
        return rows

    info_a = _collect_rows(dump1)
    info_b = _collect_rows(dump2)
    return render(
        request,
        "website/diff_view.html",
        {
            "info_a": json.dumps(info_a, cls=DjangoJSONEncoder),
            "info_b": json.dumps(info_b, cls=DjangoJSONEncoder),
            "index_a": index_a,
            "index_b": index_b,
            "dump_a": dump1,
            "dump_b": dump2,
            "plugin": plugin,
        },
    )


@login_required
def temporal_diff(request, index_a, index_b):
    """Temporal diff view for comparing two captures (same host T1 vs T2)."""
    dump1 = get_object_or_404(Dump, index=index_a)
    dump2 = get_object_or_404(Dump, index=index_b)
    user_dumps = get_objects_for_user(request.user, "website.can_see")
    if dump1 not in user_dumps or dump2 not in user_dumps:
        raise Http404("404")

    reverse_order = request.GET.get("reverse") in ["1", "true", "True"]
    diff_data = compute_temporal_diff(dump1, dump2, reverse=reverse_order)
    user_cases = Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct()

    return render(
        request,
        "website/temporal_diff.html",
        {
            "diff": diff_data,
            "index_a": index_a,
            "index_b": index_b,
            "reverse_order": reverse_order,
            "cases": user_cases,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def dump_secrets(request, index):
    """View and scan secrets for a specific memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot run secrets scanner.")
        scan_dump_for_secrets(dump)

    secrets = dump.secrets.all()
    is_htmx = getattr(request, "htmx", False)
    template = "website/partial_dump_secrets.html" if is_htmx else "website/dump_secrets.html"
    return render(
        request,
        template,
        {
            "dump": dump,
            "secrets": secrets,
            "categories": DumpSecret.CATEGORY_CHOICES,
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def dump_triage(request, index):
    """View and evaluate behavioral triage rules and risk scoring for a memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot run triage evaluation.")
        evaluate_dump_triage(dump)
        dump.refresh_from_db()

    summary = compute_dump_triage_summary(dump)
    is_htmx = getattr(request, "htmx", False)
    template = "website/partial_dump_triage.html" if is_htmx else "website/dump_triage.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "findings": summary["findings"],
            "risk_level": summary["risk_level"],
            "severity_kpis": summary["severity_kpis"],
            "mitre_techniques": summary["mitre_techniques"],
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET"])
def dump_process_tree(request, index):
    """View interactive visual process tree for a memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    from orochi.website.process_tree import build_process_tree

    tree_data = build_process_tree(dump)
    focus_pid = request.GET.get("focus") or request.GET.get("pid") or ""

    is_htmx = (
        getattr(request, "htmx", False)
        or request.headers.get("HX-Request") == "true"
        or request.GET.get("modal") == "1"
    )
    template = "website/partial_dump_process_tree.html" if is_htmx else "website/dump_process_tree.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "tree_data": tree_data,
            "tree_json": json.dumps(tree_data),
            "focus_pid": focus_pid,
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def dump_narrative(request, index):
    """Generate and display natural-language first-pass triage narrative with local Ollama."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    error = None
    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot generate AI narratives.")
        model_name = request.POST.get("model_name", "").strip() or None
        try:
            generate_dump_narrative(dump, author=request.user, model_name=model_name)
        except Exception as e:
            error = str(e)

    latest_narrative = dump.narratives.first()
    history = dump.narratives.all()[1:10]

    base_url, default_model, _ = get_local_ollama_config()
    available_models = [default_model]
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=3)
        if resp.status_code == 200:
            names = [m.get("name") for m in resp.json().get("models", []) if m.get("name")]
            if names:
                available_models = names
    except Exception:
        pass

    is_htmx = getattr(request, "htmx", False)
    template = "website/partial_dump_narrative.html" if is_htmx else "website/dump_narrative.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "narrative": latest_narrative,
            "history": history,
            "available_models": available_models,
            "current_model": (latest_narrative.model_name if latest_narrative else default_model),
            "error": error,
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET"])
def dump_narrative_export(request, index, narrative_id):
    """Export verified AI narrative as a standalone Markdown document."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to access this dump.")

    narrative = get_object_or_404(DumpNarrative, pk=narrative_id, dump=dump)
    content = format_narrative_markdown(dump, narrative)
    filename = f"{slugify(dump.name)}_triage_narrative.md"
    response = HttpResponse(content, content_type="text/markdown; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@login_required
@require_http_methods(["GET"])
def dump_network(request, index):
    """View interactive network topology graph and geo-map for a memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    from orochi.website.network import extract_network_report

    network_data = extract_network_report(dump)
    is_htmx = (
        getattr(request, "htmx", False)
        or request.headers.get("HX-Request") == "true"
        or request.GET.get("modal") == "1"
    )
    template = "website/partial_dump_network.html" if is_htmx else "website/dump_network.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "network_data": network_data,
            "network_json": network_data,
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET"])
def partial_dump_network(request, index):
    """Render HTMX partial for network topology graph and geo-map."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    from orochi.website.network import extract_network_report

    network_data = extract_network_report(dump)
    return render(
        request,
        "website/partial_dump_network.html",
        {
            "dump": dump,
            "network_data": network_data,
            "network_json": network_data,
            "is_standalone": False,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def dump_process_dossier(request, index, pid: int):
    """
    360-degree Cross-Plugin Process Dossier for a single PID in a memory dump.
    Supports progressive disclosure (plugin coverage bar) and POST to enqueue
    missing forensic plugins on Dask.
    """
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    from orochi.website.process_dossier import build_process_dossier

    enqueued_plugins: list[str] = []
    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot execute plugins.")
        from orochi.api.routers.dumps import plugin_f_and_f

        requested = request.POST.getlist("plugins")
        single_plugin = request.POST.get("plugin", "").strip()
        if single_plugin:
            requested.append(single_plugin)
        if not requested and request.POST.get("run_all_missing") == "1":
            current_dossier = build_process_dossier(dump, int(pid))
            requested = current_dossier["coverage"]["missing_plugins"]

        shared_dask_client = None
        if len(requested) > 1:
            try:
                shared_dask_client = get_dask_client()
            except Exception:
                shared_dask_client = None

        for p_name in requested:
            plugin_obj = Plugin.objects.filter(name__iexact=p_name).first()
            if not plugin_obj:
                continue
            res_obj, _ = Result.objects.get_or_create(dump=dump, plugin=plugin_obj)
            if res_obj.result != RESULT_STATUS_RUNNING:
                res_obj.result = RESULT_STATUS_RUNNING
                res_obj.parameter = {}
                res_obj.save(update_fields=["result", "parameter", "updated_at"])
                try:
                    plugin_f_and_f(
                        dump,
                        plugin_obj,
                        {},
                        user_pk=request.user.pk,
                        priority=5,
                        dask_client=shared_dask_client,
                    )
                except Exception:
                    pass
                enqueued_plugins.append(plugin_obj.name)

    dossier = build_process_dossier(dump, int(pid))
    is_htmx = (
        getattr(request, "htmx", False)
        or request.headers.get("HX-Request") == "true"
        or request.GET.get("modal") == "1"
        or request.method == "POST"
    )
    template = "website/partial_process_dossier.html" if is_htmx else "website/dump_process_dossier.html"
    return render(
        request,
        template,
        {
            "dump": dump,
            "pid": int(pid),
            "dossier": dossier,
            "enqueued_plugins": enqueued_plugins,
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )
