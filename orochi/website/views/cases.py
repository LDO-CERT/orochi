import json
import logging
from pathlib import Path

import requests
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Prefetch, Q
from django.db.utils import IntegrityError
from django.http import Http404, HttpResponseBadRequest, HttpResponseForbidden, JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.text import slugify
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user

from orochi.website import ctf
from orochi.website.attack import (
    generate_navigator_layer,
    get_all_technique_choices,
    get_case_attack_coverage,
)
from orochi.website.defaults import (
    SERVICE_CAPE,
    SERVICE_CORTEX,
    SERVICE_SIEM,
    SERVICE_THEHIVE,
)
from orochi.website.forms import (
    CaseForm,
    EvidenceForm,
    FindingForm,
    FolderForm,
    SandboxSubmitForm,
)
from orochi.website.integrations import cape_base_url, submit_file_to_sandbox
from orochi.website.models import (
    Case,
    Dump,
    DumpSecret,
    Evidence,
    Finding,
    Folder,
    ReportTemplate,
    Service,
    TimelineEvent,
    TriageFinding,
    UserPlugin,
    Value,
    ValueAnnotation,
)
from orochi.website.search import execute_vector_search
from orochi.website.views.common import (
    DUMP_ORDER_BY,
    INDEX_VALUES_LIST,
    is_not_readonly,
    role_required,
)

logger = logging.getLogger(__name__)


def _accessible_cases_qs(user):
    """Cases the user can open: all for superusers, otherwise owned or shared as collaborator."""
    return Case.objects.visible_to(user, all_for_superuser=True)


def _user_can_access_case(case, user) -> bool:
    """True when the user owns the case, collaborates on it or is a superuser."""
    if not case:
        return False
    return user.is_superuser or case.user_id == user.pk or case.collaborators.filter(pk=user.pk).exists()


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def folder_create(request):
    """Render the folder form (GET) or create a folder owned by the user (POST)."""
    if request.method != "POST":
        return (
            render(request, "website/partial_folder.html", {"form": FolderForm()})
            if getattr(request, "htmx", False)
            else JsonResponse(
                {
                    "html_form": render_to_string(
                        "website/partial_folder.html",
                        {"form": FolderForm()},
                        request=request,
                    )
                }
            )
        )
    form = FolderForm(request.POST)
    if form.is_valid():
        try:
            with transaction.atomic():
                folder = form.save(commit=False)
                folder.user = request.user
                folder.save()
            return HttpResponse(
                "",
                headers={
                    "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Folder has been created", "type": "success"}, "closeModal": true}'
                },
            )
        except IntegrityError:
            form.add_error("name", "Folder already exists")
    return render(request, "website/partial_folder.html", {"form": form})


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def case_create(request):
    """Render the case form (GET) or create a case owned by the user (POST)."""
    if request.method != "POST":
        return (
            render(
                request,
                "website/partial_case.html",
                {
                    "form": CaseForm(request.user),
                    "url": reverse("website:case_create"),
                },
            )
            if getattr(request, "htmx", False)
            else JsonResponse(
                {
                    "html_form": render_to_string(
                        "website/partial_case.html",
                        {
                            "form": CaseForm(request.user),
                            "url": reverse("website:case_create"),
                        },
                        request=request,
                    )
                }
            )
        )
    form = CaseForm(request.user, request.POST)
    if form.is_valid():
        try:
            with transaction.atomic():
                case = form.save(commit=False)
                case.user = request.user
                case.save()
                form.save_m2m()
            return HttpResponse(
                "",
                headers={
                    "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been created", "type": "success"}, "closeModal": true, "refreshCases": true}'
                },
            )
        except IntegrityError:
            form.add_error("name", "Case already exists")
    return render(
        request,
        "website/partial_case.html",
        {"form": form, "url": reverse("website:case_create")},
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def case_edit(request):
    """Render or save the edit form of a case the user can access (``?pk=`` query parameter)."""
    case = get_object_or_404(
        _accessible_cases_qs(request.user),
        pk=request.GET.get("pk"),
    )
    edit_url = reverse("website:case_edit") + f"?pk={case.pk}"
    if request.method == "POST":
        form = CaseForm(request.user, request.POST, instance=case)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been updated", "type": "success"}, "closeModal": true, "refreshCaseDetail": true, "refreshCases": true}'
                    },
                )
            except IntegrityError:
                form.add_error("name", "Case already exists")
        return render(request, "website/partial_case.html", {"form": form, "url": edit_url})

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_case.html",
            {
                "form": CaseForm(request.user, instance=case),
                "url": edit_url,
            },
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_case.html",
                {
                    "form": CaseForm(request.user, instance=case),
                    "url": edit_url,
                },
                request=request,
            )
        }
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_delete(request, pk):
    """Delete a case with its evidence; only the owner or a superuser can do it."""
    case = (
        get_object_or_404(Case, pk=pk)
        if request.user.is_superuser
        else get_object_or_404(Case, pk=pk, user=request.user)
    )
    from orochi.website.notifier import bold, notify_users

    recipients = list({case.user, *case.collaborators.all()})
    case_name = case.name
    case.delete()
    notify_users(
        recipients,
        f"Case {bold(case_name)} has been deleted by {bold(request.user.username)}.",
        html=True,
        kind="warning",
    )
    if getattr(request, "htmx", False):
        return HttpResponse(
            "",
            headers={
                "HX-Redirect": reverse("website:index"),
                "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been deleted", "type": "success"}}',
            },
        )
    return redirect("website:index")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_change_status(request, pk):
    """Set the status (Open / In Progress / Closed) of an accessible case and refresh the case views."""
    case = get_object_or_404(
        _accessible_cases_qs(request.user),
        pk=pk,
    )
    new_status = request.POST.get("status") or request.GET.get("status")
    valid_statuses = [choice[0] for choice in Case.STATUS_CHOICES]
    if new_status in valid_statuses:
        case.status = new_status
        case.save(update_fields=["status"])
        return HttpResponse(
            "",
            headers={
                "HX-Trigger": json.dumps(
                    {
                        "showMessage": {
                            "title": "Operation successful!",
                            "content": f"Case status updated to {new_status}",
                            "type": "success",
                        },
                        "refreshCaseDetail": True,
                        "refreshCases": True,
                    }
                )
            },
        )
    return HttpResponse("Invalid status", status=400)


def _sandbox_task_url(service, task_id):
    """Link to the CAPE analysis page of a task, when the API answered with an id."""
    return f"{cape_base_url(service.url)}/submit/status/{task_id}/" if task_id else None


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def sandbox_submit(request):
    """Modal to send a file extracted from a dump to the configured CAPE / Cuckoo sandbox."""
    service = Service.objects.filter(name=SERVICE_CAPE).first()
    if not service:
        return HttpResponseBadRequest("CAPE / Cuckoo Sandbox service is not configured.")

    form = SandboxSubmitForm(request.POST if request.method == "POST" else request.GET)
    if not form.is_valid():
        return HttpResponseBadRequest("Missing dump or file.")
    dump = get_object_or_404(
        get_objects_for_user(request.user, "website.can_see", klass=Dump), index=form.cleaned_data["index"]
    )
    context = {"form": form, "dump": dump, "filename": Path(form.cleaned_data["path"]).name}

    if request.method == "POST":
        try:
            res = submit_file_to_sandbox(
                dump,
                filepath=form.cleaned_data["path"],
                machine=form.cleaned_data["machine"] or None,
                tags=form.cleaned_data["tags"] or None,
            )
        except requests.RequestException as exc:
            logger.warning("Sandbox submission to %s failed: %s", service.url, exc)
            context["error"] = f"Cannot reach the sandbox at {service.url}: check the service URL, proxy and network."
            return render(request, "website/partial_sandbox_submit.html", context)
        except (ValueError, FileNotFoundError, RuntimeError) as exc:
            context["error"] = str(exc)
            return render(request, "website/partial_sandbox_submit.html", context)

        task_id = res.get("task_id")
        context.update(submitted=True, task_id=task_id, task_url=_sandbox_task_url(service, task_id))
    return render(request, "website/partial_sandbox_submit.html", context)


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def cortex_submit(request, pk, evidence_id):
    """Modal to run a Cortex analyzer on the extracted file of a case evidence (#1550)."""
    from orochi.website.integrations import run_cortex_analyzer

    case = get_object_or_404(_accessible_cases_qs(request.user), pk=pk)
    evidence = get_object_or_404(Evidence.objects.select_related("dump"), case=case, pk=evidence_id)
    if not Service.objects.filter(name=SERVICE_CORTEX).exclude(url="").exists():
        return HttpResponseBadRequest("Cortex service is not configured.")
    filepath = evidence.extracted_file or (
        evidence.result_row.get("down_path") if isinstance(evidence.result_row, dict) else None
    )
    context = {"case": case, "evidence": evidence, "filename": Path(filepath).name if filepath else None}
    if job_id := request.GET.get("job"):
        # "Check result": status and report summary of a submitted job
        from orochi.website.integrations import cortex_job_report

        try:
            context["report"] = cortex_job_report(job_id)
        except (requests.RequestException, RuntimeError, ValueError) as exc:
            context["error"] = f"Cannot read the Cortex job: {exc}"
        context["job"] = {"job_id": job_id, "status": context.get("report", {}).get("status", "?")}
        return render(request, "website/partial_cortex_submit.html", context)
    try:
        from orochi.website.integrations import list_cortex_analyzers

        context["analyzers"] = list_cortex_analyzers("file")
    except (requests.RequestException, RuntimeError, ValueError) as exc:
        context["analyzers_error"] = f"Analyzers could not be listed from Cortex ({exc}); enter the analyzer name."
    if request.method == "POST":
        analyzer_id = (request.POST.get("analyzer_id") or "").strip()
        if not analyzer_id:
            context["error"] = "Enter the analyzer to run (e.g. FileInfo_8_0)."
        elif not (filepath and evidence.dump):
            context["error"] = "This evidence does not reference a file extracted from a dump."
        else:
            try:
                context["job"] = run_cortex_analyzer(evidence.dump, filepath, analyzer_id)
            except requests.RequestException as exc:
                context["error"] = f"Cannot reach Cortex: {exc.__class__.__name__}. Check the service URL and proxy."
            except (ValueError, FileNotFoundError, RuntimeError) as exc:
                context["error"] = str(exc)
        context["analyzer_id"] = analyzer_id
    return render(request, "website/partial_cortex_submit.html", context)


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def case_import(request):
    """Modal to import a .orochi.zip Case Bundle (#1539); verified against its manifest before anything is created."""
    from orochi.website.case_bundle import BundleIntegrityError, import_case_bundle

    context = {}
    if request.method == "POST":
        upload = request.FILES.get("bundle")
        if not upload:
            context["error"] = "Choose a .orochi.zip bundle."
        else:
            try:
                case = import_case_bundle(upload.read(), request.user, name_override=request.POST.get("name") or None)
            except BundleIntegrityError as exc:
                context["error"] = f"Bundle refused: {exc}"
            except Exception as exc:
                logger.warning("Case bundle import failed: %s", exc)
                context["error"] = "The file is not a valid Orochi case bundle."
            else:
                return HttpResponse(headers={"HX-Redirect": reverse("website:case_detail", kwargs={"pk": case.pk})})
    return render(request, "website/partial_case_import.html", context)


@login_required
def case_detail(request, pk):
    """Case page: evidence, findings, timeline, related dumps and ATT&CK coverage.

    Related dumps are the visible dumps of the case folder or referenced by its Evidence; CTF cases also list
    the challenge dumps. HTMX requests get the partial, others the full workbench page.
    """
    case = get_object_or_404(
        _accessible_cases_qs(request.user),
        pk=pk,
    )

    # Handle manual timeline event create/delete (#1538)
    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot modify case timeline.")
        action = request.POST.get("action")
        if action == "add_timeline_event":
            from datetime import UTC

            from django.utils.dateparse import parse_datetime
            from django.utils.timezone import is_naive, make_aware
            from django.utils.timezone import now as tz_now

            desc = (request.POST.get("description") or "").strip()
            ev_type = (request.POST.get("event_type") or "Manual Entry").strip()
            ts_raw = (request.POST.get("timestamp") or "").strip()
            ts = parse_datetime(ts_raw) if ts_raw else tz_now()
            if ts is None:
                ts = tz_now()
            elif is_naive(ts):
                ts = make_aware(ts, UTC)
            if desc:
                TimelineEvent.objects.create(
                    case=case, timestamp=ts, event_type=ev_type, description=desc, created_by=request.user
                )
                messages.success(request, "Manual timeline event added.")
            else:
                messages.error(request, "Timeline event description is required.")
            return redirect("website:case_detail", pk=case.pk)
        elif action == "delete_timeline_event":
            from orochi.website.defaults import ACTIVITY_EVENT_TYPES

            ev_id = request.POST.get("event_id")
            if ev_id and str(ev_id).isdigit():
                TimelineEvent.objects.filter(case=case, pk=int(ev_id)).exclude(
                    event_type__in=ACTIVITY_EVENT_TYPES
                ).delete()
                messages.success(request, "Timeline event deleted.")
            return redirect("website:case_detail", pk=case.pk)

    visible_dumps = get_objects_for_user(request.user, "website.can_see")
    evidence_dump_ids = list(case.evidences.exclude(dump__isnull=True).values_list("dump_id", flat=True))
    if case.ctf_template_id:
        evidence_dump_ids += [d.pk for d in ctf.challenge_dumps(case.ctf_template)]
    elif case.is_ctf:
        evidence_dump_ids += list(case.ctf_dumps.values_list("pk", flat=True))
    if case.folder:
        related_dumps = visible_dumps.filter(Q(folder=case.folder) | Q(pk__in=evidence_dump_ids)).distinct()
    else:
        related_dumps = visible_dumps.filter(pk__in=evidence_dump_ids).distinct()
    from orochi.website.case_reporting import _collect_artefact_timeline, _collect_case_dumps

    case_dumps = _collect_case_dumps(case)
    from orochi.website.defaults import ACTIVITY_EVENT_TYPES as activity_types

    all_tl = list(case.timeline_events.all())
    manual_timeline = [e for e in all_tl if e.event_type not in activity_types]
    # One chronological forensic timeline: artefact times from the dumps and the analysts' manual entries
    forensic_timeline = sorted(
        [
            {"timestamp": ts, "event_type": ev_t, "description": desc, "kind": "artefact"}
            for ts, ev_t, desc in _collect_artefact_timeline(case, case_dumps, include_manual=False)
        ]
        + [
            {
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "description": e.description,
                "kind": "manual",
                "pk": e.pk,
                "author": e.created_by.username if e.created_by_id else "",
            }
            for e in manual_timeline
        ],
        key=lambda item: item["timestamp"],
    )
    artefact_timeline = [e for e in forensic_timeline if e["kind"] == "artefact"]
    activity_timeline = [e for e in all_tl if e.event_type in activity_types]

    templates = ReportTemplate.objects.all()
    context = {
        "case": case,
        "evidences": case.evidences.all(),
        "findings": case.findings.all(),
        "timeline_events": all_tl,
        "forensic_timeline": forensic_timeline,
        "artefact_timeline": artefact_timeline,
        "manual_timeline": manual_timeline,
        "activity_timeline": activity_timeline,
        "related_dumps": related_dumps,
        "report_templates": templates,
        "attack_coverage": get_case_attack_coverage(case.findings.all()),
        "configured_integrations": set(
            Service.objects.filter(name__in=[SERVICE_SIEM, SERVICE_THEHIVE, SERVICE_CORTEX, SERVICE_CAPE])
            .exclude(url__isnull=True)
            .exclude(url="")
            .values_list("name", flat=True)
        ),
        "SERVICE_CAPE": SERVICE_CAPE,
        "SERVICE_CORTEX": SERVICE_CORTEX,
        "SERVICE_SIEM": SERVICE_SIEM,
        "SERVICE_THEHIVE": SERVICE_THEHIVE,
    }

    if getattr(request, "htmx", False) and request.headers.get("HX-Target") != "body":
        return TemplateResponse(request, "website/partial_case_detail.html", context)

    from django.db.models import Exists, OuterRef

    has_auto_plugins = UserPlugin.objects.filter(
        user=request.user,
        automatic=True,
        plugin__operating_system__in=[OuterRef("operating_system"), "Other"],
        plugin__disabled=False,
    )
    context |= {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .annotate(has_auto=Exists(has_auto_plugins))
        .values_list(*INDEX_VALUES_LIST)
        .order_by(*DUMP_ORDER_BY),
        "main_page": True,
        "selected_indexes": [],
        "selected_plugin": None,
        "selected_query": None,
        "cases": Case.objects.visible_to(request.user).prefetch_related("evidences", "collaborators"),
        "readonly": not is_not_readonly(request.user),
    }
    return TemplateResponse(request, "website/index.html", context)


@login_required
@role_required(is_not_readonly)
def case_export(request, pk):
    """Download a portable, SHA-256-verified ``.orochi.zip`` Case Bundle (Issue #1539)."""
    from orochi.website.case_bundle import export_case_bundle

    case = get_object_or_404(
        _accessible_cases_qs(request.user),
        pk=pk,
    )
    bundle_bytes = export_case_bundle(case)
    resp = HttpResponse(bundle_bytes, content_type="application/zip")
    resp["Content-Disposition"] = f'attachment; filename="case_{case.pk}.orochi.zip"'
    return resp


@login_required
def case_mitre_export(request, pk):
    """Download the MITRE ATT&CK Navigator layer (JSON) built from the case findings."""
    case = get_object_or_404(Case, pk=pk)
    if not _user_can_access_case(case, request.user):
        raise Http404("Not authorized")

    layer_data = generate_navigator_layer(case, case.findings.all())
    json_bytes = json.dumps(layer_data, indent=2).encode("utf-8")

    response = HttpResponse(json_bytes, content_type="application/json")
    safe_name = slugify(case.name) or f"case_{case.pk}"
    response["Content-Disposition"] = f'attachment; filename="case_{safe_name}_mitre_layer.json"'
    return response


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_report(request, pk):
    """Render a case report from a ReportTemplate (DOCX via docxtpl, otherwise a Django HTML template).

    With ``use_ai=true`` an Ollama summary of the findings is added to the context as ``ai_summary``.
    """
    import io

    import requests
    from django.http import HttpResponse
    from django.template import engines
    from docxtpl import DocxTemplate

    from orochi.website.defaults import SERVICE_OLLAMA

    case = get_object_or_404(
        _accessible_cases_qs(request.user),
        pk=pk,
    )
    template_id = request.POST.get("template_id")
    use_ai = request.POST.get("use_ai") == "true"

    report_template = get_object_or_404(ReportTemplate, pk=template_id)

    context = {
        "case": case,
        "evidences": case.evidences.all(),
        "findings": case.findings.all(),
        "timeline_events": case.timeline_events.all(),
        "ai_summary": None,
        "ai_summary_html": None,
    }

    if use_ai:
        ollama_service = Service.objects.filter(name=SERVICE_OLLAMA).first()
        if ollama_service and ollama_service.url:
            findings_text = "\n".join(
                [
                    f"- [{f.severity}] {f.mitre_attack_technique or 'No Technique'}: {f.note}"
                    for f in case.findings.all()
                ]
            )
            prompt = (
                f"Write a professional executive summary for a digital forensics case named '{case.name}'. "
                f"Findings:\n{findings_text}\nProvide a concise analysis in markdown format."
            )

            model_name = ollama_service.decrypted_key or "llama3"  # Use key for model name if provided

            try:
                proxies = ollama_service.proxy or None
                response = requests.post(
                    f"{ollama_service.url.rstrip('/')}/api/generate",
                    json={"model": model_name, "prompt": prompt, "stream": False},
                    proxies=proxies,
                    timeout=60,
                )
                if response.status_code == 200:
                    context["ai_summary"] = response.json().get("response", "")
                else:
                    context["ai_summary"] = f"Error from Ollama: {response.text}"
            except Exception as e:
                context["ai_summary"] = f"Error connecting to Ollama: {str(e)}"
        else:
            context["ai_summary"] = (
                "Ollama service is not configured in Admin > Services. "
                "Please configure Ollama with URL (e.g. http://ollama:11434) and a downloaded model name (e.g. llama3)."
            )

    if context["ai_summary"]:
        try:
            import marko

            context["ai_summary_html"] = marko.convert(context["ai_summary"])
        except Exception:
            context["ai_summary_html"] = context["ai_summary"]

    try:
        template_name = report_template.template.name.lower()
        if template_name.endswith(".docx"):
            with report_template.template.open("rb") as f:
                doc = DocxTemplate(f)
                doc.render(context)
                bio = io.BytesIO()
                doc.save(bio)
                bio.seek(0)

            safe_name = (
                "".join(c for c in case.name if c.isalnum() or c in (" ", "-", "_")).strip().replace(" ", "_")
                or f"case_{case.pk}"
            )
            response = HttpResponse(
                bio.getvalue(),
                content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
            response["Content-Disposition"] = f'attachment; filename="{safe_name}_report.docx"'
            return response
        else:
            with report_template.template.open("r") as f:
                template_content = f.read()
                if isinstance(template_content, bytes):
                    template_content = template_content.decode("utf-8")

            django_engine = engines["django"]
            template = django_engine.from_string(template_content)
            rendered_html = template.render(context, request)

            return HttpResponse(rendered_html)
    except Exception:
        logger.exception("Report template rendering failed for case %s", pk)
        return HttpResponse("Error rendering template, check the server logs for details.", status=500)


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def evidence_create(request):
    """Render or save the Evidence form; ``dump`` may be posted as primary key or as dump index."""
    if request.method == "POST":
        data = request.POST.copy()
        dump_val = data.get("dump")
        if dump_val and not str(dump_val).isdigit():
            try:
                d = Dump.objects.get(index=dump_val)
                data["dump"] = str(d.pk)
            except Dump.DoesNotExist:
                pass
        form = EvidenceForm(request.user, data)
        if form.is_valid():
            try:
                with transaction.atomic():
                    _ = form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": json.dumps(
                            {
                                "showMessage": {
                                    "title": "Operation successful!",
                                    "content": "Evidence has been created",
                                    "type": "success",
                                },
                                "closeModal": True,
                                "refreshCaseDetail": True,
                            }
                        )
                    },
                )
            except IntegrityError:
                form.add_error("name", "Evidence already exists")
        return render(request, "website/partial_evidence.html", {"form": form})

    initial = {}
    if request.GET.get("dump"):
        dump_param = request.GET.get("dump")
        if dump_param and not str(dump_param).isdigit():
            try:
                d = Dump.objects.get(index=dump_param)
                initial["dump"] = d.pk
            except Dump.DoesNotExist:
                initial["dump"] = dump_param
        else:
            initial["dump"] = dump_param
    if request.GET.get("plugin"):
        initial["plugin"] = request.GET.get("plugin")
    if request.GET.get("result_row"):
        import base64

        try:
            raw_decoded = base64.b64decode(request.GET.get("result_row")).decode("utf-8")
            try:
                initial["result_row"] = json.loads(raw_decoded)
            except Exception:
                initial["result_row"] = raw_decoded
        except Exception:
            initial["result_row"] = request.GET.get("result_row")
    if request.GET.get("extracted_file"):
        initial["extracted_file"] = request.GET.get("extracted_file")
    if request.GET.get("case"):
        initial["case"] = request.GET.get("case")

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_evidence.html",
            {"form": EvidenceForm(request.user, initial=initial)},
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_evidence.html",
                {"form": EvidenceForm(request.user, initial=initial)},
                request=request,
            )
        }
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def finding_create(request, evidence_pk):
    """Render or save a Finding for an Evidence of an accessible case."""
    evidence = get_object_or_404(Evidence, pk=evidence_pk)
    if not _user_can_access_case(evidence.case, request.user):
        raise Http404("Not authorized")

    create_url = reverse("website:finding_create", args=[evidence.pk])
    if request.method == "POST":
        form = FindingForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    _ = form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Finding has been created", "type": "success"}, "closeModal": true, "refreshCaseDetail": true}'
                    },
                )
            except IntegrityError:
                form.add_error("note", "Error creating finding")
        return render(
            request,
            "website/partial_finding.html",
            {
                "form": form,
                "evidence": evidence,
                "url": create_url,
                "mitre_techniques": get_all_technique_choices(),
            },
        )

    initial = {
        "evidence": evidence.pk,
        "case": evidence.case.pk,
    }

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_finding.html",
            {
                "form": FindingForm(initial=initial),
                "evidence": evidence,
                "url": reverse("website:finding_create", args=[evidence.pk]),
                "mitre_techniques": get_all_technique_choices(),
            },
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_finding.html",
                {
                    "form": FindingForm(initial=initial),
                    "evidence": evidence,
                    "url": reverse("website:finding_create", args=[evidence.pk]),
                    "mitre_techniques": get_all_technique_choices(),
                },
                request=request,
            )
        }
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def finding_edit(request, pk):
    """Render or save the edit form of a Finding of an accessible case."""
    finding = get_object_or_404(Finding, pk=pk)

    case = finding.case
    if not _user_can_access_case(case, request.user):
        raise Http404("Not authorized")

    if request.method == "POST":
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            try:
                with transaction.atomic():
                    form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Finding has been updated", "type": "success"}, "closeModal": true, "refreshCaseDetail": true}'
                    },
                )
            except IntegrityError:
                form.add_error("note", "Error updating finding")
        return render(
            request,
            "website/partial_finding.html",
            {
                "form": form,
                "evidence": finding.evidence,
                "url": reverse("website:finding_edit", args=[finding.pk]),
                "mitre_techniques": get_all_technique_choices(),
            },
        )

    form = FindingForm(instance=finding)

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_finding.html",
            {
                "form": form,
                "evidence": finding.evidence,
                "url": reverse("website:finding_edit", args=[finding.pk]),
                "mitre_techniques": get_all_technique_choices(),
            },
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_finding.html",
                {
                    "form": form,
                    "evidence": finding.evidence,
                    "url": reverse("website:finding_edit", args=[finding.pk]),
                    "mitre_techniques": get_all_technique_choices(),
                },
                request=request,
            )
        }
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def finding_delete(request, pk):
    """Delete a Finding of an accessible case."""
    finding = get_object_or_404(Finding, pk=pk)

    case = finding.case
    if not _user_can_access_case(case, request.user):
        raise Http404("Not authorized")

    finding.delete()
    return HttpResponse(
        "",
        headers={
            "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Finding has been deleted", "type": "success"}, "refreshCaseDetail": true}'
        },
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def evidence_delete(request, pk):
    """Delete an Evidence of an accessible case."""
    evidence = get_object_or_404(Evidence, pk=pk)

    case = evidence.case
    if case and not _user_can_access_case(case, request.user):
        raise Http404("Not authorized")

    evidence.delete()
    return HttpResponse(
        "",
        headers={
            "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Evidence has been deleted", "type": "success"}, "refreshCaseDetail": true}'
        },
    )


@login_required
def global_search(request):
    """Global vector search across Cases, Dumps, and Plugin Results."""
    q = request.GET.get("q", "").strip()
    scope = request.GET.get("scope", "all")
    if scope not in ("all", "cases", "dumps", "results"):
        scope = "all"
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.GET.get("ajax") == "1"

    limit = 10 if is_ajax else 50
    results = execute_vector_search(request.user, q, scope=scope, limit=limit)

    if is_ajax:
        return JsonResponse(results)

    context = {
        "query": q,
        "scope": scope,
        "results": results,
        "user_cases": Case.objects.visible_to(request.user),
        "user_folders": Folder.objects.filter(user=request.user),
    }
    return render(request, "website/global_search.html", context)


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def add_to_case_from_search(request):
    """Add selected search results (Value rows or Dumps) to a new or existing Case as Evidence."""
    case_mode = request.POST.get("case_mode", "existing")
    notes = request.POST.get("notes", "").strip()

    if case_mode == "new":
        case_name = request.POST.get("case_name", "").strip()
        if not case_name:
            return JsonResponse({"error": "Case name is required."}, status=400)

        case_description = request.POST.get("case_description", "").strip()
        folder_name = request.POST.get("folder_name", "").strip()
        is_ctf = request.POST.get("is_ctf") in ("true", "1", "on")

        folder = None
        if folder_name:
            folder, _ = Folder.objects.get_or_create(name=folder_name, user=request.user)

        case, _ = Case.objects.get_or_create(
            name=case_name,
            user=request.user,
            defaults={
                "description": case_description,
                "folder": folder,
                "is_ctf": is_ctf,
            },
        )
    elif case_id := request.POST.get("case_id"):
        case = get_object_or_404(
            Case.objects.visible_to(request.user),
            pk=case_id,
        )

    else:
        return JsonResponse({"error": "Please select an existing case."}, status=400)
    # Values
    value_ids = request.POST.getlist("selected_values[]") or request.POST.getlist("selected_values")
    if not value_ids and request.POST.get("selected_values_str"):
        value_ids = [v.strip() for v in request.POST.get("selected_values_str").split(",") if v.strip()]
    # Primary keys only: a stray non-numeric id must not turn into a 500
    value_ids = [v for v in value_ids if str(v).isdigit()]

    allowed_dumps = get_objects_for_user(request.user, "website.can_see")
    created_evidences = []

    if value_ids:
        values = Value.objects.filter(
            pk__in=value_ids,
            result__dump__in=allowed_dumps,
        ).select_related("result__dump", "result__plugin")

        for val in values:
            dump = val.result.dump
            plugin_name = val.result.plugin.name
            val_data = val.value or {}

            title_identifier = ""
            for id_key in (
                "ImageFileName",
                "Name",
                "PID",
                "Process",
                "Path",
                "Offset",
            ):
                if id_key in val_data:
                    title_identifier = f" {id_key}:{val_data[id_key]}"
                    break
            evidence_name = f"[{plugin_name}]{title_identifier}"[:250]

            evidence = Evidence.objects.create(
                case=case,
                dump=dump,
                plugin=plugin_name,
                result_row=val_data,
                name=evidence_name,
                description=notes or f"Imported from Vector Global Search for dump '{dump.name}'",
            )
            created_evidences.append(evidence.pk)

    # Dumps
    dump_ids = request.POST.getlist("selected_dumps[]") or request.POST.getlist("selected_dumps")
    if not dump_ids and request.POST.get("selected_dumps_str"):
        dump_ids = [d.strip() for d in request.POST.get("selected_dumps_str").split(",") if d.strip()]
    dump_ids = [d for d in dump_ids if str(d).isdigit()]

    if dump_ids:
        dumps = allowed_dumps.filter(pk__in=dump_ids)
        for dump in dumps:
            evidence = Evidence.objects.create(
                case=case,
                dump=dump,
                name=f"Dump: {dump.name}"[:250],
                description=notes or f"Imported dump '{dump.name}' from Vector Global Search",
            )
            created_evidences.append(evidence.pk)

    case_url = reverse("website:case_detail", kwargs={"pk": case.pk})

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.POST.get("ajax") == "1"
    if is_ajax:
        return JsonResponse(
            {
                "success": True,
                "case_id": case.pk,
                "case_name": case.name,
                "case_url": case_url,
                "evidences_count": len(created_evidences),
                "message": f"Successfully added {len(created_evidences)} evidence item(s) to case '{case.name}'.",
            }
        )

    messages.success(
        request,
        f"Successfully added {len(created_evidences)} evidence item(s) to case '{case.name}'.",
    )
    return redirect(case_url)


@login_required
@require_http_methods(["GET", "POST"])
def value_annotations(request, value_id):
    """View and add annotations/comments on an individual plugin result row (Value)."""
    val = get_object_or_404(
        Value.objects.select_related("result__dump", "result__plugin"),
        pk=value_id,
    )
    dump = val.result.dump
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot add annotations.")
        status = request.POST.get("status", "comment")
        comment = request.POST.get("comment", "").strip()
        parent = None
        if parent_id := request.POST.get("parent_id"):
            # Replies hang off a top-level annotation of the same row (#1669)
            parent = val.annotations.filter(pk=parent_id).first()
            parent = parent.parent if parent and parent.parent_id else parent
        if comment:
            ValueAnnotation.objects.create(
                value=val,
                parent=parent,
                user=request.user,
                status=status,
                comment=comment,
            )

    annotations = (
        val.annotations.filter(parent__isnull=True)
        .select_related("user")
        .prefetch_related(
            Prefetch("replies", queryset=ValueAnnotation.objects.select_related("user").order_by("created_at"))
        )
        .order_by("created_at")
    )
    # Extract human-readable summary from JSON row
    val_json = val.value or {}
    summary_fields = []
    for key in [
        "ImageFileName",
        "Name",
        "Process",
        "COMM",
        "PID",
        "ForeignAddr",
        "Destination Addr",
        "Path",
    ]:
        if key in val_json:
            summary_fields.append(f"{key}: {val_json[key]}")
    row_summary = " | ".join(summary_fields) if summary_fields else f"Offset: {val_json.get('Offset', '-')}"

    response = render(
        request,
        "website/partial_value_annotations.html",
        {
            "value": val,
            "dump": dump,
            "plugin": val.result.plugin,
            "row_summary": row_summary,
            "annotations": annotations,
            "status_choices": ValueAnnotation.STATUS_CHOICES,
            "readonly": not is_not_readonly(request.user),
        },
    )
    if request.method == "POST" or request.GET.get("updated") == "1":
        response["HX-Trigger"] = json.dumps({"reloadPluginTable": True})
    return response


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST", "DELETE"])
def delete_value_annotation(request, pk):
    """Delete an individual annotation/comment on a plugin result row."""
    annotation = get_object_or_404(ValueAnnotation, pk=pk)
    if annotation.user != request.user and not request.user.is_superuser:
        return HttpResponseForbidden("Cannot delete another user's annotation.")
    value_id = annotation.value_id
    annotation.delete()
    return redirect(f"{reverse('website:value_annotations', kwargs={'value_id': value_id})}?updated=1")


@login_required
@require_http_methods(["GET", "POST"])
def promote_to_finding(request):
    """Promote a DumpSecret or TriageFinding to an investigative Case Finding."""
    if request.method == "POST" and not is_not_readonly(request.user):
        return HttpResponseForbidden("Read-only users cannot promote findings.")

    if request.method == "GET":
        item_type = request.GET.get("type", "").strip()
        item_id = request.GET.get("id", "").strip()

        if item_type == "secret":
            secret = get_object_or_404(DumpSecret, pk=item_id)
            if secret.dump not in get_objects_for_user(request.user, "website.can_see"):
                return HttpResponseForbidden("Unauthorized to access this dump.")
            title = f"Exposed {secret.get_category_display()}: {secret.rule_name}"
            severity = "High"
            mitre_technique = "T1552 - Unsecured Credentials"
            tags = "credential,secret,memory"
            note = (
                f"Secret detected in memory dump '{secret.dump.name}'\n"
                f"Rule: {secret.rule_name}\n"
                f"Category: {secret.get_category_display()}\n"
                f"Process: {secret.process_name or 'N/A'} (PID: {secret.pid or 'N/A'})\n"
                f"Offset: {secret.offset or 'N/A'}\n"
                f"Masked Snippet: {secret.masked_data}"
            )
        elif item_type == "triage":
            tf = get_object_or_404(TriageFinding, pk=item_id)
            if tf.dump not in get_objects_for_user(request.user, "website.can_see"):
                return HttpResponseForbidden("Unauthorized to access this dump.")
            title = f"[{tf.severity}] {tf.rule_name}"
            severity = tf.severity if tf.severity in ["Low", "Medium", "High", "Critical"] else "Medium"
            mitre_technique = tf.mitre_technique or ""
            tags = "triage,behavioral,detection"
            note = (
                f"Detection Rule: {tf.rule_name} ({tf.rule_id})\n"
                f"Category: {tf.category}\n"
                f"Severity: {tf.severity} (Score Weight: +{tf.score})\n"
                f"Entity: {tf.entity or 'N/A'}\n"
                f"Description: {tf.description}\n"
                f"Evidence: {tf.evidence_snippet or 'N/A'}"
            )
        else:
            return HttpResponseForbidden("Invalid promotion item type.")

        cases = Case.objects.visible_to(request.user)

        return render(
            request,
            "website/partial_promote_to_finding.html",
            {
                "cases": cases,
                "title": title,
                "severity": severity,
                "mitre_technique": mitre_technique,
                "tags": tags,
                "note": note,
                "item_type": item_type,
                "item_id": item_id,
            },
        )

    # POST
    item_type = request.POST.get("item_type", "").strip()
    item_id = request.POST.get("item_id", "").strip()
    case_id = request.POST.get("case_id", "").strip()
    new_case_name = request.POST.get("new_case_name", "").strip()
    severity = request.POST.get("severity", "Medium")
    mitre_technique = request.POST.get("mitre_technique", "").strip()
    tags_str = request.POST.get("tags", "").strip()
    tags = [t.strip() for t in tags_str.split(",") if t.strip()]
    note = request.POST.get("note", "").strip()

    if new_case_name:
        case, _ = Case.objects.get_or_create(
            name=new_case_name,
            user=request.user,
        )
    elif case_id:
        case = get_object_or_404(
            Case.objects.visible_to(request.user),
            pk=case_id,
        )
    else:
        cases = Case.objects.visible_to(request.user)
        return render(
            request,
            "website/partial_promote_to_finding.html",
            {
                "error": "Please select an existing case or enter a new case name.",
                "cases": cases,
                "title": f"Item #{item_id}",
                "severity": severity,
                "mitre_technique": mitre_technique,
                "tags": tags_str,
                "note": note,
                "item_type": item_type,
                "item_id": item_id,
            },
        )

    evidence = None
    if item_type == "secret":
        secret = get_object_or_404(DumpSecret, pk=item_id)
        if secret.dump not in get_objects_for_user(request.user, "website.can_see"):
            return HttpResponseForbidden("Unauthorized to access this dump.")
        evidence = Evidence.objects.create(
            case=case,
            dump=secret.dump,
            plugin="secrets_scanner",
            name=f"Secret: {secret.rule_name}"[:250],
            description=secret.masked_data,
        )
    elif item_type == "triage":
        tf = get_object_or_404(TriageFinding, pk=item_id)
        if tf.dump not in get_objects_for_user(request.user, "website.can_see"):
            return HttpResponseForbidden("Unauthorized to access this dump.")
        evidence = Evidence.objects.create(
            case=case,
            dump=tf.dump,
            plugin=tf.category,
            result_row=tf.raw_data,
            name=f"Triage: {tf.rule_name}"[:250],
            description=tf.description,
        )

    Finding.objects.create(
        case=case,
        evidence=evidence,
        severity=severity,
        mitre_attack_technique=mitre_technique,
        note=note,
        tags=tags,
    )

    return render(
        request,
        "website/partial_promote_to_finding.html",
        {
            "success": True,
            "case": case,
        },
    )
