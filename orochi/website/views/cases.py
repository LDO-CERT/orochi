import json
import logging
from pathlib import Path

import requests
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import Q
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
    SERVICE_SIEM,
    SERVICE_THEHIVE,
)
from orochi.website.forms import (
    CaseForm,
    CTFQuestionForm,
    EvidenceForm,
    FindingForm,
    FolderForm,
    SandboxSubmitForm,
)
from orochi.website.integrations import cape_base_url, submit_file_to_sandbox
from orochi.website.models import (
    Case,
    CTFHint,
    CTFQuestion,
    Dump,
    DumpSecret,
    Evidence,
    Finding,
    Folder,
    ReportTemplate,
    Service,
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


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def folder_create(request):
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
    return render(request, "website/partial_case.html", {"form": form})


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def case_edit(request):
    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        pk=request.GET.get("pk"),
    )
    if request.method == "POST":
        form = CaseForm(request.user, request.POST, instance=case)
        if form.is_valid():
            try:
                form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been updated", "type": "success"}, "closeModal": true, "refreshCaseDetail": true, "refreshCases": true}'
                    },
                )
            except IntegrityError:
                form.add_error("name", "Case already exists")
        return render(request, "website/partial_case.html", {"form": form})

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_case.html",
            {
                "form": CaseForm(request.user, instance=case),
                "url": reverse("website:case_edit") + f"?pk={case.pk}",
            },
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_case.html",
                {
                    "form": CaseForm(request.user, instance=case),
                    "url": reverse("website:case_edit") + f"?pk={case.pk}",
                },
                request=request,
            )
        }
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_delete(request, pk):
    case = get_object_or_404(Case, pk=pk, user=request.user)
    case.delete()
    return HttpResponse(
        '<div class="flex items-center justify-center h-full p-10"><p class="text-zinc-500 text-lg">Case deleted.</p></div>',
        headers={
            "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been deleted", "type": "success"}, "refreshCases": true}'
        },
    )


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_change_status(request, pk):
    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
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


def _ctf_panel(request, case, message=None, level="info", form=None):
    questions = ctf.questions_for_user(case, request.user)
    context = {
        "case": case,
        "questions": questions,
        "leaderboard": ctf.leaderboard(case),
        "can_manage": ctf.can_manage(case, request.user),
        "total_points": sum(q["points"] for q in questions),
        "my_points": sum(q["awarded_points"] or 0 for q in questions),
        "solved_count": sum(1 for q in questions if q["solved"]),
        "message": message,
        "message_level": level,
        "form": form or CTFQuestionForm(initial={"order": max((q["order"] for q in questions), default=0) + 1}),
    }
    return render(request, "website/partial_case_ctf.html", context)


def _get_ctf_case(request, pk):
    case = ctf.get_case_for_user(pk, request.user)
    if case is None:
        raise Http404("Case not found")
    return case


@login_required
@require_http_methods(["GET"])
def case_ctf(request, pk):
    return _ctf_panel(request, _get_ctf_case(request, pk))


@login_required
@require_http_methods(["POST"])
def case_ctf_submit(request, pk, question_id):
    case = _get_ctf_case(request, pk)
    question = get_object_or_404(CTFQuestion, case=case, pk=question_id)
    answer = request.POST.get("answer", "").strip()
    if not answer:
        return _ctf_panel(request, case, "Type an answer first.", "warning")
    try:
        result = ctf.submit_answer(question, request.user, answer)
    except ctf.TooManyAttempts as exc:
        return _ctf_panel(request, case, str(exc), "error")
    if result.already_solved:
        return _ctf_panel(request, case, f"Q{question.order} was already solved.", "info")
    if result.is_correct:
        return _ctf_panel(request, case, f"Correct! +{result.awarded_points} points.", "success")
    return _ctf_panel(request, case, f"Wrong answer for Q{question.order}.", "error")


@login_required
@require_http_methods(["POST"])
def case_ctf_unlock(request, pk, hint_id):
    case = _get_ctf_case(request, pk)
    hint = get_object_or_404(CTFHint, question__case=case, pk=hint_id)
    ctf.unlock_hint(hint, request.user)
    return _ctf_panel(request, case, f"Hint unlocked: -{hint.cost} points if you solve the question now.", "info")


@login_required
@role_required(is_not_readonly)
@require_http_methods(["POST"])
def case_ctf_question_create(request, pk):
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
    case = _get_ctf_case(request, pk)
    if not ctf.can_manage(case, request.user):
        raise PermissionDenied
    question = get_object_or_404(CTFQuestion, case=case, pk=question_id)
    question.delete()
    return _ctf_panel(request, case, f"Question Q{question.order} deleted.", "success")


@login_required
def case_detail(request, pk):
    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        pk=pk,
    )
    visible_dumps = get_objects_for_user(request.user, "website.can_see")
    evidence_dump_ids = case.evidences.exclude(dump__isnull=True).values_list("dump_id", flat=True)
    if case.folder:
        related_dumps = visible_dumps.filter(Q(folder=case.folder) | Q(pk__in=evidence_dump_ids)).distinct()
    else:
        related_dumps = visible_dumps.filter(pk__in=evidence_dump_ids).distinct()
    templates = ReportTemplate.objects.all()
    context = {
        "case": case,
        "evidences": case.evidences.all(),
        "findings": case.findings.all(),
        "timeline_events": case.timeline_events.all(),
        "related_dumps": related_dumps,
        "report_templates": templates,
        "attack_coverage": get_case_attack_coverage(case.findings.all()),
        "configured_integrations": set(
            Service.objects.filter(name__in=[SERVICE_SIEM, SERVICE_THEHIVE, SERVICE_CAPE]).values_list(
                "name", flat=True
            )
        ),
        "SERVICE_CAPE": SERVICE_CAPE,
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
        "cases": Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user))
        .prefetch_related("evidences", "collaborators")
        .distinct(),
        "readonly": not is_not_readonly(request.user),
    }
    return TemplateResponse(request, "website/index.html", context)


@login_required
@role_required(is_not_readonly)
def case_export(request, pk):
    import io
    import json
    import tarfile
    from pathlib import Path

    from django.http import FileResponse

    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        pk=pk,
    )

    # Collect all data
    data = {
        "case": {
            "name": case.name,
            "description": case.description,
            "status": case.status,
            "created_at": case.created_at,
        },
        "evidences": list(case.evidences.values("name", "description", "created_at", "plugin", "result_row")),
        "findings": list(case.findings.values("severity", "tags", "note", "mitre_attack_technique", "created_at")),
        "timeline": list(case.timeline_events.values("timestamp", "event_type", "description")),
    }

    json_data = json.dumps(data, cls=DjangoJSONEncoder, indent=4)

    # Create tar.gz in memory
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        # Add json data
        json_file = io.BytesIO(json_data.encode("utf-8"))
        info = tarfile.TarInfo(name=f"case_{case.pk}_export.json")
        info.size = len(json_file.getvalue())
        tar.addfile(tarinfo=info, fileobj=json_file)

        # We could also append actual downloaded files if they exist in evidence
        for ev in case.evidences.all():
            if ev.result_row and isinstance(ev.result_row, dict) and "down_path" in ev.result_row:
                down_path = ev.result_row["down_path"]
                if down_path and Path(down_path).exists():
                    tar.add(down_path, arcname=f"files/{Path(down_path).name}")

    tar_stream.seek(0)
    return FileResponse(tar_stream, as_attachment=True, filename=f"case_{case.pk}_bundle.tar.gz")


@login_required
def case_mitre_export(request, pk):
    case = get_object_or_404(Case, pk=pk)
    if case.user != request.user and request.user not in case.collaborators.all():
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
    import io

    import requests
    from django.http import HttpResponse
    from django.template import engines
    from docxtpl import DocxTemplate

    from orochi.website.defaults import SERVICE_OLLAMA

    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
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
    except Exception as e:
        return HttpResponse(f"Error rendering template: {str(e)}", status=500)


@login_required
@role_required(is_not_readonly)
@require_http_methods(["GET", "POST"])
def evidence_create(request):
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
    evidence = get_object_or_404(Evidence, pk=evidence_pk)

    if request.method == "POST":
        form = FindingForm(request.POST)
        if form.is_valid():
            try:
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
    finding = get_object_or_404(Finding, pk=pk)

    case = finding.case
    if case.user != request.user and request.user not in case.collaborators.all():
        raise Http404("Not authorized")

    if request.method == "POST":
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            try:
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
    finding = get_object_or_404(Finding, pk=pk)

    case = finding.case
    if case.user != request.user and request.user not in case.collaborators.all():
        raise Http404("Not authorized")

    finding.delete()
    return HttpResponse(
        "",
        headers={
            "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Finding has been deleted", "type": "success"}, "refreshCaseDetail": true}'
        },
    )


@role_required(is_not_readonly)
@require_http_methods(["POST"])
def evidence_delete(request, pk):
    evidence = get_object_or_404(Evidence, pk=pk)

    case = evidence.case
    if case and case.user != request.user and request.user not in case.collaborators.all():
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
        "user_cases": Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
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
            Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)),
            pk=case_id,
        )

    else:
        return JsonResponse({"error": "Please select an existing case."}, status=400)
    # Values
    value_ids = request.POST.getlist("selected_values[]") or request.POST.getlist("selected_values")
    if not value_ids and request.POST.get("selected_values_str"):
        value_ids = [v.strip() for v in request.POST.get("selected_values_str").split(",") if v.strip()]

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
        if comment:
            ValueAnnotation.objects.create(
                value=val,
                user=request.user,
                status=status,
                comment=comment,
            )

    annotations = val.annotations.select_related("user").all()
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

    return render(
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
    return redirect("website:value_annotations", value_id=value_id)


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

        cases = Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct()

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
            Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)),
            pk=case_id,
        )
    else:
        cases = Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct()
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
