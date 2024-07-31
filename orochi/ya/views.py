import os
import shutil
from pathlib import Path

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import management
from django.db.models import Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string
from django.views.decorators.http import require_http_methods
from extra_settings.models import Setting

from orochi.ya.forms import EditRuleForm, RuleForm
from orochi.ya.models import Rule, Ruleset
from orochi.ya.schema import RuleIndex


def update_rules(request):
    """
    Run management command to update rules
    """
    if request.user.is_superuser:
        management.call_command("rules_sync", verbosity=0)
        messages.add_message(request, messages.INFO, "Sync Rules done")
        return redirect("/admin")
    raise Http404("404")


def generate_default_rule(request):
    """
    Run management command to create default rule
    """
    if request.user.is_superuser:
        management.call_command("generate_default_rule", verbosity=0)
        messages.add_message(request, messages.INFO, "Default Rule created")
        return redirect("/admin")
    raise Http404("404")


@login_required
def list_rules(request):
    """
    Ajax rules return for datatables
    """
    draw = request.GET.get("draw")
    start = int(request.GET.get("start"))
    length = int(request.GET.get("length"))
    search = request.GET.get("search[value]")

    sort_column = int(request.GET.get("order[0][column]"))
    sort_order = request.GET.get("order[0][dir]")

    rules = (
        Rule.objects.prefetch_related("ruleset")
        .filter(Q(ruleset__user__isnull=True) | Q(ruleset__user=request.user))
        .filter(ruleset__enabled=True)
        .filter(enabled=True)
    )
    rules_id = [x.id for x in rules]
    total = rules.count()

    if search:
        sort = ["id", "ruleset", "path"][sort_column]
        if sort_order == "desc":
            sort = f"-{sort}"
        rule_index = RuleIndex()
        try:
            results = rule_index.search(search, sort)
            filtered_data = [x for x in results if int(x[0]) in rules_id][
                start : start + length
            ]
        except Exception as excp:
            # partial query error. Eg: "foobar AND"
            filtered_data = []
        return_data = {
            "draw": draw,
            "recordsTotal": total,
            "recordsFiltered": len(filtered_data),
            "data": filtered_data,
        }
        return JsonResponse(return_data)

    sort = ["pk", "ruleset__name", "path"][sort_column]
    if sort_order == "desc":
        sort = f"-{sort}"
    data = rules.order_by(sort)[start : start + length]
    return_data = {
        "draw": draw,
        "recordsTotal": rules.count(),
        "recordsFiltered": rules.count(),
        "data": [
            [
                x.pk,
                x.ruleset.name,
                x.ruleset.description,
                Path(x.path).name,
                "---",
            ]
            for x in data
        ],
    }
    return JsonResponse(return_data)


@require_http_methods(["GET"])
@login_required
def detail(request):
    """
    Return content of rule
    """
    pk = request.GET.get("pk")
    rule = get_object_or_404(Rule, pk=pk)
    try:
        with open(rule.path, "rb") as f:
            rule_data = f.read()
        context = {
            "form": EditRuleForm(
                initial={
                    "text": "".join(rule_data.decode("utf-8", "replace")),
                    "pk": rule.pk,
                }
            ),
            "id": rule.pk,
        }
        data = {
            "html_form": render_to_string(
                "ya/partial_rule_edit.html",
                context,
                request=request,
            )
        }
        return JsonResponse(data)
    except UnicodeDecodeError as e:
        raise Http404 from e


@login_required
def upload(request):
    """
    Manage yara rule upload to user ruleset
    """
    data = {}
    if request.method == "POST":
        form = RuleForm(data=request.POST)
        ruleset = get_object_or_404(Ruleset, user=request.user)
        if form.is_valid():
            file_list = [
                (rule.file.path, rule.name) for rule in form.cleaned_data["rules"]
            ]
            for path, name in file_list:
                user_path = (
                    f"{Setting.get('LOCAL_YARA_PATH')}/{request.user.username}-Ruleset"
                )
                os.makedirs(user_path, exist_ok=True)
                new_path = f"{user_path}/{name}"
                filename, extension = os.path.splitext(new_path)
                counter = 1
                while os.path.exists(new_path):
                    new_path = f"{filename}{counter}{extension}"
                    counter += 1

                shutil.move(
                    path,
                    new_path,
                )
                Rule.objects.create(
                    path=new_path,
                    ruleset=ruleset,
                )
            return JsonResponse({"ok": True})
        raise Http404

    form = RuleForm()
    context = {"form": form}
    data["html_form"] = render_to_string(
        "ya/partial_rule_upload.html",
        context,
        request=request,
    )
    return JsonResponse(data)
