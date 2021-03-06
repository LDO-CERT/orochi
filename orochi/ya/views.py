import os
import yara
import shutil
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.core import management
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.db.models import Q
from orochi.ya.forms import RuleForm
from orochi.ya.models import Rule, Ruleset
from orochi.website.models import CustomRule


LOCAL_YARA_PATH = "/yara"


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
    start = int(request.GET.get("start"))
    length = int(request.GET.get("length"))
    search = request.GET.get("search[value]")

    sort_column = int(request.GET.get("order[0][column]"))
    sort_order = request.GET.get("order[0][dir]")

    sort = ["pk", "ruleset__name", "ruleset__description", "path"][sort_column]
    if sort_order == "desc":
        sort = "-{}".format(sort)

    rules = (
        Rule.objects.prefetch_related("ruleset")
        .filter(Q(ruleset__user__isnull=True) | Q(ruleset__user=request.user))
        .filter(ruleset__enabled=True)
        .filter(enabled=True)
    )

    filtered_rules = rules.filter(
        Q(ruleset__name__icontains=search)
        | Q(path__icontains=search)
        | Q(ruleset__description__icontains=search)
    )

    data = filtered_rules.order_by(sort)[start : start + length]

    return_data = {
        "recordsTotal": rules.count(),
        "recordsFiltered": filtered_rules.count(),
        "data": [[x.pk, x.ruleset.name, x.ruleset.description, x.path] for x in data],
    }
    return JsonResponse(return_data)


@login_required
def build(request):
    """
    Creates fat yara from selected rules
    """
    rules_id = request.GET.getlist("rules[]")
    rulename = request.GET.get("rulename")

    rules = Rule.objects.filter(pk__in=rules_id)

    rules_file = {
        "{}_{}".format(rule.ruleset.name, rule.pk): rule.path for rule in rules
    }

    rules = yara.compile(filepaths=rules_file)

    # Manage duplicated file path
    folder = "/yara/customs/{}".format(request.user.username)
    os.makedirs(folder, exist_ok=True)
    new_path = "{}/{}.yara".format(folder, rulename)
    filename, extension = os.path.splitext(new_path)
    counter = 1
    while os.path.exists(new_path):
        new_path = "{}{}{}".format(filename, counter, extension)
        counter += 1

    rules.save(new_path)
    CustomRule.objects.create(
        user=request.user,
        path=new_path,
        name=rulename,
    )

    return JsonResponse({"ok": True})


@login_required
def delete(request):
    """
    Delete selected rules if in your ruleset
    """
    rules_id = request.GET.getlist("rules[]")
    rules = Rule.objects.filter(pk__in=rules_id, ruleset__user=request.user)
    rules.delete()
    return JsonResponse({"ok": True})


@login_required
def upload(request):
    """
    Manage yara rule upload to user ruleset
    """
    data = dict()
    if request.method == "POST":
        form = RuleForm(data=request.POST)
        ruleset = get_object_or_404(Ruleset, user=request.user)
        if form.is_valid():
            file_list = [
                (rule.file.path, rule.name) for rule in form.cleaned_data["rules"]
            ]
            for path, name in file_list:
                user_path = "{}/{}-Ruleset".format(
                    LOCAL_YARA_PATH, request.user.username
                )
                os.makedirs(user_path, exist_ok=True)
                new_path = "{}/{}".format(user_path, name)
                filename, extension = os.path.splitext(new_path)
                counter = 1
                while os.path.exists(new_path):
                    new_path = "{}{}{}".format(filename, counter, extension)
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
        "ya/partial_upload_rules.html",
        context,
        request=request,
    )
    return JsonResponse(data)