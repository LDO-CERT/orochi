from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import management
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string
from django.views.decorators.http import require_http_methods

from orochi.ya.forms import EditRuleForm, RuleForm
from orochi.ya.models import Rule


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


@require_http_methods(["GET"])
@login_required
def detail(request):
    """
    Form to edit rule
    """
    pk = request.GET.get("pk")
    rule = get_object_or_404(Rule, pk=pk)
    try:
        with open(rule.path, "rb") as f:
            rule_data = f.read()
        return JsonResponse(
            {
                "html_form": render_to_string(
                    "ya/partial_rule_edit.html",
                    {
                        "form": EditRuleForm(
                            initial={
                                "text": "".join(rule_data.decode("utf-8", "replace")),
                                "pk": rule.pk,
                            }
                        ),
                        "id": rule.pk,
                    },
                    request=request,
                )
            }
        )
    except UnicodeDecodeError as e:
        raise Http404 from e


@login_required
def upload(request):
    """
    Form to upload yara files in rule management
    """
    return JsonResponse(
        {
            "html_form": render_to_string(
                "ya/partial_rule_upload.html",
                {"form": RuleForm()},
                request=request,
            )
        }
    )
