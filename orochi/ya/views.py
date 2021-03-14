from django.http import Http404, JsonResponse
from django.shortcuts import redirect
from django.contrib import messages
from django.core import management
from django.core import serializers

from orochi.ya.models import Rule
from django.db.models import Q


def update_rules(request):
    """
    Run management command to update rules
    """
    if request.user.is_superuser:
        management.call_command("rules_sync", verbosity=0)
        messages.add_message(request, messages.INFO, "Sync Rules done")
        return redirect("/admin")
    raise Http404("404")


def list_rules(request):
    start = int(request.GET.get("start"))
    length = int(request.GET.get("length"))
    search = request.GET.get("search[value]")

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

    data = filtered_rules.only("pk", "ruleset__name", "ruleset__description", "path")[
        start : start + length
    ]

    return_data = {
        "recordsTotal": rules.count(),
        "recordsFiltered": filtered_rules.count(),
        "data": [[x.pk, x.ruleset.name, x.ruleset.description, x.path] for x in data],
    }
    return JsonResponse(return_data)
