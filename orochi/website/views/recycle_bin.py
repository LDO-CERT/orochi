"""Recycle bin modal of the workbench sidebar."""

from django.contrib.auth.decorators import login_required
from django.template.response import TemplateResponse
from guardian.shortcuts import get_objects_for_user

from orochi.website.recycle_bin import deleted_dumps, purge_at, retention_days, schedule_purge
from orochi.website.roles import ROLE_ANALYST, has_role


@login_required
def recycle_bin(request):
    """List the deleted dumps the user can see, with restore / delete permanently actions.

    Opening the bin also enqueues the purge of the expired dumps.
    """
    schedule_purge()
    dumps = list(
        get_objects_for_user(request.user, "website.can_see", klass=deleted_dumps()).select_related("deleted_by")
    )
    for dump in dumps:
        dump.purge_date = purge_at(dump)
    return TemplateResponse(
        request,
        "website/partial_recycle_bin.html",
        {
            "dumps": dumps,
            "retention_days": retention_days(),
            "can_manage": has_role(request.user, ROLE_ANALYST),
        },
    )
