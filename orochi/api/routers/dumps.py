from typing import List
from uuid import UUID

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from guardian.shortcuts import get_objects_for_user
from ninja import Query, Router
from ninja.security import django_auth

from orochi.api.filters import DumpFilters, OperatingSytemFilters
from orochi.api.models import DumpInfoSchema, DumpSchema, ResultSmallOutSchema
from orochi.website.models import Dump, Result

router = Router()


@router.get("/", auth=django_auth, response=List[DumpSchema])
def list_dumps(request, filters: Query[OperatingSytemFilters]):
    dumps = (
        Dump.objects.all()
        if request.user.is_superuser
        else get_objects_for_user(request.user, "website.can_see")
    )
    if filters and filters.operating_system:
        dumps = [x for x in dumps if x.operating_system == filters.operating_system]
    return dumps


@router.get("/{pk}", response=DumpInfoSchema, auth=django_auth)
def get_dump_info(request, pk: UUID):
    dump = get_object_or_404(Dump, index=pk)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponse("Forbidden", status=403)
    return dump


@router.get("/{idxs:pks}/plugins", response=ResultSmallOutSchema, auth=django_auth)
def get_dump_plugins(request, pks: List[UUID], filters: Query[DumpFilters] = None):
    dumps_ok = get_objects_for_user(request.user, "website.can_see")
    dumps = [
        dump.index for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok
    ]
    res = (
        Result.objects.select_related("dump", "plugin")
        .filter(dump__index__in=dumps)
        .order_by("plugin__name")
    )
    if filters and filters.result:
        res = res.filter(result=filters.result)
    return res
