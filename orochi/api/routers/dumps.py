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
    """
    Summary:
    Retrieve a list of dumps based on optional operating system filters.

    Explanation:
    Returns a list of dumps accessible to the user, filtered by the specified operating system if provided and the user's permissions.

    Args:
    - request: The request object.
    - filters: Query object containing operating system filters.

    Returns:
    - List of DumpSchema objects representing the dumps that match the criteria.
    """
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
    """
    Summary:
    Retrieve detailed information about a specific dump by its index.

    Explanation:
    Fetches the dump with the specified index and returns its information if the user has permission to view it; otherwise, returns a 403 Forbidden response.

    Args:
    - request: The request object.
    - pk: The UUID index of the dump to retrieve information for.

    Returns:
    - DumpInfoSchema object representing the detailed information of the dump.
    """
    dump = get_object_or_404(Dump, index=pk)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponse("Forbidden", status=403)
    return dump


@router.get(
    "/{idxs:pks}/plugins",
    url_name="dumps_plugins",
    response=List[ResultSmallOutSchema],
    auth=django_auth,
)
def get_dump_plugins(request, pks: List[UUID], filters: Query[DumpFilters] = None):
    """
    Summary:
    Retrieve a list of plugins associated with specified dumps.

    Explanation:
    Fetches the plugins related to the dumps identified by the provided list of UUIDs, considering user permissions, and optionally filters the results based on DumpFilters.

    Args:
    - request: The request object.
    - pks: List of UUIDs representing the indexes of the dumps to retrieve plugins for.
    - filters: Optional Query object containing dump filters.

    Returns:
    - List of ResultSmallOutSchema objects representing the plugins associated with the specified dumps.
    """
    dumps_ok = get_objects_for_user(request.user, "website.can_see")
    dumps = [
        dump.index for dump in Dump.objects.filter(index__in=pks) if dump in dumps_ok
    ]
    res = (
        Result.objects.select_related("dump", "plugin")
        .filter(dump__index__in=dumps)
        .order_by("plugin__name")
        .distinct()
        .values("plugin__name", "plugin__comment")
    )
    if filters and filters.result:
        res = res.filter(result=filters.result)
    return res
