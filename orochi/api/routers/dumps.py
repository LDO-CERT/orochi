import shutil
from pathlib import Path
from typing import List, Optional
from uuid import UUID, uuid1

from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from guardian.shortcuts import get_objects_for_user
from ninja import File, Query, Router, UploadedFile
from ninja.security import django_auth

from orochi.api.filters import DumpFilters, OperatingSytemFilters
from orochi.api.models import DumpIn, DumpInfoSchema, DumpSchema, ResultSmallOutSchema
from orochi.website.defaults import RESULT_STATUS_NOT_STARTED, RESULT_STATUS_RUNNING
from orochi.website.models import Dump, Folder, Result, UserPlugin
from orochi.website.views import index_f_and_f

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


@router.post("/", url_name="create_index", response=DumpSchema, auth=django_auth)
def create_dump(request, payload: DumpIn, upload: Optional[UploadedFile] = File(None)):
    """
    Creates a new dump index and handles the associated file uploads. This function processes the provided payload to create a dump entry in the database and manages file storage based on the input parameters.

    Args:
        request: The HTTP request object.
        payload (DumpIn): The data containing information about the dump to be created.
        upload (Optional[UploadedFile]): An optional file to be uploaded.

    Returns:
        DumpSchema: The created dump object.

    Raises:
        HttpResponse: Returns a 400 Bad Request response if an error occurs during the process.
    """

    try:
        if payload.folder:
            folder, _ = Folder.objects.get_or_create(
                name=payload.folder.name, user=request.user
            )
        else:
            folder = None
        dump_index = str(uuid1())
        Path(f"{settings.MEDIA_ROOT}/{dump_index}").mkdir()
        dump = Dump.objects.create(
            name=payload.name,
            color=payload.color,
            comment=payload.comment,
            operating_system=payload.operating_system,
            folder=folder,
            author=request.user,
            index=dump_index,
        )
        if payload.local_folder:
            start = payload.local_folder
            start = start.replace("/upload/upload", "/media/uploads")
            filename = payload.original_name or Path(start).name
            shutil.move(start, f"{settings.MEDIA_ROOT}/{dump_index}/{filename}")
            dump.upload.name = f"{settings.MEDIA_URL}{dump_index}/{filename}"
            move = False
        elif upload:
            dump.upload.save(Path(upload.name).name, upload)
            move = True
        else:
            return HttpResponse("Bad Request", status=400)
        dump.save()
        Result.objects.bulk_create(
            [
                Result(
                    plugin=up.plugin,
                    dump=dump,
                    result=(
                        RESULT_STATUS_RUNNING
                        if up.automatic
                        else RESULT_STATUS_NOT_STARTED
                    ),
                )
                for up in UserPlugin.objects.filter(
                    plugin__operating_system__in=[
                        dump.operating_system,
                        "Other",
                    ],
                    user=request.user,
                    plugin__disabled=False,
                )
            ]
        )

        transaction.on_commit(
            lambda: index_f_and_f(
                dump.pk,
                request.user.pk,
                password=payload.password,
                restart=None,
                move=move,
            )
        )
        return dump
    except Exception as excp:
        return HttpResponse(f"Bad Request ({excp})", status=400)


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
        .values("plugin__name", "plugin__comment", "plugin__id")
    )
    if filters and filters.result:
        res = res.filter(result=filters.result)
    return res
