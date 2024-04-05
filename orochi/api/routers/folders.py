from typing import List

import django
import psycopg2
from django.shortcuts import get_object_or_404
from ninja import Router
from ninja.security import django_auth

from orochi.api.models import ErrorsOut, FolderFullSchema, FolderSchema, SuccessResponse
from orochi.api.permissions import ninja_test_required
from orochi.website.models import Folder

router = Router()


@router.get("/", auth=django_auth, response=List[FolderFullSchema])
def list_folders(request):
    if request.user.is_superuser:
        return Folder.objects.all()
    return Folder.objects.filter(user=request.user)


@router.post(
    "/",
    response={201: FolderFullSchema, 400: ErrorsOut},
    auth=django_auth,
    url_name="folder_create",
)
@ninja_test_required("is_not_readonly")
def create_folder(request, folder_in: FolderSchema):
    try:
        folder = Folder.objects.create(name=folder_in.name, user=request.user)
        folder.save()
        return 201, folder
    except (psycopg2.errors.UniqueViolation, django.db.utils.IntegrityError):
        return 400, {"errors": "Folder already exists"}


@router.delete("/{name}", auth=django_auth, response={200: SuccessResponse})
def delete_folder(request, name: str):
    folder = get_object_or_404(Folder, name=name, user=request.user)
    folder.delete()
    return 200, {"message": f"Folder {name} deleted"}
