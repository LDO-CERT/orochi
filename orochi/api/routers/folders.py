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
    """
    Summary:
    Retrieve a list of folders based on user permissions.

    Explanation:
    Returns all folders if the user is a superuser; otherwise, returns folders associated with the current user.

    Args:
    - request: The request object.

    Returns:
    - List of FolderFullSchema objects representing the folders accessible to the user.
    """
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
    """
    Summary:
    Create a new folder with the provided name.

    Explanation:
    Attempts to create a new folder with the specified name for the current user. Returns the created folder if successful, or an error response if the folder already exists.

    Args:
    - request: The request object.
    - folder_in: FolderSchema object containing the details of the folder to be created.

    Returns:
    - If successful, returns HTTP status code 201 and the created FolderFullSchema object. If the folder already exists, returns HTTP status code 400 and an ErrorsOut object with an error message.
    """
    try:
        folder = Folder.objects.create(name=folder_in.name, user=request.user)
        folder.save()
        return 201, folder
    except (psycopg2.errors.UniqueViolation, django.db.utils.IntegrityError):
        return 400, {"errors": "Folder already exists"}


@router.delete(
    "/{str:name}", auth=django_auth, response={200: SuccessResponse, 400: ErrorsOut}
)
def delete_folder(request, name: str):
    """
    Summary:
    Delete a folder by name with error handling.

    Explanation:
    Attempts to delete the folder with the specified name belonging to the current user. Returns a success message if the deletion is successful, or an error response with details if an exception occurs during deletion.

    Args:
    - request: The request object.
    - name: The name of the folder to delete.

    Returns:
    - If successful, returns HTTP status code 200 and a success message dictionary. If an exception occurs, returns HTTP status code 400 and an ErrorsOut object with the exception details.
    """
    folder = get_object_or_404(Folder, name=name, user=request.user)
    try:
        folder.delete()
        return 200, {"message": f"Folder {name} deleted"}
    except Exception as excp:
        return 400, {"errors": str(excp)}
