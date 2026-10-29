from django.shortcuts import get_object_or_404
from ninja import Router, Status

from orochi.api.models import ErrorsOut, FolderFullSchema, FolderSchema, SuccessResponse
from orochi.api.permissions import ninja_test_required
from orochi.api.security import dual_auth
from orochi.website.models import Folder

router = Router()


@router.get("/", auth=dual_auth, response=list[FolderFullSchema])
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
    response={200: FolderFullSchema, 201: FolderFullSchema, 400: ErrorsOut},
    auth=dual_auth,
    url_name="folder_create",
)
@ninja_test_required("is_not_readonly")
def create_folder(request, folder_in: FolderSchema):
    """
    Summary:
    Create a new folder or return existing folder with the provided name for current user.

    Args:
    - request: The request object.
    - folder_in: FolderSchema object containing the details of the folder to be created.

    Returns:
    - If created, returns HTTP 201 with FolderFullSchema. If existing, returns HTTP 200 with FolderFullSchema.
    """
    name = folder_in.name.strip() if folder_in.name else ""
    if not name:
        return Status(400, {"errors": "Folder name cannot be empty"})
    try:
        folder, created = Folder.objects.get_or_create(name=name, user=request.user)
        return Status(201 if created else 200, folder)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete("/{str:name}", auth=dual_auth, response={200: SuccessResponse, 400: ErrorsOut})
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
        return Status(200, {"message": f"Folder {name} deleted"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})
