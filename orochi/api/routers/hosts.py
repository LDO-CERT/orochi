from typing import List

from ninja import Router, Status
from ninja.security import django_auth

from orochi.api.models import ErrorsOut, HostFullSchema, HostSchema, SuccessResponse
from orochi.api.permissions import ninja_test_required
from orochi.website.models import Host

router = Router()


@router.get("/", auth=django_auth, response=List[HostFullSchema])
def list_hosts(request):
    """
    Summary:
    Retrieve a list of all hosts in the system.

    Returns:
    - List of HostFullSchema objects representing the hosts available in the system.
    """
    return Host.objects.all().order_by("name")


@router.post(
    "/",
    response={201: HostFullSchema, 200: HostFullSchema, 400: ErrorsOut},
    auth=django_auth,
    url_name="host_create",
)
@ninja_test_required("is_not_readonly")
def create_host(request, host_in: HostSchema):
    """
    Summary:
    Create a new host or return existing host with the provided name.

    Args:
    - request: The request object.
    - host_in: HostSchema object containing the name of the host.

    Returns:
    - If created, returns HTTP 201 with HostFullSchema. If existing, returns HTTP 200 with HostFullSchema.
    """
    name = host_in.name.strip() if host_in.name else ""
    if not name:
        return Status(400, {"errors": "Host name cannot be empty"})
    try:
        host, created = Host.objects.get_or_create(name=name)
        return Status(201 if created else 200, host)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete(
    "/{str:name}", auth=django_auth, response={200: SuccessResponse, 400: ErrorsOut, 404: ErrorsOut}
)
@ninja_test_required("is_not_readonly")
def delete_host(request, name: str):
    """
    Summary:
    Delete a host by name with error handling.

    Args:
    - request: The request object.
    - name: The name of the host to delete.

    Returns:
    - HTTP 200 on success, HTTP 404 if not found, HTTP 400 on error.
    """
    name = name.strip()
    host = Host.objects.filter(name=name).first()
    if not host:
        return Status(404, {"errors": f"Host '{name}' not found"})
    try:
        host.delete()
        return Status(200, {"message": f"Host '{name}' deleted"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})
