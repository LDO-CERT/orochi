from typing import List

from django.db.models import Q
from ninja import Router, Status
from ninja.security import django_auth

from orochi.api.models import CaseFullSchema, CaseSchema, ErrorsOut, SuccessResponse
from orochi.api.permissions import ninja_test_required
from orochi.website.models import Case

router = Router()


@router.get("/", auth=django_auth, response=List[CaseFullSchema])
def list_cases(request):
    """
    Summary:
    Retrieve a list of cases accessible to the user.
    """
    if request.user.is_superuser:
        return Case.objects.all().order_by("name")
    return (
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user))
        .distinct()
        .order_by("name")
    )


@router.post(
    "/",
    response={201: CaseFullSchema, 200: CaseFullSchema, 400: ErrorsOut},
    auth=django_auth,
    url_name="case_create",
)
@ninja_test_required("is_not_readonly")
def create_case(request, case_in: CaseSchema):
    """
    Summary:
    Create a new case or return existing case with the provided name for current user.
    """
    name = case_in.name.strip() if case_in.name else ""
    if not name:
        return Status(400, {"errors": "Case name cannot be empty"})
    try:
        case, created = Case.objects.get_or_create(name=name, user=request.user)
        return Status(201 if created else 200, case)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete(
    "/{int:case_id}",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def delete_case(request, case_id: int):
    """
    Summary:
    Delete a case by ID if authorized.
    """
    try:
        if request.user.is_superuser:
            case = Case.objects.filter(pk=case_id).first()
        else:
            case = Case.objects.filter(pk=case_id, user=request.user).first()
        if not case:
            return Status(404, {"errors": "Case not found"})
        case.delete()
        return Status(200, {"message": "Case deleted successfully"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})
