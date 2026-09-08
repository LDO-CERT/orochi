from typing import List

from django.contrib.auth import get_user_model
from django.db.models import Q
from ninja import Router, Status
from ninja.security import django_auth

from orochi.api.models import (
    CaseFullSchema,
    CaseSchema,
    CaseUpdateSchema,
    ErrorsOut,
    SuccessResponse,
)
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


@router.patch(
    "/{int:case_id}",
    auth=django_auth,
    response={200: CaseFullSchema, 400: ErrorsOut, 404: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def update_case(request, case_id: int, case_in: CaseUpdateSchema):
    """
    Summary:
    Update case attributes (status, collaborators, name, description, is_ctf).
    """
    try:
        if request.user.is_superuser:
            case = Case.objects.filter(pk=case_id).first()
        else:
            case = Case.objects.filter(
                Q(user=request.user) | Q(collaborators=request.user),
                pk=case_id,
            ).first()
        if not case:
            return Status(404, {"errors": "Case not found"})

        if case_in.name is not None:
            name = case_in.name.strip()
            if not name:
                return Status(400, {"errors": "Case name cannot be empty"})
            case.name = name
        if case_in.description is not None:
            case.description = case_in.description
        if case_in.status is not None:
            valid_statuses = [choice[0] for choice in Case.STATUS_CHOICES]
            if case_in.status not in valid_statuses:
                return Status(
                    400, {"errors": f"Invalid status. Must be one of {valid_statuses}"}
                )
            case.status = case_in.status
        if case_in.is_ctf is not None:
            case.is_ctf = case_in.is_ctf

        case.save()

        if case_in.collaborators is not None:
            User = get_user_model()
            users = User.objects.filter(pk__in=case_in.collaborators).exclude(
                pk=case.user.pk
            )
            case.collaborators.set(users)

        return Status(200, case)
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
