from django.http import HttpRequest
from ninja import Router, Status
from ninja.security import django_auth

from orochi.api.models import (
    ErrorsOut,
    PlaybookCreateIn,
    PlaybookLaunchOut,
    PlaybookOut,
    PlaybookUpdateIn,
    SuccessResponse,
)
from orochi.website.models import Dump
from orochi.website.playbooks import (
    create_custom_playbook,
    delete_custom_playbook,
    get_available_playbooks,
    get_playbook,
    update_custom_playbook,
)
from orochi.website.tasks import run_playbook_task
from orochi.website.views import is_not_readonly

router = Router()


@router.get(
    "/",
    auth=django_auth,
    url_name="list_playbooks",
    response=list[PlaybookOut],
)
def list_playbooks(request: HttpRequest, os: str | None = None):
    """
    List available incident response auto-triage playbooks, optionally filtered by OS.
    """
    playbooks = get_available_playbooks(os_type=os, user=request.user)
    return [PlaybookOut(**p) for p in playbooks]


@router.post(
    "/",
    auth=django_auth,
    url_name="create_playbook",
    response={200: PlaybookOut, 400: ErrorsOut, 403: ErrorsOut},
)
def create_playbook_endpoint(request: HttpRequest, payload: PlaybookCreateIn):
    """
    Create a new custom IR Playbook selecting the list of plugins to execute.
    """
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot create playbooks."})

    try:
        pb = create_custom_playbook(
            name=payload.name,
            operating_system=payload.operating_system,
            plugin_names=payload.plugin_names,
            user=request.user,
            description=payload.description,
            icon=payload.icon,
            color=payload.color,
            tags=payload.tags,
        )
        return Status(200, PlaybookOut(**pb))
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete(
    "/{str:playbook_id}",
    auth=django_auth,
    url_name="delete_playbook",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
def delete_playbook_endpoint(request: HttpRequest, playbook_id: str):
    """
    Delete a user-created custom playbook.
    """
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot delete playbooks."})

    try:
        delete_custom_playbook(playbook_id, user=request.user)
        return Status(200, {"message": f"Playbook '{playbook_id}' deleted successfully."})
    except ValueError as excp:
        return Status(400, {"errors": str(excp)})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.put(
    "/{str:playbook_id}",
    auth=django_auth,
    url_name="update_playbook",
    response={200: PlaybookOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
def update_playbook_endpoint(request: HttpRequest, playbook_id: str, payload: PlaybookUpdateIn):
    """
    Update an existing user-created custom playbook.
    """
    if not is_not_readonly(request.user):
        return Status(403, {"errors": "Read-only users cannot edit playbooks."})

    try:
        pb = update_custom_playbook(
            playbook_id=playbook_id,
            name=payload.name,
            operating_system=payload.operating_system,
            plugin_names=payload.plugin_names,
            description=payload.description,
            icon=payload.icon,
            color=payload.color,
            tags=payload.tags,
            user=request.user,
        )
        return Status(200, PlaybookOut(**pb))
    except ValueError as excp:
        return Status(400, {"errors": str(excp)})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.get(
    "/{str:playbook_id}",
    auth=django_auth,
    url_name="get_playbook",
    response={200: PlaybookOut, 404: ErrorsOut},
)
def get_playbook_endpoint(request: HttpRequest, playbook_id: str):
    """
    Retrieve definition of an auto-triage playbook by ID.
    """
    pb = get_playbook(playbook_id)
    if not pb:
        return Status(404, {"errors": f"Playbook '{playbook_id}' not found."})
    return Status(200, PlaybookOut(**pb))


@router.post(
    "/{str:playbook_id}/launch/{str:dump_index}",
    auth=django_auth,
    url_name="launch_playbook",
    response={200: PlaybookLaunchOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
def launch_playbook_endpoint(request: HttpRequest, playbook_id: str, dump_index: str):
    """
    Launch execution of an incident response auto-triage playbook on a dump (Issue #1544).
    """
    try:
        dump = Dump.objects.filter(index=dump_index).first()
        if not dump:
            return Status(404, {"errors": f"Dump with index '{dump_index}' not found."})

        if not request.user.has_perm("website.can_see", dump):
            return Status(403, {"errors": "You do not have permission to run playbooks on this dump."})

        pb = get_playbook(playbook_id)
        if not pb:
            return Status(404, {"errors": f"Playbook '{playbook_id}' not found."})

        if pb["operating_system"].lower() != dump.operating_system.lower():
            return Status(
                400,
                {
                    "errors": f"Playbook '{pb['name']}' is designed for {pb['operating_system']}, but dump is {dump.operating_system}."
                },
            )

        task_res = run_playbook_task.enqueue(
            dump_pk=dump.pk,
            playbook_id=playbook_id,
            user_pk=request.user.pk,
        )

        return Status(
            200,
            PlaybookLaunchOut(
                dump_index=dump.index,
                dump_name=dump.name,
                playbook_id=playbook_id,
                playbook_name=pb["name"],
                task_id=str(task_res.id),
                message=f"Playbook '{pb['name']}' queued successfully for dump '{dump.name}'.",
            ),
        )
    except Exception as excp:
        return Status(400, {"errors": str(excp)})
