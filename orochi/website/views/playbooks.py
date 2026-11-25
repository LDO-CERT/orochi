import json
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user

from orochi.website.models import (
    Dump,
    Plugin,
)
from orochi.website.views.common import (
    is_not_readonly,
)

logger = logging.getLogger(__name__)


@login_required
@require_http_methods(["GET", "POST"])
def list_playbooks(request):
    """
    Dedicated section to list, create, edit, and manage incident response playbooks.
    Similar to Plugins (/users/<username>/plugins) and Symbols (/list_symbols).
    """

    from orochi.website.playbooks import (
        create_custom_playbook,
        delete_custom_playbook,
        get_available_playbooks,
        update_custom_playbook,
    )

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot manage playbooks.")

        action = request.POST.get("action")
        if action == "create":
            name = request.POST.get("name", "").strip()
            operating_system = request.POST.get("operating_system", "Windows")
            selected_plugins = request.POST.getlist("plugins")
            description = request.POST.get("description", "").strip()
            icon = request.POST.get("icon", "fa-bolt").strip()
            color = request.POST.get("color", "indigo").strip()
            raw_tags = request.POST.get("tags", "")
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()]

            if not name:
                messages.error(request, "Playbook name is required.")
            elif not selected_plugins:
                messages.error(request, "At least one plugin must be selected.")
            else:
                try:
                    pb = create_custom_playbook(
                        name=name,
                        operating_system=operating_system,
                        plugin_names=selected_plugins,
                        user=request.user,
                        description=description,
                        icon=icon,
                        color=color,
                        tags=tags,
                    )
                    messages.success(request, f"Playbook '{pb['name']}' created successfully.")
                except Exception as e:
                    messages.error(request, str(e))

            return redirect("website:list_playbooks")

        elif action == "edit":
            playbook_id = request.POST.get("playbook_id")
            name = request.POST.get("name", "").strip()
            operating_system = request.POST.get("operating_system")
            selected_plugins = request.POST.getlist("plugins")
            description = request.POST.get("description", "").strip()
            icon = request.POST.get("icon", "fa-bolt").strip()
            color = request.POST.get("color", "indigo").strip()
            raw_tags = request.POST.get("tags", "")
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()]

            if not playbook_id:
                messages.error(request, "Playbook ID is required for editing.")
            elif not name:
                messages.error(request, "Playbook name cannot be empty.")
            elif not selected_plugins:
                messages.error(request, "At least one plugin must be selected.")
            else:
                try:
                    pb = update_custom_playbook(
                        playbook_id=playbook_id,
                        name=name,
                        operating_system=operating_system,
                        plugin_names=selected_plugins,
                        description=description,
                        icon=icon,
                        color=color,
                        tags=tags,
                        user=request.user,
                    )
                    messages.success(request, f"Playbook '{pb['name']}' updated successfully.")
                except Exception as e:
                    messages.error(request, str(e))

            return redirect("website:list_playbooks")

        elif action == "delete":
            playbook_id = request.POST.get("playbook_id")
            if not playbook_id:
                messages.error(request, "Playbook ID is required for deletion.")
            else:
                try:
                    delete_custom_playbook(playbook_id, user=request.user)
                    messages.success(request, "Playbook deleted successfully.")
                except Exception as e:
                    messages.error(request, str(e))

            return redirect("website:list_playbooks")

    # GET request
    all_playbooks = get_available_playbooks(user=request.user)

    # Statistics
    total_count = len(all_playbooks)
    win_count = sum(1 for p in all_playbooks if p["operating_system"].lower() == "windows")
    linux_count = sum(1 for p in all_playbooks if p["operating_system"].lower() == "linux")
    mac_count = sum(1 for p in all_playbooks if p["operating_system"].lower() == "mac")
    custom_count = sum(1 for p in all_playbooks if p.get("is_custom", False))

    # Plugins by OS for creation/editing
    plugins_qs = Plugin.objects.filter(disabled=False).order_by("name")
    plugins_by_os = {
        "Windows": [
            {"name": p.name, "comment": p.comment or ""} for p in plugins_qs.filter(operating_system="Windows")
        ],
        "Linux": [{"name": p.name, "comment": p.comment or ""} for p in plugins_qs.filter(operating_system="Linux")],
        "Mac": [{"name": p.name, "comment": p.comment or ""} for p in plugins_qs.filter(operating_system="Mac")],
    }

    return render(
        request,
        "website/list_playbooks.html",
        {
            "playbooks": all_playbooks,
            "stats": {
                "total": total_count,
                "windows": win_count,
                "linux": linux_count,
                "mac": mac_count,
                "custom": custom_count,
            },
            "plugins_by_os": plugins_by_os,
            "plugins_by_os_json": json.dumps(plugins_by_os),
            "readonly": not is_not_readonly(request.user),
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def dump_playbooks(request, index):
    """View and trigger incident response auto-triage playbooks for a memory dump (Issue #1544)."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    from orochi.website.playbooks import (
        get_available_playbooks,
        get_playbook,
        resolve_playbook_plugins,
    )
    from orochi.website.tasks import run_playbook_task

    launched_playbook = None
    launch_message = None

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot execute playbooks.")

        playbook_id = request.POST.get("playbook_id")
        pb = get_playbook(playbook_id)
        if not pb:
            return HttpResponseBadRequest(f"Unknown playbook ID '{playbook_id}'.")
        if pb["operating_system"].lower() != dump.operating_system.lower():
            return HttpResponseBadRequest(f"Playbook incompatible with {dump.operating_system}.")

        task_res = run_playbook_task.enqueue(
            dump_pk=dump.pk,
            playbook_id=playbook_id,
            user_pk=request.user.pk,
        )
        launched_playbook = pb
        launch_message = f"Playbook '{pb['name']}' successfully enqueued (Task: {task_res.id})."

    available_pbs = get_available_playbooks(dump.operating_system, user=request.user)
    playbook_cards = []
    for pb in available_pbs:
        resolved_plugins = resolve_playbook_plugins(dump, pb)
        playbook_cards.append(
            {
                "playbook": pb,
                "plugins": resolved_plugins,
                "plugin_names": [p.name for p in resolved_plugins],
                "is_ready": len(resolved_plugins) > 0,
            }
        )

    is_htmx = (
        getattr(request, "htmx", False)
        or request.headers.get("HX-Request") == "true"
        or request.GET.get("modal") == "1"
    )
    template = "website/partial_dump_playbook.html" if is_htmx else "website/dump_playbook.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "playbooks": playbook_cards,
            "launched_playbook": launched_playbook,
            "launch_message": launch_message,
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )
