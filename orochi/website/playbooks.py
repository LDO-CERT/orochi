import logging
from typing import Any

from orochi.website.models import Dump, Plugin

logger = logging.getLogger(__name__)

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "win_malware_quick": {
        "id": "win_malware_quick",
        "name": "Windows Quick Malware Triage",
        "description": "Rapid triage of Windows memory dumps: scans processes, active network connections, and injected code / memory hooks.",
        "operating_system": "Windows",
        "plugins": [
            "windows.pslist.PsList",
            "windows.netscan.NetScan",
            "windows.malfind.Malfind",
        ],
        "icon": "fa-bolt",
        "color": "amber",
        "tags": ["quick", "processes", "network", "malware"],
    },
    "win_ransomware_hunt": {
        "id": "win_ransomware_hunt",
        "name": "Windows Ransomware Hunt",
        "description": "Searches for ransomware activity: process enumeration, suspicious open handles, mass file manipulation, and mutex synchronization primitives.",
        "operating_system": "Windows",
        "plugins": [
            "windows.pslist.PsList",
            "windows.handles.Handles",
            "windows.filescan.FileScan",
            "windows.mutant.MutantScan",
        ],
        "icon": "fa-skull-crossbones",
        "color": "rose",
        "tags": ["ransomware", "filesystem", "mutex", "handles"],
    },
    "win_stealth_rootkit": {
        "id": "win_stealth_rootkit",
        "name": "Windows Stealth Rootkit Hunt",
        "description": "Deep kernel and hook analysis: unlinked process scanning, DLL injection/unlinking, SSDT hooks, and kernel driver modules.",
        "operating_system": "Windows",
        "plugins": [
            "windows.psscan.PsScan",
            "windows.ldrmodules.LdrModules",
            "windows.ssdt.SSDT",
            "windows.driverscan.DriverScan",
        ],
        "icon": "fa-mask",
        "color": "purple",
        "tags": ["rootkit", "kernel", "hooks", "stealth"],
    },
    "linux_quick_triage": {
        "id": "linux_quick_triage",
        "name": "Linux Quick Triage",
        "description": "Baseline Linux incident triage: running processes, network sockets, and loaded kernel modules.",
        "operating_system": "Linux",
        "plugins": [
            "linux.pslist.PsList",
            "linux.sockstat.Sockstat",
            "linux.lsmod.Lsmod",
        ],
        "icon": "fa-bolt",
        "color": "emerald",
        "tags": ["linux", "quick", "baseline"],
    },
    "linux_rootkit_hunt": {
        "id": "linux_rootkit_hunt",
        "name": "Linux Rootkit & Persistence Hunt",
        "description": "Deep Linux rootkit hunting: hooked system calls, hidden kernel modules, memory code injection, and bash command history.",
        "operating_system": "Linux",
        "plugins": [
            "linux.check_syscall.Check_syscall",
            "linux.check_modules.Check_modules",
            "linux.malfind.Malfind",
            "linux.bash.Bash",
        ],
        "icon": "fa-shield-halved",
        "color": "red",
        "tags": ["linux", "rootkit", "syscalls", "hidden"],
    },
    "mac_quick_triage": {
        "id": "mac_quick_triage",
        "name": "macOS Quick Triage",
        "description": "Rapid triage of macOS memory images: processes, network sockets, and memory code injection.",
        "operating_system": "Mac",
        "plugins": [
            "mac.pslist.PsList",
            "mac.netstat.Netstat",
            "mac.malfind.Malfind",
        ],
        "icon": "fa-apple-whole",
        "color": "blue",
        "tags": ["mac", "quick", "baseline"],
    },
}


def get_available_playbooks(
    os_type: str | None = None,
    user=None,
) -> list[dict[str, Any]]:
    """
    Return all playbooks (built-in and user-created custom playbooks),
    optionally filtered by target operating system and authorized user.
    """
    from django.db.models import Q

    from orochi.website.models import Playbook

    playbooks = []
    # 1. Built-in playbooks
    for pb in PLAYBOOKS.values():
        pb_copy = dict(pb)
        pb_copy["is_custom"] = False
        pb_copy["can_delete"] = False
        pb_copy["author"] = "System Built-in"
        playbooks.append(pb_copy)

    # 2. Custom playbooks from database
    qs = Playbook.objects.prefetch_related("plugins", "user").all()
    if user and not user.is_superuser:
        qs = qs.filter(Q(user__isnull=True) | Q(user=user))

    for db_pb in qs:
        playbooks.append(
            {
                "id": db_pb.playbook_id,
                "name": db_pb.name,
                "description": db_pb.description or "",
                "operating_system": db_pb.operating_system,
                "plugins": db_pb.plugin_names,
                "icon": db_pb.icon or "fa-bolt",
                "color": db_pb.color or "indigo",
                "tags": db_pb.tags or [],
                "is_custom": True,
                "can_delete": bool(user and (user.is_superuser or db_pb.user == user)),
                "author": db_pb.user.username if db_pb.user else "System",
            }
        )

    if os_type:
        os_lower = os_type.lower()
        playbooks = [p for p in playbooks if p["operating_system"].lower() == os_lower]

    return playbooks


def get_playbook(playbook_id: str) -> dict[str, Any] | None:
    """Return a single playbook definition by ID (built-in or database custom)."""
    if playbook_id in PLAYBOOKS:
        pb_copy = dict(PLAYBOOKS[playbook_id])
        pb_copy["is_custom"] = False
        pb_copy["can_delete"] = False
        pb_copy["author"] = "System Built-in"
        return pb_copy

    from orochi.website.models import Playbook

    db_pb = Playbook.objects.filter(playbook_id=playbook_id).prefetch_related("plugins", "user").first()
    if db_pb:
        return {
            "id": db_pb.playbook_id,
            "name": db_pb.name,
            "description": db_pb.description or "",
            "operating_system": db_pb.operating_system,
            "plugins": db_pb.plugin_names,
            "icon": db_pb.icon or "fa-bolt",
            "color": db_pb.color or "indigo",
            "tags": db_pb.tags or [],
            "is_custom": True,
            "can_delete": True,
            "author": db_pb.user.username if db_pb.user else "System",
        }

    return None


def create_custom_playbook(
    name: str,
    operating_system: str,
    plugin_names: list[str],
    user=None,
    description: str = "",
    icon: str = "fa-bolt",
    color: str = "indigo",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """
    Create and persist a custom user playbook with selected Volatility plugins.
    """
    from django.utils.text import slugify

    from orochi.website.models import Playbook, Plugin

    if not name or not name.strip():
        raise ValueError("Playbook name cannot be empty.")
    if not plugin_names:
        raise ValueError("At least one plugin must be selected for the playbook.")

    os_map = {"windows": "Windows", "linux": "Linux", "mac": "Mac"}
    normalized_os = os_map.get(operating_system.lower(), operating_system)

    matched_plugins = []
    for p_name in plugin_names:
        p_str = str(p_name).strip()
        plugin = None
        if p_str.isdigit():
            plugin = Plugin.objects.filter(operating_system=normalized_os, pk=int(p_str)).first()
        if not plugin:
            plugin = Plugin.objects.filter(operating_system=normalized_os, name=p_str).first()
        if not plugin:
            short = p_str.split(".")[-1].lower()
            plugin = (
                Plugin.objects.filter(
                    operating_system=normalized_os,
                    name__iendswith=f".{short}",
                ).first()
                or Plugin.objects.filter(
                    operating_system=normalized_os,
                    name__icontains=short,
                ).first()
            )
        if plugin and plugin not in matched_plugins:
            matched_plugins.append(plugin)

    if not matched_plugins:
        raise ValueError(f"None of the selected plugins match operating system '{normalized_os}'.")

    base_slug = slugify(name).replace("-", "_")[:50] or "custom_playbook"
    playbook_id = f"custom_{base_slug}"
    counter = 1
    while playbook_id in PLAYBOOKS or Playbook.objects.filter(playbook_id=playbook_id).exists():
        playbook_id = f"custom_{base_slug}_{counter}"
        counter += 1

    db_pb = Playbook.objects.create(
        playbook_id=playbook_id,
        name=name.strip(),
        description=description.strip() if description else "",
        operating_system=normalized_os,
        user=user,
        icon=icon or "fa-bolt",
        color=color or "indigo",
        tags=tags or [],
    )
    db_pb.plugins.set(matched_plugins)

    return get_playbook(db_pb.playbook_id)


def delete_custom_playbook(playbook_id: str, user=None) -> bool:
    """
    Delete a user-created custom playbook from database.
    """
    if playbook_id in PLAYBOOKS:
        raise ValueError("Built-in system playbooks cannot be deleted.")

    from orochi.website.models import Playbook

    qs = Playbook.objects.filter(playbook_id=playbook_id)
    if user and not user.is_superuser:
        qs = qs.filter(user=user)

    db_pb = qs.first()
    if not db_pb:
        raise ValueError(f"Custom playbook '{playbook_id}' not found or unauthorized.")

    db_pb.delete()
    return True


def update_custom_playbook(
    playbook_id: str,
    name: str | None = None,
    plugin_names: list[str] | None = None,
    operating_system: str | None = None,
    description: str | None = None,
    icon: str | None = None,
    color: str | None = None,
    tags: list[str] | None = None,
    user=None,
) -> dict[str, Any]:
    """
    Update an existing user-created custom playbook in the database.
    """
    if playbook_id in PLAYBOOKS:
        raise ValueError("Built-in system playbooks cannot be modified.")

    from orochi.website.models import Playbook, Plugin

    qs = Playbook.objects.filter(playbook_id=playbook_id)
    if user and not user.is_superuser:
        qs = qs.filter(user=user)

    db_pb = qs.first()
    if not db_pb:
        raise ValueError(f"Custom playbook '{playbook_id}' not found or unauthorized.")

    if operating_system:
        os_map = {"windows": "Windows", "linux": "Linux", "mac": "Mac"}
        db_pb.operating_system = os_map.get(operating_system.lower(), operating_system)

    if name is not None:
        if not name.strip():
            raise ValueError("Playbook name cannot be empty.")
        db_pb.name = name.strip()

    if description is not None:
        db_pb.description = description.strip()

    if icon is not None:
        db_pb.icon = icon.strip() or "fa-bolt"

    if color is not None:
        db_pb.color = color.strip() or "indigo"

    if tags is not None:
        db_pb.tags = tags

    if plugin_names is not None:
        if not plugin_names:
            raise ValueError("At least one plugin must be selected for the playbook.")
        matched_plugins = []
        for p_name in plugin_names:
            p_str = str(p_name).strip()
            plugin = None
            if p_str.isdigit():
                plugin = Plugin.objects.filter(operating_system=db_pb.operating_system, pk=int(p_str)).first()
            if not plugin:
                plugin = Plugin.objects.filter(operating_system=db_pb.operating_system, name=p_str).first()
            if not plugin:
                short = p_str.split(".")[-1].lower()
                plugin = (
                    Plugin.objects.filter(
                        operating_system=db_pb.operating_system,
                        name__iendswith=f".{short}",
                    ).first()
                    or Plugin.objects.filter(
                        operating_system=db_pb.operating_system,
                        name__icontains=short,
                    ).first()
                )
            if plugin and plugin not in matched_plugins:
                matched_plugins.append(plugin)

        if not matched_plugins:
            raise ValueError(f"None of the selected plugins match operating system '{db_pb.operating_system}'.")
        db_pb.plugins.set(matched_plugins)

    db_pb.save()
    return get_playbook(db_pb.playbook_id)


def resolve_playbook_plugins(dump: Dump, playbook: dict[str, Any]) -> list[Plugin]:
    """
    Resolve matching Plugin models configured for the dump's OS from the playbook's plugin list.
    """
    resolved = []
    for item in playbook.get("plugins", []):
        plugin = Plugin.objects.filter(
            operating_system=dump.operating_system,
            name=item,
        ).first()

        if not plugin:
            # Try suffix or short name
            short_name = item.split(".")[-1].lower()
            plugin = (
                Plugin.objects.filter(
                    operating_system=dump.operating_system,
                    name__iendswith=f".{short_name}",
                ).first()
                or Plugin.objects.filter(
                    operating_system=dump.operating_system,
                    name__icontains=short_name,
                ).first()
            )

        if plugin and plugin not in resolved:
            resolved.append(plugin)

    return resolved
