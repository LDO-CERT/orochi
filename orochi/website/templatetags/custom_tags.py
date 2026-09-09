from datetime import datetime

from django import template
from django.forms import CheckboxInput

register = template.Library()


@register.filter(name="is_checkbox")
def is_checkbox(field):
    return field.field.widget.__class__.__name__ == CheckboxInput().__class__.__name__


@register.filter(name="in_list")
def in_list(value, the_list):
    value = str(value)
    return value in the_list.split(",")


@register.filter(name="starts_with")
def starts_with(value, value_with):
    return value.startswith(value_with)


@register.filter(name="epoch")
def epoch(value):
    return datetime.fromtimestamp(value)


@register.filter(name="has_group")
def has_group(user, group_name):
    return user.groups.filter(name=group_name).exists()


@register.filter(name="user_role")
def user_role(user):
    from orochi.website.roles import get_user_role

    return get_user_role(user)


@register.filter(name="has_role")
def has_role_filter(user, role_name):
    from orochi.website.roles import has_role

    return has_role(user, role_name)


@register.filter(name="can_run_plugin")
def can_run_plugin_filter(user, plugin):
    from orochi.website.models import Plugin
    from orochi.website.roles import can_execute_plugin

    if isinstance(plugin, str):
        plugin_obj = Plugin.objects.filter(name=plugin).first()
        if not plugin_obj:
            return False
        return can_execute_plugin(user, plugin_obj)
    return can_execute_plugin(user, plugin)


@register.filter(name="organize_dumps")
def organize_dumps(dumps_list):
    """
    Organizes flat dumps values_list into structured hierarchies for sidebar rendering:
    - by_folder: Folders containing host-grouped dumps and standalone dumps.
    - by_host: Global hosts containing all their dumps across folders, plus unassigned dumps.
    """
    if not dumps_list:
        return {
            "by_folder": [],
            "by_host": [],
            "unassigned": [],
            "has_hosts": False,
            "total_count": 0,
        }

    folders = {}
    global_hosts = {}
    global_unassigned = []
    total_count = 0

    for item in dumps_list:
        total_count += 1
        folder_name = item[0] or "General"
        host_name = item[10] if len(item) > 10 else None

        dump_dict = {
            "folder": folder_name,
            "index": item[1],
            "name": item[2],
            "color": item[3],
            "os": item[4],
            "author": item[5],
            "filename": item[6],
            "status": item[7],
            "description": item[8],
            "has_auto": item[9],
            "host_name": host_name,
        }

        # Folder grouping
        if folder_name not in folders:
            folders[folder_name] = {"hosts": {}, "standalone": []}

        if host_name:
            if host_name not in folders[folder_name]["hosts"]:
                folders[folder_name]["hosts"][host_name] = []
            folders[folder_name]["hosts"][host_name].append(dump_dict)

            # Global host grouping
            if host_name not in global_hosts:
                global_hosts[host_name] = []
            global_hosts[host_name].append(dump_dict)
        else:
            folders[folder_name]["standalone"].append(dump_dict)
            global_unassigned.append(dump_dict)

    # Build by_folder list
    by_folder = []
    for f_name, f_data in folders.items():
        hosts_list = []
        hosts_list.extend(
            {
                "name": h_name,
                "dumps": h_dumps,
                "count": len(h_dumps),
                "can_diff": len(h_dumps) == 2,
                "t1_index": h_dumps[0]["index"] if len(h_dumps) == 2 else None,
                "t2_index": h_dumps[1]["index"] if len(h_dumps) == 2 else None,
            }
            for h_name, h_dumps in f_data["hosts"].items()
        )
        by_folder.append(
            {
                "folder": f_name,
                "hosts": hosts_list,
                "standalone": f_data["standalone"],
                "total_count": len(f_data["standalone"])
                + sum(h["count"] for h in hosts_list),
            }
        )

    # Build by_host list
    by_host = []
    by_host.extend(
        {
            "name": h_name,
            "dumps": h_dumps,
            "count": len(h_dumps),
            "can_diff": len(h_dumps) == 2,
            "t1_index": h_dumps[0]["index"] if len(h_dumps) == 2 else None,
            "t2_index": h_dumps[1]["index"] if len(h_dumps) == 2 else None,
        }
        for h_name, h_dumps in global_hosts.items()
    )
    return {
        "by_folder": by_folder,
        "by_host": by_host,
        "unassigned": global_unassigned,
        "has_hosts": bool(by_host),
        "total_count": total_count,
    }


@register.filter(name="split_pipe")
def split_pipe(value):
    """Splits a pipe-delimited evidence snippet into structured key-value tokens."""
    if not value:
        return []
    parts = []
    for item in str(value).split("|"):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            k, v = item.split(":", 1)
            parts.append({"key": k.strip(), "value": v.strip(), "raw": item})
        else:
            parts.append({"key": "", "value": item, "raw": item})
    return parts


@register.filter(name="mitre_url")
def mitre_url(value):
    """Extracts MITRE technique ID and returns the canonical attack.mitre.org URL."""
    if not value:
        return "https://attack.mitre.org"
    import re

    match = re.search(r"(T\d{4}(?:\.\d{3})?)", str(value))
    if match:
        tech_id = match.group(1)
        if "." in tech_id:
            parent, sub = tech_id.split(".", 1)
            return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
        return f"https://attack.mitre.org/techniques/{tech_id}/"
    return "https://attack.mitre.org"


@register.filter(name="mitre_id")
def mitre_id(value):
    """Extracts clean MITRE technique ID (e.g. T1059.004) from descriptive strings."""
    if not value:
        return ""
    import re

    match = re.search(r"(T\d{4}(?:\.\d{3})?)", str(value))
    return match.group(1) if match else str(value)
