import logging
import mmap
import os
from functools import wraps

from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.db.models import F
from django.http.response import HttpResponse

from orochi.utils.volatility_dask_elk import manage_upload
from orochi.website.roles import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_READONLY,
    get_user_role,
    has_role,
)

logger = logging.getLogger(__name__)

COLOR_TEMPLATE = """<div class="w-3.5 h-3.5 rounded shadow-xs ring-1 ring-black/10 dark:ring-white/10 shrink-0" style="background-color: {};"></div>"""

SYSTEM_COLUMNS = [
    "orochi_createdAt",
    "orochi_os",
    "orochi_plugin",
    "down_path",
]

PLUGIN_WITH_CHILDREN = {
    "frameworkinfo.frameworkinfo": "Data",
    "linux.iomem.iomem": "Name",
    "linux.mountinfo.mountinfo": "MOUNT_POINT",
    "linux.pstree.pstree": "PID",
    "mac.pstree.pstree": "PID",
    "windows.devicetree.devicetree": "Offset",
    "windows.mbrscan.mbrscan": "Potential MBR at Physical Offset",
    "windows.mftscan.mftscan": "Offset",
    "windows.pstree.pstree": "PID",
    "windows.registry.userassist.userassist": "Hive Offset",
}

INDEX_VALUES_LIST = [
    "folder__name",
    "index",
    "name",
    "color",
    "operating_system",
    "author",
    "upload",
    "status",
    "description",
    "has_auto",
    "host__name",
]

DUMP_ORDER_BY = (
    "folder__name",
    F("host__name").asc(nulls_last=True),
    "created_at",
    "name",
)


##############################
# SAFE DUMP FILE RESOLUTION
##############################


def resolve_dump_file(filepath, user):
    """
    Resolve a client-supplied path to an existing file stored inside a dump folder.

    The real path (symlinks and ``..`` resolved) must live under ``MEDIA_ROOT`` and its
    first path component that names a Dump must be a dump the user can see.
    Returns ``(Path, Dump)`` or ``(None, None)``.
    """
    from pathlib import Path

    from django.conf import settings
    from guardian.shortcuts import get_objects_for_user

    from orochi.website.models import Dump

    if not filepath or "\x00" in str(filepath):
        return None, None
    media_root = os.path.realpath(settings.MEDIA_ROOT)
    media_prefix = media_root.rstrip(os.sep) + os.sep
    raw = str(filepath)
    candidates = [raw if raw.startswith("/") else f"/{raw}", os.path.join(media_root, raw.lstrip("/"))]
    # Row actions pass URL-style paths ("/media/<index>/..."): map them onto MEDIA_ROOT wherever it is
    media_url = (settings.MEDIA_URL or "/media/").rstrip("/") + "/"
    if raw.startswith(media_url):
        candidates.append(os.path.join(media_root, raw[len(media_url) :]))
    for cand in candidates:
        # Normalize (resolving symlinks and "..") before the containment check
        real_str = os.path.realpath(cand)
        if not real_str.startswith(media_prefix):
            continue
        if not os.path.isfile(real_str):
            continue
        real = Path(real_str)
        rel_parts = Path(real_str[len(media_prefix) :]).parts
        dump = None
        for part in rel_parts[:-1]:
            dump = Dump.objects.filter(index=part).first()
            if dump:
                break
        if not dump:
            continue
        if not get_objects_for_user(user, "website.can_see", klass=Dump).filter(pk=dump.pk).exists():
            return None, None
        return real, dump
    return None, None


##############################
# NGIN AUTH CHECK
##############################


def auth_check(request):
    """
    A view for Nginx's auth_request.

    The @login_required decorator handles everything. If the user is authenticated,
    Django will execute this view and return a 200 OK. If they are not,
    the decorator will redirect to the login page, which for an auth_request
    results in a non-200 status that Nginx can interpret as "unauthorized".
    """
    if request.user.is_authenticated:
        return HttpResponse(status=200)
    else:
        return HttpResponse(status=401)


def is_not_readonly(user):
    """Check if user is not readonly"""
    return get_user_role(user) != ROLE_READONLY


def is_analyst_or_admin(user):
    """Check if user is Analyst or Admin"""
    return has_role(user, ROLE_ANALYST)


def is_admin(user):
    """Check if user is Admin"""
    return has_role(user, ROLE_ADMIN)


def role_required(test_func):
    """Enforce a role predicate without trapping authenticated users in login redirects."""

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            """Redirect anonymous users to login and raise 403 when ``test_func`` fails."""
            if not request.user.is_authenticated:
                return redirect_to_login(request.get_full_path())
            if not test_func(request.user):
                raise PermissionDenied
            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator


def change_keys(obj, title):
    """Change keys for tree rendering"""
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            if k not in SYSTEM_COLUMNS and k == "__children" and v != []:
                new["children"] = change_keys(v, title)
            elif k not in SYSTEM_COLUMNS and k == "__children" or (k in SYSTEM_COLUMNS and k != "orochi_plugin"):
                continue
            elif k == title:
                new["title"] = v
            else:
                new[k] = v if v is not None else "-"
    elif isinstance(obj, list):
        new = [change_keys(v, title) for v in obj]
    else:
        return obj
    return new


def get_hex_rec(path, length, start):
    """Returns formatted portion of memory"""
    if ".." in str(path):
        raise ValueError(f"Invalid path: {path}")
    with open(path, "r+b") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        if file_size == 0:
            return [], 0
        if start >= file_size or start < 0:
            raise ValueError(f"Offset {start} is out of bounds for file size {file_size}")
        actual_len = min(length, file_size - start)
        map_file = mmap.mmap(f.fileno(), length=0, prot=mmap.PROT_READ)
        map_file.seek(start)
        values = []
        data = map_file.read(actual_len)
        parts = [data[i : i + 16] for i in range(0, len(data), 16)]
        for i, line in enumerate(parts):
            idx = start + i * 16
            values.append(
                (
                    f"{idx:08x}",
                    " ".join([f"{x:02x}" for x in line]),
                    " ".join(
                        [
                            (
                                "<span class='singlechar'>.</span>"
                                if int(f"{x:02x}", 16) <= 32
                                or 127 <= int(f"{x:02x}", 16) <= 160
                                or int(f"{x:02x}", 16) == 173
                                else f"<span class='singlechar'>{chr(x)}</span>"
                            )
                            for x in line
                        ]
                    ),
                )
            )

        return values, (file_size + 15) // 16


def index_f_and_f(dump_pk, user_pk, password=None, restart=None, move=True):
    """Run all plugin for a new index on dask"""
    from orochi.backends.dask_client import submit_and_confirm

    # Confirmed submission: a plain fire-and-forget future is lost if this process exits first
    submit_and_confirm(manage_upload, dump_pk, user_pk, password, restart, move, timeout=15)
