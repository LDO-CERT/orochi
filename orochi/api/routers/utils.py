import json
import logging
from pathlib import Path
from typing import Any

import geoip2.database
from dask.distributed import Client
from django.conf import settings
from django.shortcuts import get_object_or_404
from geoip2.errors import GeoIP2Error
from guardian.shortcuts import get_objects_for_user
from ninja import Router
from ninja.security import django_auth, django_auth_superuser

from orochi.api.models import (
    DaskStatusOut,
    ErrorsOut,
    SuccessResponse,
    TaskLogItem,
    WorkerInfo,
)
from orochi.website.models import Dump, TaskLog

logger = logging.getLogger(__name__)

router = Router()


@router.get("changelog", auth=django_auth, response={200: Any, 400: ErrorsOut})
def changelog(request):
    """
    Summary:
    Endpoint to retrieve the changelog content.

    Args:
        request: The incoming request object.

    Returns:
        tuple: A tuple containing the HTTP status code (200) and a dictionary
        with the changelog content under the key "note".
    """
    changelog_path = Path("/app/CHANGELOG.md")
    try:
        with open(changelog_path, "r") as f:
            changelog_content = "".join(f.readlines())
            return 200, {"note": changelog_content}
    except Exception as excp:
        return 400, ErrorsOut(errors=str(excp))


@router.get(
    "/dask_status",
    auth=django_auth,
    response=DaskStatusOut,
    url_name="dask_status",
)
def dask_status(request):
    """
    Get the status of running tasks, connected workers, and recent task log entries.

    Args:
        request: The request object.

    Returns:
        DaskStatusOut: Detailed task counts, worker nodes, and recent task records.
    """
    workers_data = []
    dask_running = 0
    try:
        dask_client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
        sched_info = dask_client.scheduler_info()
        proc_info = dask_client.processing()
        for w_addr, w_info in sched_info.get("workers", {}).items():
            executing = len(proc_info.get(w_addr, ()))
            dask_running += executing
            workers_data.append(
                WorkerInfo(
                    name=w_info.get("name", w_addr.split("//")[-1]),
                    address=w_addr,
                    nthreads=w_info.get("nthreads", 1),
                    memory_limit=w_info.get("memory_limit", 0),
                    executing=executing,
                )
            )
        dask_client.close()
    except Exception as e:
        logger.debug(f"Could not connect to Dask scheduler: {e}")

    db_running = TaskLog.objects.filter(status="Running").count()
    db_queued = TaskLog.objects.filter(status="Submitted").count()

    total_running = max(dask_running, db_running)

    recent_logs = TaskLog.objects.all().order_by("-created_at")[:15]
    task_items = [
        TaskLogItem(
            task_id=log.task_id,
            name=log.name,
            status=log.status,
            created_at=log.created_at.strftime("%H:%M:%S (%b %d)"),
            updated_at=log.updated_at.strftime("%H:%M:%S (%b %d)"),
            result=log.result,
            error=log.error,
        )
        for log in recent_logs
    ]

    return DaskStatusOut(
        running=total_running,
        queued=db_queued,
        workers_count=len(workers_data),
        workers=workers_data,
        recent_tasks=task_items,
    )


@router.post(
    "/tasks/rerun/{task_id}",
    auth=django_auth_superuser,
    response={200: SuccessResponse, 400: ErrorsOut, 404: ErrorsOut},
    url_name="rerun_task",
)
def rerun_task(request, task_id: str):
    """Re-enqueue a task by its task_id from TaskLog."""
    try:
        task_log = TaskLog.objects.get(task_id=task_id)
    except TaskLog.DoesNotExist:
        return 404, {"errors": "Task not found"}

    name = task_log.name
    task_obj = None
    if name in ["sync_volatility_plugins", "_sync_volatility_plugins"]:
        from orochi.website.tasks import sync_volatility_plugins

        task_obj = sync_volatility_plugins
    elif name in ["sync_volatility_symbols", "_sync_volatility_symbols"]:
        from orochi.website.tasks import sync_volatility_symbols

        task_obj = sync_volatility_symbols
    elif name in ["build_cache_in_background", "_build_cache_in_background"]:
        from orochi.website.tasks import build_cache_in_background

        task_obj = build_cache_in_background
    elif name in ["sync_yara_rules", "_sync_yara_rules"]:
        from orochi.ya.tasks import sync_yara_rules

        task_obj = sync_yara_rules

    if not task_obj:
        return 400, {"errors": f"Cannot re-run unsupported task: {name}"}

    try:
        res = task_obj.enqueue()
        return 200, {
            "message": f"Task {name} re-enqueued successfully with ID {res.id}"
        }
    except Exception as e:
        return 400, {"errors": f"Failed to enqueue task: {e}"}


@router.get(
    "/maxmind",
    auth=django_auth,
    url_name="maxmind",
    response={200: Any, 400: ErrorsOut},
)
def maxmind(request, ip: str):
    """
    Retrieve geolocation data for the given IP address using MaxMind databases.

    Args:
        request: The request object.
        ip (str): The IP address for which geolocation data is to be retrieved.

    Returns:
        tuple: A tuple containing the HTTP status code and the geolocation data as a dictionary.
            The status code 200 indicates success, while 400 indicates an error.
    """
    if (
        not Path("/maxmind/GeoLite2-ASN.mmdb").exists()
        and not Path("/maxmind/GeoLite2-City.mmdb").exists()
        and not Path("/maxmind/GeoLite2-Country.mmdb").exists()
    ):
        return 400, ErrorsOut(errors="Maxmind databases not found.")

    try:
        data = {}
        if Path("/maxmind/GeoLite2-ASN.mmdb").exists():
            with geoip2.database.Reader("/maxmind/GeoLite2-ASN.mmdb") as reader:
                data |= reader.asn(ip).to_dict()
        if Path("/maxmind/GeoLite2-City.mmdb").exists():
            with geoip2.database.Reader("/maxmind/GeoLite2-City.mmdb") as reader:
                data |= reader.city(ip).to_dict()
        if Path("/maxmind/GeoLite2-Country.mmdb").exists():
            with geoip2.database.Reader("/maxmind/GeoLite2-Country.mmdb") as reader:
                data |= reader.country(ip).to_dict()
        return 200, data
    except (GeoIP2Error, Exception) as excp:
        return 400, ErrorsOut(errors=str(excp))


@router.get("/vt", url_name="vt", response={200: Any, 400: ErrorsOut}, auth=django_auth)
def get_extracted_dump_vt_report(request, path: str):
    path = Path(path)
    index = path.parts[2]
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return 403, ErrorsOut(errors="You do not have permission to access this dump.")
    if path.exists():
        return 200, json.loads(open(path, "r").read())
    return 400, ErrorsOut(errors="File not found.")
