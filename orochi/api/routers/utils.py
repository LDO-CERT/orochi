import json
import logging
from pathlib import Path
from typing import Any

import geoip2.database
from dask.distributed import Client, Future
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from geoip2.errors import GeoIP2Error
from guardian.shortcuts import get_objects_for_user
from ninja import Router, Status
from ninja.security import django_auth, django_auth_superuser

from orochi.api.models import (
    DaskStatusOut,
    ErrorsOut,
    LiveDaskTask,
    SuccessResponse,
    TaskInfoOut,
    TaskLogItem,
    WorkerInfo,
)
from orochi.website.defaults import (
    DUMP_STATUS_CREATED,
    DUMP_STATUS_ERROR,
    DUMP_STATUS_UNZIPPING,
    RESULT_STATUS_ERROR,
    RESULT_STATUS_RUNNING,
)
from orochi.website.models import Dump, Result, TaskLog

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
    if not changelog_path.exists():
        changelog_path = Path(settings.BASE_DIR).parent / "CHANGELOG.md"
    try:
        with open(changelog_path, "r") as f:
            changelog_content = "".join(f.readlines())
            return Status(200, {"note": changelog_content})
    except Exception as excp:
        return Status(400, ErrorsOut(errors=str(excp)))


@router.get(
    "/dask_status",
    auth=django_auth,
    response=DaskStatusOut,
    url_name="dask_status",
)
def dask_status(request):
    """
    Get the status of running tasks, connected workers, live Dask executions, and recent task log entries.
    """
    workers_data = []
    dask_running = 0
    proc_info = {}
    scheduler_tasks = {}

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

        def get_scheduler_tasks(dask_scheduler):
            tasks = {}
            for k, ts in dask_scheduler.tasks.items():
                if ts.state in ("processing", "queued", "waiting"):
                    tasks[k] = {
                        "state": ts.state,
                        "processing_on": (
                            ts.processing_on.address if ts.processing_on else None
                        ),
                    }
            return tasks

        try:
            scheduler_tasks = dask_client.run_on_scheduler(get_scheduler_tasks)
        except Exception:
            scheduler_tasks = {}

        dask_client.close()
    except Exception as e:
        logger.debug(f"Could not connect to Dask scheduler: {e}")

    # Map Dask task keys to worker
    task_to_worker = {}
    for w_addr, keys in proc_info.items():
        for k in keys:
            task_to_worker[k] = w_addr

    live_tasks = []
    now = timezone.now()

    # 1. Active Dumps (Created or Unzipping)
    is_superuser = request.user.is_superuser
    if is_superuser:
        active_dumps = Dump.objects.filter(
            status__in=[DUMP_STATUS_CREATED, DUMP_STATUS_UNZIPPING]
        ).order_by("-created_at")
    else:
        user_dumps = get_objects_for_user(request.user, "website.can_see")
        active_dumps = user_dumps.filter(
            status__in=[DUMP_STATUS_CREATED, DUMP_STATUS_UNZIPPING]
        ).order_by("-created_at")

    for dump in active_dumps:
        is_unzip = dump.status == DUMP_STATUS_UNZIPPING
        t_type = "unzip" if is_unzip else "manage_upload"
        t_name = f"Unzip: {dump.name}" if is_unzip else f"Process Dump: {dump.name}"
        desc = (
            f"Extracting archive for dump '{dump.name}' ({dump.operating_system})"
            if is_unzip
            else f"Processing dump upload '{dump.name}' ({dump.operating_system})"
        )
        worker = None
        for k, w_addr in task_to_worker.items():
            if t_type in k:
                worker = w_addr
                break

        duration = max(0.0, (now - dump.created_at).total_seconds())
        live_tasks.append(
            LiveDaskTask(
                task_id=f"dump_{dump.pk}",
                name=t_name,
                task_type=t_type,
                dump_name=dump.name,
                dump_id=dump.pk,
                dump_index=dump.index,
                worker=worker,
                state="Unzipping" if is_unzip else "Processing",
                duration=round(duration, 1),
                started_at=dump.created_at.strftime("%H:%M:%S (%b %d)"),
                description=desc,
                can_kill=True,
            )
        )

    # 2. Active Running Plugins
    if is_superuser:
        active_results = (
            Result.objects.filter(result=RESULT_STATUS_RUNNING)
            .select_related("dump", "plugin")
            .order_by("-updated_at")
        )
    else:
        active_results = (
            Result.objects.filter(result=RESULT_STATUS_RUNNING, dump__in=user_dumps)
            .select_related("dump", "plugin")
            .order_by("-updated_at")
        )

    for res in active_results:
        worker = None
        for k, w_addr in task_to_worker.items():
            if "run_plugin" in k:
                worker = w_addr
                break
        duration = max(0.0, (now - res.updated_at).total_seconds())
        live_tasks.append(
            LiveDaskTask(
                task_id=f"result_{res.pk}",
                name=f"Plugin: {res.plugin.name}",
                task_type="run_plugin",
                dump_name=res.dump.name,
                dump_id=res.dump.pk,
                dump_index=res.dump.index,
                plugin_name=res.plugin.name,
                worker=worker,
                state="Running",
                duration=round(duration, 1),
                started_at=res.updated_at.strftime("%H:%M:%S (%b %d)"),
                description=f"Executing plugin {res.plugin.name} on dump '{res.dump.name}'",
                can_kill=True,
            )
        )

    # 3. Active TaskLog entries (System Tasks)
    active_task_logs = TaskLog.objects.filter(
        status__in=["Running", "Submitted"]
    ).order_by("-created_at")
    for log in active_task_logs:
        duration = max(0.0, (now - log.created_at).total_seconds())
        worker = task_to_worker.get(log.task_id)
        live_tasks.append(
            LiveDaskTask(
                task_id=log.task_id,
                name=log.name,
                task_type="system_task",
                worker=worker,
                state=log.status,
                duration=round(duration, 1),
                started_at=log.created_at.strftime("%H:%M:%S (%b %d)"),
                description=f"System background task '{log.name}'",
                can_kill=is_superuser,
            )
        )

    # 4. Any other raw Dask scheduler tasks not accounted for (visible to superuser)
    if is_superuser:
        accounted_keys = {t.task_id for t in live_tasks}
        for k, s_info in scheduler_tasks.items():
            if k not in accounted_keys and not any(k in t.task_id for t in live_tasks):
                if any(
                    t.task_type in k
                    for t in live_tasks
                    if t.task_type in ("unzip", "manage_upload", "run_plugin")
                ):
                    continue
                live_tasks.append(
                    LiveDaskTask(
                        task_id=k,
                        name=k.split("-")[0] if "-" in k else k,
                        task_type="dask_task",
                        worker=s_info.get("processing_on"),
                        state=s_info.get("state", "processing").capitalize(),
                        duration=0.0,
                        description=f"Dask raw task: {k}",
                        can_kill=True,
                    )
                )

    db_queued = TaskLog.objects.filter(status="Submitted").count()
    total_running = max(dask_running, len(live_tasks))

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
        live_tasks=live_tasks,
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
        return Status(404, {"errors": "Task not found"})

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
        return Status(400, {"errors": f"Cannot re-run unsupported task: {name}"})

    try:
        res = task_obj.enqueue()
        return Status(
            200,
            {"message": f"Task {name} re-enqueued successfully with ID {res.id}"},
        )
    except Exception as e:
        return Status(400, {"errors": f"Failed to enqueue task: {e}"})


@router.get(
    "/tasks/info/{task_id}",
    auth=django_auth,
    response={200: TaskInfoOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="task_info",
)
def task_info(request, task_id: str):
    """Retrieve detailed stats and metadata for a specific task."""
    now = timezone.now()

    # Check if task is a dump
    if task_id.startswith("dump_"):
        try:
            dump_pk = int(task_id.replace("dump_", ""))
            dump = Dump.objects.get(pk=dump_pk)
        except (ValueError, Dump.DoesNotExist):
            return Status(404, {"errors": "Dump task not found"})

        if not request.user.is_superuser:
            user_dumps = get_objects_for_user(request.user, "website.can_see")
            if dump not in user_dumps:
                return Status(403, {"errors": "Permission denied"})

        is_unzip = dump.status == DUMP_STATUS_UNZIPPING
        duration = max(0.0, (now - dump.created_at).total_seconds())

        return Status(
            200,
            TaskInfoOut(
                task_id=task_id,
                name=(
                    f"Unzip: {dump.name}" if is_unzip else f"Process Dump: {dump.name}"
                ),
                task_type="unzip" if is_unzip else "manage_upload",
                state="Unzipping" if is_unzip else "Processing",
                duration=round(duration, 1),
                started_at=dump.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                dump_id=dump.pk,
                dump_name=dump.name,
                dump_index=dump.index,
                dump_os=dump.operating_system,
                description=(
                    f"Extracting compressed archive file for dump '{dump.name}' ({dump.operating_system})"
                    if is_unzip
                    else f"Indexing & processing memory dump '{dump.name}' ({dump.operating_system})"
                ),
                can_kill=True,
                extra={
                    "size": dump.size,
                    "md5": dump.md5,
                    "sha256": dump.sha256,
                    "author": dump.author.username if dump.author else "System",
                },
            ),
        )

    # Check if task is a result
    if task_id.startswith("result_"):
        try:
            result_pk = int(task_id.replace("result_", ""))
            result = Result.objects.select_related("dump", "plugin").get(pk=result_pk)
        except (ValueError, Result.DoesNotExist):
            return Status(404, {"errors": "Plugin task not found"})

        if not request.user.is_superuser:
            user_dumps = get_objects_for_user(request.user, "website.can_see")
            if result.dump not in user_dumps:
                return Status(403, {"errors": "Permission denied"})

        duration = max(0.0, (now - result.updated_at).total_seconds())
        return Status(
            200,
            TaskInfoOut(
                task_id=task_id,
                name=f"Plugin: {result.plugin.name}",
                task_type="run_plugin",
                state=(
                    "Running"
                    if result.result == RESULT_STATUS_RUNNING
                    else str(result.result)
                ),
                duration=round(duration, 1),
                started_at=result.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                dump_id=result.dump.pk,
                dump_name=result.dump.name,
                dump_index=result.dump.index,
                dump_os=result.dump.operating_system,
                plugin_name=result.plugin.name,
                plugin_params=result.parameter,
                description=f"Running volatility plugin '{result.plugin.name}' on dump '{result.dump.name}'",
                can_kill=True,
                result=result.description,
                extra={
                    "plugin_description": result.plugin.comment,
                },
            ),
        )

    # Check TaskLog
    try:
        log = TaskLog.objects.get(task_id=task_id)
        duration = max(0.0, (now - log.created_at).total_seconds())
        return Status(
            200,
            TaskInfoOut(
                task_id=log.task_id,
                name=log.name,
                task_type="system_task",
                state=log.status,
                duration=round(duration, 1),
                started_at=log.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                description=f"Background system job '{log.name}'",
                can_kill=request.user.is_superuser,
                error=log.error,
                result=log.result,
            ),
        )
    except TaskLog.DoesNotExist:
        pass

    # Raw Dask task
    if request.user.is_superuser:
        try:
            dask_client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")

            def inspect_task(dask_scheduler):
                ts = dask_scheduler.tasks.get(task_id)
                if ts:
                    return {
                        "state": ts.state,
                        "worker": (
                            ts.processing_on.address if ts.processing_on else None
                        ),
                    }
                return None

            t_info = dask_client.run_on_scheduler(inspect_task)
            dask_client.close()
            if t_info:
                return Status(
                    200,
                    TaskInfoOut(
                        task_id=task_id,
                        name=task_id.split("-")[0] if "-" in task_id else task_id,
                        task_type="dask_task",
                        state=t_info.get("state", "processing").capitalize(),
                        worker=t_info.get("worker"),
                        description=f"Dask raw task key: {task_id}",
                        can_kill=True,
                    ),
                )
        except Exception as e:
            logger.debug(f"Error checking raw Dask task: {e}")

    return Status(404, {"errors": f"Task '{task_id}' not found"})


@router.post(
    "/tasks/kill/{task_id}",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="kill_task",
)
def kill_task(request, task_id: str):
    """Cancel a running task (Dump, Plugin, TaskLog, or Dask key)."""

    def cancel_in_dask(key_or_keys):
        try:
            client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
            keys = [key_or_keys] if isinstance(key_or_keys, str) else list(key_or_keys)
            for k in keys:
                try:
                    f = Future(k, client=client)
                    client.cancel(f, force=True)
                except Exception:
                    client.cancel([k], force=True)
            client.close()
        except Exception as e:
            logger.error(f"Failed to cancel {key_or_keys} in Dask: {e}")

    is_superuser = request.user.is_superuser
    is_readonly = (
        not is_superuser and request.user.groups.filter(name="ReadOnly").exists()
    )
    if is_readonly:
        return Status(403, {"errors": "Read-only users cannot cancel tasks"})

    # Case 1: Dump task
    if task_id.startswith("dump_"):
        try:
            dump_pk = int(task_id.replace("dump_", ""))
            dump = Dump.objects.get(pk=dump_pk)
        except (ValueError, Dump.DoesNotExist):
            return Status(404, {"errors": "Dump task not found"})

        if not is_superuser:
            user_dumps = get_objects_for_user(request.user, "website.can_see")
            if dump not in user_dumps:
                return Status(403, {"errors": "Permission denied"})

        try:
            client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
            proc_info = client.processing()
            keys_to_cancel = []
            for keys in proc_info.values():
                for k in keys:
                    if "unzip" in k or "manage_upload" in k or f"dump_{dump.pk}" in k:
                        keys_to_cancel.append(k)
            if keys_to_cancel:
                client.cancel(keys_to_cancel, force=True)
            client.close()
        except Exception as e:
            logger.error(f"Error querying Dask during dump kill: {e}")

        dump.status = DUMP_STATUS_ERROR
        dump.comment = "Cancelled by user"
        dump.save()
        dump.result_set.filter(result=RESULT_STATUS_RUNNING).update(
            result=RESULT_STATUS_ERROR, description="Cancelled by user"
        )
        return Status(
            200,
            {"message": f"Dump '{dump.name}' processing was cancelled successfully"},
        )

    # Case 2: Plugin task
    if task_id.startswith("result_"):
        try:
            result_pk = int(task_id.replace("result_", ""))
            result = Result.objects.select_related("dump", "plugin").get(pk=result_pk)
        except (ValueError, Result.DoesNotExist):
            return Status(404, {"errors": "Plugin task not found"})

        if not is_superuser:
            user_dumps = get_objects_for_user(request.user, "website.can_see")
            if result.dump not in user_dumps:
                return Status(403, {"errors": "Permission denied"})

        try:
            client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
            proc_info = client.processing()
            keys_to_cancel = [
                k for keys in proc_info.values() for k in keys if "run_plugin" in k
            ]
            if keys_to_cancel:
                client.cancel(keys_to_cancel, force=True)
            client.close()
        except Exception as e:
            logger.error(f"Error querying Dask during plugin kill: {e}")

        result.result = RESULT_STATUS_ERROR
        result.description = "Cancelled by user"
        result.save()
        return Status(
            200,
            {"message": f"Plugin task '{result.plugin.name}' cancelled successfully"},
        )

    # Case 3: TaskLog task
    try:
        task_log = TaskLog.objects.get(task_id=task_id)
        if not is_superuser:
            return Status(
                403,
                {"errors": "Superuser permission required to cancel system tasks"},
            )

        cancel_in_dask(task_id)
        task_log.status = "Failed"
        task_log.error = "Killed by user"
        task_log.save()
        return Status(200, {"message": f"Task {task_log.name} killed successfully"})
    except TaskLog.DoesNotExist:
        pass

    # Case 4: Raw Dask task key
    if is_superuser:
        cancel_in_dask(task_id)
        return Status(200, {"message": f"Dask task {task_id} cancelled"})

    return Status(404, {"errors": "Task not found"})


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
        return Status(400, ErrorsOut(errors="Maxmind databases not found."))

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
        return Status(200, data)
    except (GeoIP2Error, Exception) as excp:
        return Status(400, ErrorsOut(errors=str(excp)))


@router.get("/vt", url_name="vt", response={200: Any, 400: ErrorsOut}, auth=django_auth)
def get_extracted_dump_vt_report(request, path: str):
    path = Path(path)
    index = path.parts[2]
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return Status(
            403, ErrorsOut(errors="You do not have permission to access this dump.")
        )
    if path.exists():
        return Status(200, json.loads(open(path, "r").read()))
    return Status(400, ErrorsOut(errors="File not found."))
