import logging
from datetime import timedelta

from distributed import Client, fire_and_forget
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from guardian.shortcuts import get_objects_for_user
from ninja import Query, Router, Status
from ninja.security import django_auth

from orochi.api.models import (
    BulkTaskKillIn,
    ErrorsOut,
    SuccessResponse,
    TaskFilterQuery,
    TaskInfoOut,
    TaskListOut,
    TaskSummaryOut,
    UnifiedTaskOut,
    WorkerInfo,
)
from orochi.api.permissions import ninja_role_required
from orochi.website.defaults import (
    DUMP_STATUS_CREATED,
    DUMP_STATUS_ERROR,
    DUMP_STATUS_UNZIPPING,
    RESULT_STATUS_ERROR,
    RESULT_STATUS_RUNNING,
)
from orochi.website.models import Dump, Result, TaskLog
from orochi.website.roles import ROLE_ADMIN

logger = logging.getLogger(__name__)
router = Router()


def get_dask_cluster_state() -> tuple[list[WorkerInfo], dict[str, str], dict[str, dict], int]:
    """
    Connects to the Dask scheduler and returns:
    - workers_data: list of WorkerInfo
    - task_to_worker: mapping of task keys to worker addresses
    - scheduler_tasks: mapping of raw scheduler task states
    - dask_running_count: count of active running tasks
    """
    workers_data = []
    task_to_worker = {}
    scheduler_tasks = {}
    dask_running_count = 0

    try:
        dask_client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
        sched_info = dask_client.scheduler_info()
        proc_info = dask_client.processing()

        for w_addr, w_info in sched_info.get("workers", {}).items():
            executing = len(proc_info.get(w_addr, ()))
            dask_running_count += executing
            workers_data.append(
                WorkerInfo(
                    name=w_info.get("name", w_addr.split("//")[-1]),
                    address=w_addr,
                    nthreads=w_info.get("nthreads", 1),
                    memory_limit=w_info.get("memory_limit", 0),
                    executing=executing,
                )
            )

        for w_addr, keys in proc_info.items():
            for k in keys:
                task_to_worker[k] = w_addr

        def _get_sched_tasks(dask_scheduler):
            tasks = {}
            for k, ts in dask_scheduler.tasks.items():
                if ts.state in ("processing", "queued", "waiting"):
                    tasks[k] = {
                        "state": ts.state,
                        "processing_on": (ts.processing_on.address if ts.processing_on else None),
                    }
            return tasks

        try:
            scheduler_tasks = dask_client.run_on_scheduler(_get_sched_tasks)
        except Exception:
            scheduler_tasks = {}

        dask_client.close()
    except Exception as e:
        logger.debug(f"Could not connect to Dask scheduler: {e}")

    return workers_data, task_to_worker, scheduler_tasks, dask_running_count


def cancel_dask_keys(key_or_keys):
    """Cancels one or more keys in the Dask scheduler."""
    try:
        client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
        keys = [key_or_keys] if isinstance(key_or_keys, str) else list(key_or_keys)
        client.cancel(keys, force=True)
        client.close()
    except Exception as e:
        logger.error(f"Failed to cancel tasks in Dask: {e}")


@router.get(
    "/",
    auth=django_auth,
    response={200: TaskListOut, 400: ErrorsOut},
    url_name="list_tasks",
)
def list_tasks(request, filters: Query[TaskFilterQuery] = None):
    """
    Summary:
    List all tasks in the system with unified status, filtering, and pagination.

    Explanation:
    Aggregates in-flight memory dump processing, plugin executions, background system jobs (TaskLog),
    and raw Dask scheduler tasks. Supports filtering by status ('Running', 'Queued', 'Completed', 'Failed', 'All'),
    task type ('dump', 'plugin', 'system_task', 'dask_task'), dump ID, and text search.
    """
    filters = filters or TaskFilterQuery()
    workers_data, task_to_worker, scheduler_tasks, _ = get_dask_cluster_state()
    now = timezone.now()
    is_superuser = request.user.is_superuser
    is_admin = is_superuser or request.user.is_staff or request.user.groups.filter(name="Admin").exists()

    all_tasks: list[UnifiedTaskOut] = []

    # 1. In-flight Dumps
    if is_superuser:
        active_dumps = Dump.objects.filter(status__in=[DUMP_STATUS_CREATED, DUMP_STATUS_UNZIPPING]).order_by(
            "-created_at"
        )
    else:
        user_dumps = get_objects_for_user(request.user, "website.can_see")
        active_dumps = user_dumps.filter(status__in=[DUMP_STATUS_CREATED, DUMP_STATUS_UNZIPPING]).order_by(
            "-created_at"
        )

    for dump in active_dumps:
        is_unzip = dump.status == DUMP_STATUS_UNZIPPING
        t_type = "unzip" if is_unzip else "manage_upload"
        worker = None
        for k, w_addr in task_to_worker.items():
            if t_type in k or f"dump_{dump.pk}" in k:
                worker = w_addr
                break
        duration = max(0.0, (now - dump.created_at).total_seconds())
        all_tasks.append(
            UnifiedTaskOut(
                task_id=f"dump_{dump.pk}",
                name=(f"Unzip: {dump.name}" if is_unzip else f"Process Dump: {dump.name}"),
                task_type="dump",
                state="Unzipping" if is_unzip else "Processing",
                worker=worker,
                duration=round(duration, 1),
                started_at=dump.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                created_at=dump.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                dump_id=dump.pk,
                dump_name=dump.name,
                dump_index=dump.index,
                dump_os=dump.operating_system,
                description=(
                    f"Extracting archive for dump '{dump.name}' ({dump.operating_system})"
                    if is_unzip
                    else f"Processing dump upload '{dump.name}' ({dump.operating_system})"
                ),
                can_kill=True,
                can_retry=False,
            )
        )

    # 2. In-flight Plugins
    if is_superuser:
        active_results = (
            Result.objects.filter(result=RESULT_STATUS_RUNNING).select_related("dump", "plugin").order_by("-updated_at")
        )
    else:
        user_dumps = get_objects_for_user(request.user, "website.can_see")
        active_results = (
            Result.objects.filter(result=RESULT_STATUS_RUNNING, dump__in=user_dumps)
            .select_related("dump", "plugin")
            .order_by("-updated_at")
        )

    for res in active_results:
        worker = None
        for k, w_addr in task_to_worker.items():
            if f"run_plugin_{res.pk}" in k or "run_plugin" in k:
                worker = w_addr
                break
        duration = max(0.0, (now - res.updated_at).total_seconds())
        all_tasks.append(
            UnifiedTaskOut(
                task_id=f"result_{res.pk}",
                name=f"Plugin: {res.plugin.name}",
                task_type="plugin",
                state="Running",
                worker=worker,
                duration=round(duration, 1),
                started_at=res.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                created_at=res.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                updated_at=res.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                dump_id=res.dump.pk,
                dump_name=res.dump.name,
                dump_index=res.dump.index,
                dump_os=res.dump.operating_system,
                plugin_name=res.plugin.name,
                description=f"Running plugin {res.plugin.name} on dump '{res.dump.name}'",
                can_kill=True,
                can_retry=False,
            )
        )

    # 3. System Tasks (TaskLog)
    task_log_qs = TaskLog.objects.all().order_by("-created_at")
    for log in task_log_qs[:200]:
        duration = max(0.0, (now - log.created_at).total_seconds()) if log.status in ("Running", "Submitted") else 0.0
        worker = task_to_worker.get(log.task_id)
        is_active = log.status in ("Running", "Submitted")
        all_tasks.append(
            UnifiedTaskOut(
                task_id=log.task_id,
                name=log.name,
                task_type="system_task",
                state=log.status,
                worker=worker,
                duration=round(duration, 1),
                started_at=log.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                created_at=log.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                updated_at=log.updated_at.strftime("%Y-%m-%d %H:%M:%S"),
                description=f"System background task '{log.name}'",
                can_kill=is_active and is_admin,
                can_retry=log.status in ("Failed", "Completed"),
                error=log.error,
                result=log.result,
            )
        )

    # 4. Raw Dask Scheduler Tasks (Superuser only)
    if is_superuser:
        accounted_keys = {t.task_id for t in all_tasks}
        for k, s_info in scheduler_tasks.items():
            if k not in accounted_keys and all(t.task_id not in k for t in all_tasks):
                all_tasks.append(
                    UnifiedTaskOut(
                        task_id=k,
                        name=k.split("-")[0] if "-" in k else k,
                        task_type="dask_task",
                        state=s_info.get("state", "processing").capitalize(),
                        worker=s_info.get("processing_on"),
                        duration=0.0,
                        description=f"Raw Dask task: {k}",
                        can_kill=True,
                        can_retry=False,
                    )
                )

    # Filtering
    filtered = all_tasks

    # Status filter
    if filters.status and filters.status.lower() != "all":
        st = filters.status.lower()
        if st in ("running", "processing", "unzipping"):
            filtered = [t for t in filtered if t.state.lower() in ("running", "processing", "unzipping")]
        elif st in ("queued", "submitted", "waiting"):
            filtered = [t for t in filtered if t.state.lower() in ("queued", "submitted", "waiting")]
        elif st in ("completed", "success"):
            filtered = [t for t in filtered if t.state.lower() in ("completed", "success")]
        elif st in ("failed", "error"):
            filtered = [t for t in filtered if t.state.lower() in ("failed", "error")]
        else:
            filtered = [t for t in filtered if t.state.lower() == st]

    # Task Type filter
    if filters.task_type and filters.task_type.lower() != "all":
        tt = filters.task_type.lower()
        filtered = [t for t in filtered if t.task_type.lower() == tt]

    # Dump ID filter
    if filters.dump_id is not None:
        filtered = [t for t in filtered if t.dump_id == filters.dump_id]

    # Text Search filter
    if filters.search:
        q = filters.search.lower()
        filtered = [
            t
            for t in filtered
            if q in t.name.lower()
            or q in t.task_id.lower()
            or (t.description and q in t.description.lower())
            or (t.dump_name and q in t.dump_name.lower())
            or (t.plugin_name and q in t.plugin_name.lower())
        ]

    total_count = len(all_tasks)
    filtered_count = len(filtered)

    # Pagination
    start = max(0, filters.offset)
    end = start + filters.limit
    paginated = filtered[start:end]

    return TaskListOut(
        total=total_count,
        filtered=filtered_count,
        tasks=paginated,
    )


@router.get(
    "/summary",
    auth=django_auth,
    response={200: TaskSummaryOut},
    url_name="tasks_summary",
)
def tasks_summary(request):
    """
    Summary:
    Retrieve aggregate metrics and worker utilization across the task queue.
    """
    workers_data, _, _, dask_running = get_dask_cluster_state()

    active_dumps_count = Dump.objects.filter(status__in=[DUMP_STATUS_CREATED, DUMP_STATUS_UNZIPPING]).count()
    active_results_count = Result.objects.filter(result=RESULT_STATUS_RUNNING).count()
    running_logs_count = TaskLog.objects.filter(status="Running").count()

    total_running = max(dask_running, active_dumps_count + active_results_count + running_logs_count)
    queued_count = TaskLog.objects.filter(status="Submitted").count()
    completed_count = TaskLog.objects.filter(status="Completed").count()
    failed_count = TaskLog.objects.filter(status="Failed").count()

    total_all = total_running + queued_count + completed_count + failed_count

    return TaskSummaryOut(
        running=total_running,
        queued=queued_count,
        completed=completed_count,
        failed=failed_count,
        total=total_all,
        workers_count=len(workers_data),
        workers=workers_data,
    )


@router.post(
    "/bulk/kill",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
    url_name="bulk_kill_tasks",
)
@ninja_role_required(ROLE_ADMIN)
def bulk_kill_tasks(request, payload: BulkTaskKillIn):
    """
    Summary:
    Bulk cancel multiple tasks matching criteria.

    Explanation:
    Supports cancelling all running tasks, all queued tasks, all tasks for a specific dump,
    or a specific list of task IDs.
    """
    cancelled_count = 0

    # 1. Kill by explicit task IDs
    if payload.task_ids:
        for tid in payload.task_ids:
            try:
                from orochi.api.routers.utils import kill_task

                resp = kill_task(request, tid)
                if getattr(resp, "status_code", 200) == 200:
                    cancelled_count += 1
            except Exception as e:
                logger.warning(f"Failed to cancel task {tid}: {e}")

    # 2. Kill by dump ID
    if payload.dump_id:
        dump = get_object_or_404(Dump, pk=payload.dump_id)
        if dump.status in (DUMP_STATUS_CREATED, DUMP_STATUS_UNZIPPING):
            cancel_dask_keys([f"dump_{dump.pk}", f"unzip_{dump.pk}", f"manage_upload_{dump.pk}"])
            dump.status = DUMP_STATUS_ERROR
            dump.comment = "Bulk cancelled by administrator"
            dump.save()
            cancelled_count += 1

        running_results = dump.result_set.filter(result=RESULT_STATUS_RUNNING)
        if running_results.exists():
            keys = [f"run_plugin_{r.pk}" for r in running_results]
            cancel_dask_keys(keys)
            running_results.update(result=RESULT_STATUS_ERROR, description="Bulk cancelled by administrator")
            cancelled_count += running_results.count()

    # 3. Kill all running tasks
    if payload.all_running:
        try:
            client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
            proc_info = client.processing()
            all_keys = []
            if hasattr(proc_info, "values"):
                for keys in proc_info.values():
                    if isinstance(keys, (list, tuple, set)):
                        all_keys.extend(keys)
            if all_keys:
                client.cancel(all_keys, force=True)
            client.close()
        except Exception as e:
            logger.debug(f"Error bulk cancelling running keys in Dask: {e}")

        dumps_updated = Dump.objects.filter(status__in=[DUMP_STATUS_CREATED, DUMP_STATUS_UNZIPPING]).update(
            status=DUMP_STATUS_ERROR, comment="Bulk cancelled by administrator"
        )
        results_updated = Result.objects.filter(result=RESULT_STATUS_RUNNING).update(
            result=RESULT_STATUS_ERROR, description="Bulk cancelled by administrator"
        )
        logs_updated = TaskLog.objects.filter(status="Running").update(
            status="Failed", error="Bulk cancelled by administrator"
        )
        cancelled_count += dumps_updated + results_updated + logs_updated

    # 4. Kill all queued tasks
    if payload.all_queued:
        queued_logs = TaskLog.objects.filter(status="Submitted")
        keys = list(queued_logs.values_list("task_id", flat=True))
        if keys:
            cancel_dask_keys(keys)
        count = queued_logs.update(status="Failed", error="Bulk cancelled by administrator")
        cancelled_count += count

    return Status(200, {"message": f"Successfully cancelled {cancelled_count} task(s)"})


@router.delete(
    "/prune",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
    url_name="prune_tasks",
)
@ninja_role_required(ROLE_ADMIN)
def prune_tasks(request, days: int = 7, status: str | None = None, all: bool = False):
    """
    Summary:
    Prune and clean up historical TaskLog records.

    Explanation:
    Deletes finished ('Completed' or 'Failed') TaskLog records older than the specified number of days (default 7).
    Set 'all=true' to purge all completed and failed task logs regardless of age.
    """
    qs = TaskLog.objects.filter(status__in=["Completed", "Failed"])

    if not all:
        cutoff = timezone.now() - timedelta(days=max(0, days))
        qs = qs.filter(created_at__lte=cutoff)

    if status:
        qs = qs.filter(status=status)

    count, _ = qs.delete()
    return Status(200, {"message": f"Successfully pruned {count} historical task log(s)"})


@router.post(
    "/workers/restart",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
    url_name="restart_workers",
)
@ninja_role_required(ROLE_ADMIN)
def restart_workers(request):
    """
    Summary:
    Restart Dask worker processes to clear memory and hung tasks.
    """
    try:
        client = Client(settings.DASK_SCHEDULER_URL, timeout="5s")
        client.restart()
        client.close()
        return Status(200, {"message": "Dask worker processes restarted successfully"})
    except Exception as excp:
        return Status(400, {"errors": f"Failed to restart Dask workers: {excp}"})


@router.get(
    "/{task_id}",
    auth=django_auth,
    response={200: TaskInfoOut, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="get_task_info",
)
def get_task_info(request, task_id: str):
    """
    Summary:
    Retrieve full details and metadata for a specific task.
    """
    from orochi.api.routers.utils import task_info as utils_task_info

    return utils_task_info(request, task_id)


@router.post(
    "/{task_id}/kill",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="kill_task_by_id",
)
def kill_task_endpoint(request, task_id: str):
    """
    Summary:
    Cancel/kill an active or queued task.
    """
    from orochi.api.routers.utils import kill_task as utils_kill_task

    return utils_kill_task(request, task_id)


@router.post(
    "/{task_id}/retry",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
    url_name="retry_task",
)
def retry_task(request, task_id: str):
    """
    Summary:
    Retry/re-enqueue a failed or completed task.

    Explanation:
    Supports retrying background system jobs (TaskLog), failed plugin executions (Result),
    and failed memory dump ingestion jobs.
    """
    is_superuser = request.user.is_superuser
    is_admin = is_superuser or request.user.is_staff or request.user.groups.filter(name="Admin").exists()

    # Case 1: Dump task
    if task_id.startswith("dump_"):
        try:
            dump_pk = int(task_id.replace("dump_", ""))
            dump = Dump.objects.get(pk=dump_pk)
        except (ValueError, Dump.DoesNotExist):
            return Status(404, {"errors": "Dump not found"})

        if not is_superuser:
            user_dumps = get_objects_for_user(request.user, "website.can_see")
            if dump not in user_dumps:
                return Status(403, {"errors": "Permission denied"})

        try:
            from orochi.website.tasks import manage_upload

            dump.status = DUMP_STATUS_CREATED
            dump.comment = "Retried by user"
            dump.save()
            manage_upload.enqueue(dump.pk)
            return Status(200, {"message": f"Dump processing retried for '{dump.name}'"})
        except Exception as e:
            return Status(400, {"errors": f"Failed to retry dump processing: {e}"})

    # Case 2: Plugin task
    if task_id.startswith("result_"):
        try:
            result_pk = int(task_id.replace("result_", ""))
            res = Result.objects.select_related("dump", "plugin").get(pk=result_pk)
        except (ValueError, Result.DoesNotExist):
            return Status(404, {"errors": "Plugin result not found"})

        if not is_superuser:
            user_dumps = get_objects_for_user(request.user, "website.can_see")
            if res.dump not in user_dumps:
                return Status(403, {"errors": "Permission denied"})

        try:
            from orochi.utils.volatility_dask_elk import run_plugin

            res.result = RESULT_STATUS_RUNNING
            res.description = "Retried by user"
            res.save()

            client = Client(settings.DASK_SCHEDULER_URL, timeout="2s")
            future = client.submit(
                run_plugin,
                res.dump.pk,
                res.plugin.name,
                res.parameter or {},
                key=f"run_plugin_{res.pk}",
            )
            fire_and_forget(future)
            client.close()
            return Status(200, {"message": f"Plugin '{res.plugin.name}' re-submitted on dump '{res.dump.name}'"})
        except Exception as e:
            return Status(400, {"errors": f"Failed to retry plugin execution: {e}"})

    # Case 3: TaskLog task
    try:
        task_log = TaskLog.objects.get(task_id=task_id)
    except TaskLog.DoesNotExist:
        return Status(404, {"errors": f"Task '{task_id}' not found"})

    if not is_admin:
        return Status(403, {"errors": "Administrator role required to retry system tasks"})

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
        return Status(400, {"errors": f"Cannot retry unsupported task: {name}"})

    try:
        new_res = task_obj.enqueue()
        return Status(200, {"message": f"Task '{name}' re-enqueued successfully with new ID {new_res.id}"})
    except Exception as e:
        return Status(400, {"errors": f"Failed to re-enqueue task: {e}"})
