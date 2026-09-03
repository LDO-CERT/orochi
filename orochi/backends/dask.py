import contextlib
import logging
import uuid
from copy import deepcopy

from dask.distributed import Client, fire_and_forget
from django.conf import settings
from django.tasks.backends.base import BaseTaskBackend
from django.tasks.base import TaskResult, TaskResultStatus

logger = logging.getLogger(__name__)


def _dask_task_wrapper(task_func, task_id, *args, **kwargs):
    import time

    import django

    if not django.apps.apps.ready:
        django.setup()

    from django.db import close_old_connections

    close_old_connections()

    from orochi.website.models import TaskLog

    log = None
    for _ in range(10):
        try:
            log = TaskLog.objects.get(task_id=task_id)
            break
        except TaskLog.DoesNotExist:
            time.sleep(0.3)
        except Exception as e:
            logger.error(f"Error querying TaskLog {task_id}: {e}")
            time.sleep(0.3)

    if not log:
        try:
            task_name = getattr(task_func, "__name__", "unknown_task")
            log, _ = TaskLog.objects.get_or_create(
                task_id=task_id,
                defaults={"name": task_name, "status": "Running"},
            )
        except Exception as e:
            logger.error(f"Could not recover TaskLog {task_id}: {e}")

    if log:
        try:
            log.status = "Running"
            log.save()
        except Exception as e:
            logger.error(f"Failed to update TaskLog {task_id} to Running: {e}")

    try:
        result = task_func(*args, **kwargs)
        if not log:
            with contextlib.suppress(Exception):
                log = TaskLog.objects.get(task_id=task_id)
        if log:
            try:
                log.status = "Completed"
                if result:
                    log.result = str(result)
                log.save()
            except Exception as e:
                logger.error(f"Failed to update TaskLog {task_id} to Completed: {e}")
        return result
    except Exception as e:
        if not log:
            with contextlib.suppress(Exception):
                log = TaskLog.objects.get(task_id=task_id)
        if log:
            try:
                log.status = "Failed"
                log.error = str(e)
                log.save()
            except Exception as err:
                logger.error(f"Failed to update TaskLog {task_id} to Failed: {err}")
        raise
    finally:
        close_old_connections()


class DaskTaskBackend(BaseTaskBackend):
    def __init__(self, alias, **kwargs):
        super().__init__(alias, **kwargs)
        self._client = None

    @property
    def client(self):
        if self._client is None or self._client.status in ("closed", "closing"):
            self._client = Client(settings.DASK_SCHEDULER_URL)
        return self._client

    def enqueue(self, task, args, kwargs):
        logger.info(f"Enqueuing task {task.name}")

        task_id = str(uuid.uuid4())
        try:
            from django.db.utils import OperationalError, ProgrammingError

            from orochi.website.models import TaskLog

            TaskLog.objects.create(task_id=task_id, name=task.name, status="Submitted")
        except (ProgrammingError, OperationalError):
            logger.warning(
                f"Failed to create TaskLog for {task.name}. Has the database been migrated?"
            )
        except ImportError:
            pass

        try:
            future = self.client.submit(
                _dask_task_wrapper,
                task.func,
                task_id,
                *args,
                pure=False,
                key=task_id,
                **kwargs,
            )
            fire_and_forget(future)
        except Exception as e:
            logger.error(f"Failed to submit task {task.name} to Dask: {e}")
            with contextlib.suppress(Exception):
                from orochi.website.models import TaskLog

                log = TaskLog.objects.get(task_id=task_id)
                log.status = "Failed"
                log.error = f"Failed to submit task to Dask: {e}"
                log.save()
            raise
        result = TaskResult(
            task=task,
            id=future.key,
            status=TaskResultStatus.READY,
            enqueued_at=None,
            started_at=None,
            last_attempted_at=None,
            finished_at=None,
            args=args,
            kwargs=kwargs,
            backend=self.alias,
            errors=[],
            worker_ids=[],
        )
        return deepcopy(result)
