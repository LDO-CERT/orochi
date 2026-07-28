import logging
from copy import deepcopy

from dask.distributed import Client, fire_and_forget
from django.conf import settings
from django.tasks.backends.base import BaseTaskBackend
from django.tasks.base import TaskResult, TaskResultStatus

logger = logging.getLogger(__name__)


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
        future = self.client.submit(task.func, *args, pure=False, **kwargs)
        fire_and_forget(future)
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
