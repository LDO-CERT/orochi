import logging
import traceback

from dask.distributed import Client, Future
from django.conf import settings

from .models import DaskTask

logger = logging.getLogger(__name__)


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class DaskManager(metaclass=Singleton):
    def __init__(self):
        self.client = Client(
            f"{settings.DASK_SCHEDULER_HOST}:{settings.DASK_SCHEDULER_PORT}"
        )

    def compute(self, tasks):
        for task in tasks:
            future = self.client.submit(task)
            future.add_done_callback(self.task_complete)
            dask_task = DaskTask.objects.create(task_key=future.key)

    def get_future_status(self, task_key):
        return Future(key=task_key, client=self.client).status

    @staticmethod
    def task_complete(future):
        task = DaskTask.objects.get(task_key=future.key)

        if future.status == "finished":
            task.status = future.status
            task.result = future.result()
            task.save()
        elif future.status == "error":
            task.status = future.status
            task.result = traceback.extract_tb(future.traceback()) + [
                future.exception()
            ]
            task.save()
            # will cause exception to be thrown here
            future.result()
        else:
            logger.error("Task completed with unhandled status: " + future.status)
