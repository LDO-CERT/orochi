import logging

from django.core.management.base import BaseCommand

from orochi.backends.dask_client import wait_for_scheduler
from orochi.ya.tasks import sync_yara_rules

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Enqueue the YARA rules sync task (download and index the configured rulesets)."""

    help = "Sync Yara Rules by enqueuing the background task"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle(self, *args, **kwargs):
        """Enqueue ``sync_yara_rules`` and print the task id."""
        self.stdout.write("Enqueueing yara rules sync task...")
        task_result = sync_yara_rules.enqueue()
        self.stdout.write(self.style.SUCCESS(f"Task enqueued! ID: {task_result.id}"))
        # This process exits right away: make sure the scheduler received the task
        if not wait_for_scheduler(task_result.id):
            self.stderr.write(self.style.ERROR("The Dask scheduler did not receive the task."))
            return
        self.stdout.write(
            self.style.SUCCESS("Rules sync queued: follow it in the Activity drawer or the TaskLog admin.")
        )
