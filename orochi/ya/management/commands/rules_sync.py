import logging

from django.core.management.base import BaseCommand

from orochi.ya.tasks import sync_yara_rules

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Sync Yara Rules by enqueuing the background task"

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def handle(self, *args, **kwargs):
        self.stdout.write("Enqueueing yara rules sync task...")
        task_result = sync_yara_rules.enqueue()
        self.stdout.write(self.style.SUCCESS(f"Task enqueued! ID: {task_result.id}"))
        self.stdout.write(self.style.SUCCESS("Operation rules sync completed"))
