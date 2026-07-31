from django.core.management.base import BaseCommand

from orochi.website.tasks import sync_volatility_plugins


class Command(BaseCommand):
    help = "Sync Volatility Plugins (Background Task)"

    def handle(self, *args, **kwargs):
        self.stdout.write("Enqueueing plugin sync task...")

        task_result = sync_volatility_plugins.enqueue()

        self.stdout.write(self.style.SUCCESS(f"Task enqueued! ID: {task_result.id}"))
