from django.core.management.base import BaseCommand

from orochi.website.tasks import sync_volatility_symbols


class Command(BaseCommand):
    help = "Sync Volatility Symbols (Background Task)"

    def handle(self, *args, **kwargs):
        self.stdout.write("Enqueueing symbol sync task...")

        task_result = sync_volatility_symbols.enqueue()

        self.stdout.write(self.style.SUCCESS(f"Task enqueued! ID: {task_result.id}"))
