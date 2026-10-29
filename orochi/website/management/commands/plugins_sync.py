import time

from django.core.management.base import BaseCommand

from orochi.website.models import TaskLog
from orochi.website.tasks import sync_volatility_plugins


class Command(BaseCommand):
    help = "Sync Volatility Plugins (Background Task)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--wait",
            action="store_true",
            help="Wait for the background task to complete and print its result or error",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=300,
            help="Maximum seconds to wait when --wait is enabled (default: 300)",
        )

    def handle(self, *args, **options):
        wait = options.get("wait", False)
        timeout = options.get("timeout", 300)

        self.stdout.write("Enqueueing plugin sync task...")
        task_result = sync_volatility_plugins.enqueue()
        self.stdout.write(self.style.SUCCESS(f"Task enqueued! ID: {task_result.id}"))

        if not wait:
            return

        self.stdout.write(f"Waiting for task {task_result.id} to complete (timeout: {timeout}s)...")
        start = time.time()
        last_status = None
        while time.time() - start < timeout:
            try:
                task_log = TaskLog.objects.get(task_id=task_result.id)
                if task_log.status != last_status:
                    last_status = task_log.status
                    self.stdout.write(f"Task status: {last_status}")

                if task_log.status == "Completed":
                    self.stdout.write(
                        self.style.SUCCESS(f"Task completed successfully: {task_log.result or 'No result data'}")
                    )
                    return
                elif task_log.status == "Failed":
                    self.stderr.write(self.style.ERROR(f"Task failed: {task_log.error or 'Unknown error'}"))
                    return
            except TaskLog.DoesNotExist:
                pass
            time.sleep(1)

        self.stderr.write(self.style.WARNING(f"Timed out after {timeout} seconds waiting for task {task_result.id}"))
