from django.core.management.base import BaseCommand

from orochi.ya.tasks import run_due_yara_feed_updates


class Command(BaseCommand):
    """Synchronize the YARA feeds marked for automatic update whose last sync is older than ``--interval`` hours.

    Run it from cron (see the Admin Guide), e.g. every hour: feeds are only synced once per interval.
    """

    help = "Synchronize due auto-update YARA feeds (run from cron)"

    def add_arguments(self, parser):
        """Declare ``--interval`` and ``--no-compile``."""
        parser.add_argument("--interval", type=float, default=24.0, help="Hours between two syncs of a feed")
        parser.add_argument("--no-compile", action="store_true", help="Do not rebuild the default rule set")

    def handle(self, *args, **options):
        """Sync the due feeds synchronously and print what happened."""
        res = run_due_yara_feed_updates(options["interval"], compile_default=not options["no_compile"])
        self.stdout.write(
            self.style.SUCCESS(f"Synced {res['synced_count']} feed(s), {res['skipped_count']} not due yet.")
        )
        compile_res = res.get("compile") or {}
        if compile_res.get("skipped_count"):
            self.stdout.write(
                self.style.WARNING(f"{compile_res['skipped_count']} invalid or duplicate rule(s) skipped:")
            )
            for item in compile_res.get("skipped", [])[:50]:
                self.stdout.write(f"  - {item}")
