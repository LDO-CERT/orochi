from django.core.management.base import BaseCommand

from orochi.website.recycle_bin import deleted_dumps, purge_expired, retention_days


class Command(BaseCommand):
    """Permanently delete the dumps whose recycle-bin retention has expired (run it from cron)."""

    help = "Purge expired dumps from the recycle bin"

    def add_arguments(self, parser):
        """Declare ``--days`` and ``--all``."""
        parser.add_argument("--days", type=int, help="Purge dumps deleted more than DAYS ago (default: setting)")
        parser.add_argument("--all", action="store_true", help="Empty the whole recycle bin")

    def handle(self, *args, **options):
        """Purge synchronously and print how many dumps were removed."""
        days = 0 if options["all"] else options["days"]
        count = purge_expired(days)
        left = deleted_dumps().count()
        self.stdout.write(
            self.style.SUCCESS(
                f"Purged {count} dump(s); {left} left in the recycle bin "
                f"(retention {retention_days() if days is None else days} days)."
            )
        )
