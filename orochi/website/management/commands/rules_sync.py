from django.core.management.base import BaseCommand
import subprocess


class Command(BaseCommand):
    help = "Sync Yara Rules"

    def handle(self, *args, **kwargs):
        env = {"LD_LIBRARY_PATH": "/usr/local/lib"}
        result = subprocess.run(
            ["/yaya/yaya", "update"], capture_output=True, text=True, env=env
        )
        if result.stdout:
            self.stdout.write(self.style.SUCCESS(result.stdout))
        if result.stderr:
            self.stdout.write(self.style.ERROR(result.stderr))
        result = subprocess.run(
            ["/yaya/yaya", "export", "all.yara"],
            capture_output=True,
            text=True,
            env=env,
        )
        if result.stdout:
            self.stdout.write(self.style.SUCCESS(result.stdout))
        if result.stderr:
            self.stdout.write(self.style.ERROR(result.stderr))