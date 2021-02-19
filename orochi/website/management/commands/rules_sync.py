from django.core.management.base import BaseCommand
import subprocess


class Command(BaseCommand):
    help = "Sync Yara Rules"

    def handle(self, *args, **kwargs):
        env = {"LD_LIBRARY_PATH": "/usr/local/lib"}
        with subprocess.Popen(
            "/yara/yaya update",
            stdout=subprocess.PIPE,
            env=env,
            universal_newlines=True,
            shell=True,
        ) as process:
            for line in process.stdout:
                self.stdout.write(self.style.SUCCESS(line))

        try:
            subprocess.check_call(
                "/yara/yaya export /yara/all.yara", env=env, shell=True
            )
        except subprocess.CalledProcessError as excp:
            self.stdout.write(self.style.ERROR(excp))
        self.stdout.write(self.style.SUCCESS("Operation completed"))
