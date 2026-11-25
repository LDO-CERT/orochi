from django.core.management.base import BaseCommand, CommandError

from orochi.ya.rules_sync import compile_default_yara_rule


class Command(BaseCommand):
    help = "Create Default Rule"

    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.SUCCESS("Building rule from enabled ones!"))
        try:
            result = compile_default_yara_rule()
        except Exception as excp:
            self.stdout.write(self.style.ERROR(str(excp)))
            raise CommandError("Error compiling rules") from excp

        self.stdout.write(
            self.style.SUCCESS(
                f"Operation generate default rule completed ({result['rules_count']} compiled, {result['skipped_count']} skipped)"
            )
        )
