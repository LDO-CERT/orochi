import os
from pathlib import Path

import yara
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from orochi.website.models import CustomRule
from orochi.ya.models import Rule


class Command(BaseCommand):
    help = "Create Default Rule"

    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.SUCCESS("Building rule from enabled ones!"))
        rules = (
            Rule.objects.exclude(ruleset__enabled=False)
            .exclude(ruleset__user__isnull=False)
            .exclude(enabled=False)
        )
        rules_file = {
            f"{rule.ruleset.name}_{rule.pk}": rule.path
            for rule in rules
            if Path(rule.path).exists()
        }
        self.stdout.write(f"{len(rules_file.keys())} rules must be compiled")
        try:
            rules = yara.compile(filepaths=rules_file)
        except yara.Error as excp:
            self.stdout.write(self.style.ERROR(str(excp)))
            raise CommandError("Error compiling rules") from excp

        if os.path.exists(settings.DEFAULT_YARA_RULE_PATH):
            os.remove(settings.DEFAULT_YARA_RULE_PATH)
        rules.save(settings.DEFAULT_YARA_RULE_PATH)
        self.stdout.write(self.style.SUCCESS("Building completed!"))

        for user in get_user_model().objects.all():
            try:
                default = CustomRule.objects.get(default=True, user=user)
                set_default = default.path == settings.DEFAULT_YARA_RULE_PATH
            except CustomRule.DoesNotExist:
                set_default = True
            try:
                _ = CustomRule.objects.get(
                    user=user, path=settings.DEFAULT_YARA_RULE_PATH
                )
            except CustomRule.DoesNotExist:
                CustomRule.objects.create(
                    user=user,
                    public=False,
                    path=settings.DEFAULT_YARA_RULE_PATH,
                    default=set_default,
                    name="DEFAULT",
                )
                self.stdout.write(f"\tDefault rule added to {user.username}")

        self.stdout.write(self.style.SUCCESS("Operation completed"))
