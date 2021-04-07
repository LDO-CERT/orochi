import os
import yara
from pathlib import Path

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from orochi.ya.models import Rule
from orochi.website.models import CustomRule

DEFAULT_YARA_PATH = "/yara/default.yara"


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
            "{}_{}".format(rule.ruleset.name, rule.pk): rule.path
            for rule in rules
            if Path(rule.path).exists()
        }
        self.stdout.write("{} rules must be compiled".format(len(rules_file.keys())))
        try:
            rules = yara.compile(filepaths=rules_file)
        except yara.Error as excp:
            self.stdout.write(self.style.ERROR(str(excp)))
            return

        if os.path.exists(DEFAULT_YARA_PATH):
            os.remove(DEFAULT_YARA_PATH)
        rules.save(DEFAULT_YARA_PATH)
        self.stdout.write(self.style.SUCCESS("Building completed!"))

        for user in get_user_model().objects.all():
            try:
                default = CustomRule.objects.get(default=True, user=user)
                set_default = False if default.path != DEFAULT_YARA_PATH else True
            except CustomRule.DoesNotExist:
                set_default = True
            try:
                _ = CustomRule.objects.get(user=user, path=DEFAULT_YARA_PATH)
            except:
                CustomRule.objects.create(
                    user=user,
                    public=False,
                    path=DEFAULT_YARA_PATH,
                    default=set_default,
                    name="DEFAULT",
                )
                self.stdout.write("\tDefault rule added to {}".format(user.username))

        self.stdout.write(self.style.SUCCESS("Operation completed"))
