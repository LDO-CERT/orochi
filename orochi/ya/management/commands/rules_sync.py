from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from orochi.ya.models import Ruleset
from git import Repo


class Command(BaseCommand):
    help = "Sync Yara Rules"

    def handle(self, *args, **kwargs):

        # GET ALL GIT PATH FROM ENABLED RULESET & UPLOAD THEM
        for ruleset in Ruleset.objects.filter(url__isnull=False, enabled=True):
            # DOWNLOAD RULE

            # TRY TO COMPILE

            # IF OK ADD/UPDATE DB
            print(ruleset)

        ## HOW TO MANAGE DELETED :)

        # ADD CUSTOM RULESET TO ALL OLD USERS
        for user in get_user_model().objects.all():
            _, created = Ruleset.objects.get_or_create(
                user=user, name="{}-Ruleset".format(user.username)
            )
            if created:
                self.stdout.write(
                    self.style.SUCCESS("Ruleset added to {}!".format(user))
                )

        self.stdout.write(self.style.SUCCESS("Operation completed"))
