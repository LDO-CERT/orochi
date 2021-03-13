from git.exc import GitCommandError
import pytz
import requests
import marko
from git import Repo
from bs4 import BeautifulSoup
from django.utils import timezone

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from orochi.ya.models import Ruleset

AWESOME_PATH = "https://raw.githubusercontent.com/InQuest/awesome-yara/master/README.md"
LOCAL_PATH = "/yara"


class Command(BaseCommand):
    help = "Sync Yara Rules"

    def parse_awesome(self):
        """
        Sync rulesets list from awesome-yara rule
        """
        r = requests.get(AWESOME_PATH)
        soup = BeautifulSoup(marko.convert(r.text), features="html.parser")
        rulesets_a = soup.h2.nextSibling.nextSibling.find_all("a")
        rulesets = []
        for ruleset in rulesets_a:
            link = ruleset["href"].split("/tree/")[0]
            name = ruleset.contents[0]
            if link.startswith("https://github.com/"):
                rulesets.append((link, name))

        self.stdout.write(self.style.SUCCESS("Found {} repo".format(len(rulesets))))

        updated_list = []
        for rulesetpath, rulesetname in rulesets:
            ruleset, created = Ruleset.objects.get_or_create(
                name=rulesetname, url=rulesetpath
            )
            updated_list.append(ruleset.pk)
            if not created:
                ruleset.save()

                # GIT UPDATE

            else:

                # GIT CLONE
                # try:
                repo = Repo.clone_from(
                    ruleset.url,
                    to_path="{}/{}".format(
                        LOCAL_PATH, ruleset.name.lower().replace(" ", "_")
                    ),
                )
                self.stdout.write(
                    self.style.SUCCESS("Repo {} cloned".format(ruleset.url))
                )
                # except GitCommandError as e:
                #    self.stdout.write(self.style.ERROR("{}".format(e)))

        if len(updated_list) > 0:
            old_rulesets = Ruleset.objects.filter(user__isnull=True).exclude(
                pk__in=updated_list
            )
            for ruleset in old_rulesets:
                ruleset.deleted = timezone.now()
                ruleset.disabled = True
                ruleset.save()
                for rule in ruleset.rules.all():
                    rule.deleted = timezone.now()
                    rule.disabled = True
                    rule.save()
        else:
            self.stdout.write(self.style.ERROR("No ruleset found, check code!"))

    def handle(self, *args, **kwargs):
        self.parse_awesome()

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
