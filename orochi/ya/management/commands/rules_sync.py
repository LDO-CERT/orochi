import git
import pytz
import requests
import marko
import yara
from pathlib import Path
from git import Repo
from bs4 import BeautifulSoup
from django.utils import timezone

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from orochi.ya.models import Ruleset, Rule

AWESOME_PATH = "https://raw.githubusercontent.com/InQuest/awesome-yara/master/README.md"
LOCAL_YARA_PATH = "/yara"


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
            try:
                description = BeautifulSoup(
                    ruleset.nextSibling.li.text, "html.parser"
                ).text
            except AttributeError:
                try:
                    description = BeautifulSoup(
                        ruleset.nextSibling.nextSibling.li.text, "html.parser"
                    ).text
                except AttributeError:
                    description = None
            if link.startswith("https://github.com/"):
                rulesets.append((link, name, description))

        self.stdout.write(self.style.SUCCESS("Found {} repo".format(len(rulesets))))

        updated_list = []
        for rulesetpath, rulesetname, description in rulesets:
            ruleset, created = Ruleset.objects.update_or_create(
                name=rulesetname, url=rulesetpath
            )
            ruleset.description = description
            ruleset.save()

            updated_list.append(ruleset.pk)

            repo_local = "{}/{}".format(
                LOCAL_YARA_PATH, ruleset.name.lower().replace(" ", "_")
            )

            if not created:
                # GIT UPDATE
                try:
                    repo = Repo(repo_local)
                    origin = repo.remotes.origin
                    origin.pull()
                    self.stdout.write("\tRepo {} pulled".format(ruleset.url))
                except (git.exc.GitCommandError, git.exc.NoSuchPathError) as e:
                    self.stdout.write(self.style.ERROR("\tERROR: {}".format(e)))
                    updated_list.pop()

            else:
                # GIT CLONE
                try:
                    repo = Repo.clone_from(
                        ruleset.url,
                        to_path=repo_local,
                    )
                    self.stdout.write("\tRepo {} cloned".format(ruleset.url))
                except git.exc.GitCommandError as e:
                    self.stdout.write(self.style.ERROR("\tERROR: {}".format(e)))
                    updated_list.pop()

        if len(updated_list) > 0:
            # DISABLE ALL REPO NOT ANYMORE ON AWESOME
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

    def add_yara(self):
        self.stdout.write(self.style.SUCCESS("Updating Rules"))
        for ruleset in Ruleset.objects.filter(url__isnull=False, enabled=True):
            self.stdout.write("\t{}".format(ruleset.name))
            updated_list = []
            path = "{}/{}".format(
                LOCAL_YARA_PATH, ruleset.name.lower().replace(" ", "_")
            )
            for path in Path(path).rglob("*.yar*"):
                # TRY LOADING COMPILED, IF FAILS TRY LOAD
                try:
                    rules = yara.load(str(path))
                    compiled = True
                    self.stdout.write("\t\tCOMPILED")
                except yara.Error:
                    try:
                        rules = yara.compile(str(path), includes=False)
                        compiled = False
                    except yara.SyntaxError as e:
                        self.stdout.write(
                            self.style.ERROR("\t\tCannot load rule {}!".format(path))
                        )
                        self.stdout.write("\t\t\t{}".format(e))
                        continue

                rule, created = Rule.objects.get_or_create(path=path, ruleset=ruleset)
                rule.compiled = compiled
                rule.save()
                updated_list.append(ruleset.pk)

                if created:
                    self.stdout.write("\t\tRule {} added".format(path))

                repo_local = "{}/{}".format(
                    LOCAL_YARA_PATH, ruleset.name.lower().replace(" ", "_")
                )

            rules = Rule.objects.exclude(ruleset=ruleset, pk__in=updated_list)
            for rule in rules:
                rule.deleted = timezone.now()
                rule.disabled = True
                rule.save()

    def handle(self, *args, **kwargs):
        self.parse_awesome()
        self.add_yara()

        # ADD CUSTOM RULESET TO ALL OLD USERS
        for user in get_user_model().objects.all():
            _, created = Ruleset.objects.get_or_create(
                user=user,
                name="{}-Ruleset".format(user.username),
                description="Your crafted ruleset",
            )
            if created:
                self.stdout.write(
                    self.style.SUCCESS("Ruleset added to {}!".format(user))
                )

        self.stdout.write(self.style.SUCCESS("Operation completed"))
