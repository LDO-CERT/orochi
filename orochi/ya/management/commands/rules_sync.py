from multiprocessing.dummy import Pool as ThreadPool
from pathlib import Path

import git
import marko
import requests
import yara
from bs4 import BeautifulSoup
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from git.repo import Repo

from orochi.ya.models import Rule, Ruleset


class Command(BaseCommand):
    help = "Sync Yara Rules"

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.updated_rules = []

    def compile_rule(self, item):
        """
        Check if single rule is valid
        """
        path, ruleset_pk = item
        ruleset = Ruleset.objects.get(pk=ruleset_pk)
        rule, _ = Rule.objects.get_or_create(path=path, ruleset=ruleset)
        compiled = False
        # TRY LOADING COMPILED, IF FAILS TRY LOAD
        try:
            _ = yara.load(str(path))
            compiled = True
            self.stdout.write("\t\tCOMPILED")
        except yara.Error:
            try:
                _ = yara.compile(str(path), includes=False)
            except yara.SyntaxError as e:
                self.stdout.write(self.style.ERROR(f"\t\tCannot load rule {path}!"))
                self.stdout.write(f"\t\t\t{e}")
                rule.enabled = False
        rule.compiled = compiled
        rule.save()

    def down_repo(self, item):
        """
        Clone or pull remote repos
        """
        rulesetpath, rulesetname, description = item
        ruleset, created = Ruleset.objects.update_or_create(
            name=rulesetname, url=rulesetpath, defaults={"description": description}
        )

        repo_local = (
            f'{settings.LOCAL_YARA_PATH}/{ruleset.name.lower().replace(" ", "_")}'
        )

        if created or not ruleset.cloned:
            # GIT CLONE
            try:
                repo = Repo.clone_from(
                    ruleset.url,
                    to_path=repo_local,
                )
                self.stdout.write(f"\tRepo {ruleset.url} cloned")
                ruleset.cloned = True
                ruleset.save()
                self.updated_rules += [
                    (x, ruleset.pk)
                    for x in Path(repo_local).glob("**/*")
                    if x.suffix.lower() in settings.YARA_EXT
                ]
            except git.GitCommandError as e:
                self.stdout.write(self.style.ERROR(f"\tERROR: {e}"))
                ruleset.enabled = False
                ruleset.save()
        else:
            # GIT UPDATE
            try:
                repo = Repo(repo_local)
                origin = repo.remotes.origin
                current_hash = repo.head.object.hexsha
                head_name = [x.name for x in repo.heads][0]
                origin.fetch()
                changed = origin.refs[head_name].object.hexsha != current_hash
                if changed:
                    diff = repo.head.commit.diff(origin.refs[head_name].object.hexsha)
                    origin.pull()
                    for cht in diff.change_type:
                        changes = list(diff.iter_change_type(cht))
                        if len(changes) == 0:
                            continue

                        # if file deleted, remove rule
                        if cht in "D":
                            for change in changes:
                                if (
                                    Path(change.b_path).suffix.lower()
                                    in settings.YARA_EXT
                                ):
                                    rule = Rule.objects.get(
                                        path="{}/{}".format(repo_local, change.a_path)
                                    )
                                    rule.delete()
                                    self.stdout.write(
                                        self.style.ERROR(
                                            f"\tRule {change.b_path} has been deleted"
                                        )
                                    )

                        # if changed update [rename generate also a M event]
                        elif cht in "M":
                            for change in changes:
                                if (
                                    Path(change.b_path).suffix.lower()
                                    in settings.YARA_EXT
                                ):
                                    old_path = "{}/{}".format(repo_local, change.a_path)
                                    new_path = "{}/{}".format(repo_local, change.b_path)
                                    rule = Rule.objects.get(path=old_path)
                                    rule.path = new_path
                                    rule.save()
                                    self.stdout.write(
                                        self.style.ERROR(
                                            f"\tRule {old_path} has been updated"
                                        )
                                    )

                        # if new add to test list
                        elif cht in ("A", "C"):
                            for change in changes:
                                if (
                                    Path(change.b_path).suffix.lower()
                                    in settings.YARA_EXT
                                ):
                                    path = "{}/{}".format(repo_local, change.b_path)
                                    self.updated_rules.append((path, ruleset.pk))

                self.stdout.write("\tRepo {} pulled".format(ruleset.url))
            except (git.GitCommandError, git.NoSuchPathError) as e:
                self.stdout.write(self.style.ERROR(f"\tERROR: {e}"))
                ruleset.enabled = False
                ruleset.save()

    def parse_awesome(self):
        """
        Sync rulesets list from awesome-yara rule
        """
        r = requests.get(settings.AWESOME_PATH)
        soup = BeautifulSoup(marko.convert(r.text), features="html.parser")
        rulesets = []
        if ruls := [x for x in soup.findAll("h2") if x.get_text() == "Rules"]:
            rulesets_a = ruls[0].nextSibling.nextSibling.find_all("a")
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

        # UPDATE MANUAL ADDED REPO
        other_rulesets = Ruleset.objects.filter(
            user__isnull=True, enabled=True
        ).exclude(url__in=[x[0] for x in rulesets])
        rulesets.extend(
            (ruleset.url, ruleset.name, ruleset.description)
            for ruleset in other_rulesets
        )
        self.stdout.write(self.style.SUCCESS(f"Found {len(rulesets)} repo"))

        with transaction.atomic():
            pool = ThreadPool(settings.THREAD_NO)
            _ = pool.map(self.down_repo, rulesets)
            pool.close()

        self.stdout.write("DONE")

    def add_yara(self):
        """
        Get all yara rules in rulesets
        """
        self.stdout.write(self.style.SUCCESS("Updating Rules"))
        self.stdout.write(f"\t{len(self.updated_rules)} rules to test!")
        with transaction.atomic():
            pool = ThreadPool(settings.THREAD_NO)
            _ = pool.map(self.compile_rule, self.updated_rules)
            pool.close()
        self.stdout.write("DONE")

    def custom_rulesets(self):
        """
        ADD CUSTOM RULESET TO ALL OLD USERS
        """
        for user in get_user_model().objects.all():
            _, created = Ruleset.objects.get_or_create(
                user=user,
                name=f"{user.username}-Ruleset",
                description="Your crafted ruleset",
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Ruleset added to {user}!"))

    def handle(self, *args, **kwargs):
        self.parse_awesome()
        self.add_yara()
        self.custom_rulesets()
        self.stdout.write(self.style.SUCCESS("Operation completed"))
