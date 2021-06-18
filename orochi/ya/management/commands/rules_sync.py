import git
import requests
import marko
import yara
from pathlib import Path
from git import Repo
from bs4 import BeautifulSoup
from django.db import transaction

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from orochi.ya.models import Ruleset, Rule

from multiprocessing.dummy import Pool as ThreadPool


AWESOME_PATH = "https://raw.githubusercontent.com/InQuest/awesome-yara/master/README.md"
LOCAL_YARA_PATH = "/yara"
THREAD_NO = 10
YARA_EXT = [".yar", ".yara", ".rule"]


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
                self.stdout.write(
                    self.style.ERROR("\t\tCannot load rule {}!".format(path))
                )
                self.stdout.write("\t\t\t{}".format(e))
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

        repo_local = "{}/{}".format(
            LOCAL_YARA_PATH, ruleset.name.lower().replace(" ", "_")
        )

        if created or not ruleset.cloned:
            # GIT CLONE
            try:
                repo = Repo.clone_from(
                    ruleset.url,
                    to_path=repo_local,
                )
                self.stdout.write("\tRepo {} cloned".format(ruleset.url))
                ruleset.cloned = True
                ruleset.save()
                self.updated_rules += [
                    (x, ruleset.pk)
                    for x in Path(repo_local).glob("**/*")
                    if x.suffix.lower() in YARA_EXT
                ]
            except git.exc.GitCommandError as e:
                self.stdout.write(self.style.ERROR("\tERROR: {}".format(e)))
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
                        if changes in ("D"):
                            for d in changes:
                                if Path(d.b_path).suffix.lower() in YARA_EXT:
                                    rule = Rule.objects.get(path=d.b_path)
                                    rule.delete()
                                    self.stdout.write(
                                        self.style.ERROR(
                                            "\tRule {} has been deleted".format(
                                                d.b_path
                                            )
                                        )
                                    )

                        # if changed update [rename generate also a M event]
                        elif changes in ("M"):
                            for d in changes:
                                if Path(d.b_path).suffix.lower() in YARA_EXT:
                                    rule = Rule.objects.get(path=d.a_path)
                                    rule.path = d.b_path
                                    rule.save()
                                    self.stdout.write(
                                        self.style.ERROR(
                                            "\tRule {} has been updated".format(
                                                d.a_path
                                            )
                                        )
                                    )

                        # if new add to test list
                        elif changes in ("A", "C"):
                            for d in changes:
                                if Path(d.b_path).suffix.lower() in YARA_EXT:
                                    self.updated_rules += (ruleset.pk, d.b_path)

                self.stdout.write("\tRepo {} pulled".format(ruleset.url))
            except (git.exc.GitCommandError, git.exc.NoSuchPathError) as e:
                self.stdout.write(self.style.ERROR("\tERROR: {}".format(e)))
                ruleset.enabled = False
                ruleset.save()

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

        # UPDATE MANUAL ADDED REPO
        other_rulesets = Ruleset.objects.filter(
            user__isnull=True, enabled=True
        ).exclude(url__in=[x[0] for x in rulesets])
        for ruleset in other_rulesets:
            rulesets.append((ruleset.url, ruleset.name, ruleset.description))

        self.stdout.write(self.style.SUCCESS("Found {} repo".format(len(rulesets))))

        with transaction.atomic():
            pool = ThreadPool(THREAD_NO)
            _ = pool.map(self.down_repo, rulesets)
            pool.close()

        self.stdout.write("DONE")

    def add_yara(self):
        """
        Get all yara rules in rulesets
        """
        self.stdout.write(self.style.SUCCESS("Updating Rules"))
        self.stdout.write("\t{} rules to test!".format(len(self.updated_rules)))
        with transaction.atomic():
            pool = ThreadPool(THREAD_NO)
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
                name="{}-Ruleset".format(user.username),
                description="Your crafted ruleset",
            )
            if created:
                self.stdout.write(
                    self.style.SUCCESS("Ruleset added to {}!".format(user))
                )

    def handle(self, *args, **kwargs):
        self.parse_awesome()
        self.add_yara()
        self.custom_rulesets()
        self.stdout.write(self.style.SUCCESS("Operation completed"))
