import os
import time
from multiprocessing.dummy import Pool as ThreadPool
from pathlib import Path

os.environ["GIT_TERMINAL_PROMPT"] = "0"

import git
import marko
import requests
import yara_x
from bs4 import BeautifulSoup
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.color import color_style
from django.tasks import task
from extra_settings.models import Setting
from git.repo import Repo

from orochi.ya.models import Rule, Ruleset

style = color_style()


def compile_rule_worker(item):
    """
    Check if single rule is valid without saving to DB immediately
    """
    path, ruleset_pk = item
    rule_content = None
    error_msg = None
    compiled = False

    try:
        with open(path, "rb") as f:
            rule_content = f.read().decode("utf8", "replace")[:65000]
    except Exception as e:
        error_msg = str(e)

    if rule_content is not None:
        try:
            _ = yara_x.Rules.deserialize_from(str(path))
            compiled = True
            print("\t\tCOMPILED")
        except Exception:
            try:
                with open(str(path), "r") as fp:
                    _ = yara_x.compile(fp.read())
            except Exception as e:
                print(style.ERROR(f"\t\tCannot load rule {path}!"))
                error_msg = str(e)

    return {
        "path": path,
        "ruleset_id": ruleset_pk,
        "rule": rule_content,
        "error": error_msg,
        "compiled": compiled,
        "enabled": error_msg is None,
    }


def down_repo(item):
    """
    Clone or pull remote repos
    """
    updated_rules = []
    rulesetpath, rulesetname, description = item
    ruleset, created = Ruleset.objects.update_or_create(
        name=rulesetname, url=rulesetpath, defaults={"description": description}
    )

    repo_local = (
        f'{Setting.get("LOCAL_YARA_PATH")}/{ruleset.name.lower().replace(" ", "_")}'
    )

    try:
        if created or not ruleset.cloned:
            # GIT CLONE
            repo = Repo.clone_from(
                ruleset.url,
                to_path=repo_local,
            )
            print(f"\tRepo {ruleset.url} cloned")
            ruleset.cloned = True
            ruleset.save()
            updated_rules += [
                (x, ruleset.pk)
                for x in Path(repo_local).glob("**/*")
                if x.suffix.lower() in settings.YARA_EXT
            ]
        else:
            # GIT UPDATE
            repo = Repo(repo_local)
            origin = repo.remotes.origin
            current_hash = repo.head.object.hexsha
            head_name = [x.name for x in repo.heads][0]
            origin.fetch()
            if origin.refs[head_name].object.hexsha != current_hash:
                diff = repo.head.commit.diff(origin.refs[head_name].object.hexsha)
                origin.pull()
                for cht in diff.change_type:
                    changes = list(diff.iter_change_type(cht))
                    if not changes:
                        continue

                    # if file deleted, remove rule
                    if cht in "D":
                        for change in changes:
                            if Path(change.b_path).suffix.lower() in settings.YARA_EXT:
                                rule = Rule.objects.get(
                                    path=f"{repo_local}/{change.a_path}"
                                )
                                rule.delete()
                                print(
                                    style.ERROR(
                                        f"\tRule {change.b_path} has been deleted"
                                    )
                                )

                    elif cht in "M":
                        for change in changes:
                            if Path(change.b_path).suffix.lower() in settings.YARA_EXT:
                                old_path = f"{repo_local}/{change.a_path}"
                                new_path = f"{repo_local}/{change.b_path}"
                                try:
                                    rule = Rule.objects.get(path=old_path)
                                    rule.path = new_path
                                    rule.save()
                                    updated_rules.append((new_path, ruleset.pk))
                                    print(
                                        style.SUCCESS(
                                            f"\tRule {old_path} has been updated"
                                        )
                                    )
                                except Rule.DoesNotExist:
                                    # If it doesn't exist but it was modified, we should just add it
                                    updated_rules.append((new_path, ruleset.pk))
                                    print(
                                        style.ERROR(
                                            f"\tRule {old_path} does not exists, adding it anyway"
                                        )
                                    )

                    elif cht in ("A", "C"):
                        for change in changes:
                            if Path(change.b_path).suffix.lower() in settings.YARA_EXT:
                                path = f"{repo_local}/{change.b_path}"
                                updated_rules.append((path, ruleset.pk))
            print(f"\tRepo {ruleset.url} pulled")
        return updated_rules
    except (git.GitCommandError, git.NoSuchPathError) as e:
        print(style.ERROR(f"\tERROR: {e}"))
        ruleset.enabled = False
        ruleset.save()
        return []


def _sync_yara_rules():
    """
    Sync rulesets list from awesome-yara rule and custom rulesets
    """
    start_time = time.time()

    r = requests.get(Setting.get("AWESOME_PATH"))
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
    other_rulesets = Ruleset.objects.filter(user__isnull=True, enabled=True).exclude(
        url__in=[x[0] for x in rulesets]
    )
    rulesets.extend(
        (ruleset.url, ruleset.name, ruleset.description) for ruleset in other_rulesets
    )
    print(style.SUCCESS(f"Found {len(rulesets)} repo"))

    pool = ThreadPool(Setting.get("THREAD_NO"))
    results = pool.map(down_repo, rulesets)
    pool.close()
    pool.join()

    updated_rules = []
    for res in results:
        if res:
            updated_rules.extend(res)

    if updated_rules:
        print(
            style.SUCCESS(
                f"Compiling {len(updated_rules)} updated rules in parallel..."
            )
        )
        pool = ThreadPool(Setting.get("THREAD_NO"))
        results_data = pool.map(compile_rule_worker, updated_rules)
        pool.close()
        pool.join()

        # Batch DB saves
        paths = [r["path"] for r in results_data]
        existing_rules = {
            rule.path: rule for rule in Rule.objects.filter(path__in=paths)
        }
        rules_to_create = []
        rules_to_update = []

        for data in results_data:
            path = data["path"]
            if path in existing_rules:
                rule = existing_rules[path]
                rule.rule = data["rule"]
                rule.error = data["error"]
                rule.compiled = data["compiled"]
                rule.enabled = data["enabled"]
                rules_to_update.append(rule)
            else:
                rules_to_create.append(
                    Rule(
                        path=path,
                        ruleset_id=data["ruleset_id"],
                        rule=data["rule"],
                        error=data["error"],
                        compiled=data["compiled"],
                        enabled=data["enabled"],
                    )
                )

        if rules_to_create:
            Rule.objects.bulk_create(rules_to_create, batch_size=500)
        if rules_to_update:
            Rule.objects.bulk_update(
                rules_to_update,
                ["rule", "error", "compiled", "enabled"],
                batch_size=500,
            )

    # ADD CUSTOM RULESET TO ALL OLD USERS
    users = list(get_user_model().objects.all())
    existing_custom = set(
        Ruleset.objects.filter(user__isnull=False).values_list("user_id", flat=True)
    )

    new_rulesets_list = []
    for user in users:
        if user.id not in existing_custom:
            new_rulesets_list.append(
                Ruleset(
                    user=user,
                    name=f"{user.username}-Ruleset",
                    description="Your crafted ruleset",
                )
            )
            print(style.SUCCESS(f"Ruleset added to {user}!"))

    if new_rulesets_list:
        Ruleset.objects.bulk_create(new_rulesets_list)
    new_rulesets = len(new_rulesets_list)

    print("DONE")
    duration = time.time() - start_time
    print(
        style.SUCCESS(
            f"sync_yara_rules completed in {duration:.2f}s. Updated {len(updated_rules)} rules, {new_rulesets} new rulesets."
        )
    )
    return "Sync completed successfully"


sync_yara_rules = task(queue_name="default")(_sync_yara_rules)
