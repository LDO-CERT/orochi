import os
import time
from multiprocessing.dummy import Pool as ThreadPool
from pathlib import Path

os.environ["GIT_TERMINAL_PROMPT"] = "0"

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
    path_str = str(path)
    rule_content = None
    error_msg = None
    compiled = False

    # Check file size: if larger than 2MB, skip compiling full source with yara_x to prevent worker hangs
    try:
        file_size = os.path.getsize(path_str)
    except OSError:
        file_size = 0

    if file_size > 2 * 1024 * 1024:
        error_msg = f"Rule file too large ({file_size / (1024 * 1024):.1f}MB), skipped"
        try:
            with open(path_str, "rb") as f:
                rule_content = (
                    f.read(65000).decode("utf8", "replace").replace("\x00", "")
                )
        except Exception:
            rule_content = None
    else:
        try:
            with open(path_str, "rb") as f:
                raw_bytes = f.read()
                # PostgreSQL text fields cannot contain \x00 NUL bytes
                rule_content = raw_bytes.decode("utf8", "replace")[:65000].replace(
                    "\x00", ""
                )
        except Exception as e:
            error_msg = str(e)

        if rule_content is not None:
            try:
                _ = yara_x.Rules.deserialize_from(path_str)
                compiled = True
            except Exception:
                try:
                    with open(path_str, "r", errors="ignore") as fp:
                        _ = yara_x.compile(fp.read())
                except Exception as e:
                    error_msg = str(e)

    if error_msg:
        error_msg = str(error_msg).replace("\x00", "")[:1000]

    return {
        "path": path_str.replace("\x00", "")[:255],
        "ruleset_id": ruleset_pk,
        "rule": rule_content,
        "error": error_msg,
        "compiled": compiled,
        "enabled": error_msg is None,
    }


def compile_and_commit_block(rules_block, pool):
    """
    Compile a smaller block of rules in parallel and commit immediately to DB.
    """
    if not rules_block:
        return 0, 0

    results_data = pool.map(compile_rule_worker, rules_block)

    paths = [r["path"] for r in results_data]
    existing_rules = {r.path: r for r in Rule.objects.filter(path__in=paths)}

    rules_to_create = []
    rules_to_update = []

    for data in results_data:
        path = data["path"][:255]
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

    created_count = 0
    updated_count = 0

    if rules_to_create:
        try:
            Rule.objects.bulk_create(rules_to_create, ignore_conflicts=True)
            created_count = len(rules_to_create)
        except Exception as e:
            print(f"Batch create error: {e}, saving individually...")
            for r in rules_to_create:
                try:
                    r.save()
                    created_count += 1
                except Exception as row_err:
                    print(f"Failed to save rule {r.path}: {row_err}")

    if rules_to_update:
        try:
            Rule.objects.bulk_update(
                rules_to_update,
                ["rule", "error", "compiled", "enabled"],
            )
            updated_count = len(rules_to_update)
        except Exception as e:
            print(f"Batch update error: {e}, updating individually...")
            for r in rules_to_update:
                try:
                    r.save(update_fields=["rule", "error", "compiled", "enabled"])
                    updated_count += 1
                except Exception as row_err:
                    print(f"Failed to update rule {r.path}: {row_err}")

    return created_count, updated_count


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
        f"{Setting.get('LOCAL_YARA_PATH')}/{ruleset.name.lower().replace(' ', '_')}"
    )

    try:
        if created or not ruleset.cloned or not os.path.exists(repo_local):
            # GIT CLONE
            if not os.path.exists(repo_local):
                repo = Repo.clone_from(
                    ruleset.url,
                    to_path=repo_local,
                )
                print(f"\tRepo {ruleset.url} cloned")
            ruleset.cloned = True
            ruleset.save()
            updated_rules += [
                (str(x), ruleset.pk)
                for x in Path(repo_local).glob("**/*")
                if x.suffix.lower() in settings.YARA_EXT
            ]
        else:
            # GIT UPDATE
            try:
                repo = Repo(repo_local)
                origin = repo.remotes.origin
                current_hash = repo.head.object.hexsha
                origin.fetch()
                active_branch = None
                try:
                    active_branch = repo.active_branch.name
                except (TypeError, IndexError):
                    heads = [x.name for x in repo.heads]
                    if heads:
                        active_branch = heads[0]

                remote_ref = None
                if active_branch:
                    for ref in origin.refs:
                        if (
                            ref.name.endswith(f"/{active_branch}")
                            or ref.name == active_branch
                        ):
                            remote_ref = ref
                            break

                if remote_ref and remote_ref.object.hexsha != current_hash:
                    diff = repo.head.commit.diff(remote_ref.object.hexsha)
                    origin.pull()
                    for cht in diff.change_type:
                        changes = list(diff.iter_change_type(cht))
                        if not changes:
                            continue

                        # if file deleted, remove rule
                        if cht in "D":
                            for change in changes:
                                if (
                                    Path(change.b_path).suffix.lower()
                                    in settings.YARA_EXT
                                ):
                                    try:
                                        rule = Rule.objects.get(
                                            path=f"{repo_local}/{change.a_path}"
                                        )
                                        rule.delete()
                                        print(
                                            style.ERROR(
                                                f"\tRule {change.b_path} has been deleted"
                                            )
                                        )
                                    except Rule.DoesNotExist:
                                        pass

                        elif cht in "M":
                            for change in changes:
                                if (
                                    Path(change.b_path).suffix.lower()
                                    in settings.YARA_EXT
                                ):
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
                                        updated_rules.append((new_path, ruleset.pk))

                        elif cht in ("A", "C"):
                            for change in changes:
                                if (
                                    Path(change.b_path).suffix.lower()
                                    in settings.YARA_EXT
                                ):
                                    path = f"{repo_local}/{change.b_path}"
                                    updated_rules.append((path, ruleset.pk))
                print(f"\tRepo {ruleset.url} pulled")
            except Exception as pull_err:
                print(
                    style.ERROR(f"\tWarning updating repo {ruleset.name}: {pull_err}")
                )

        # CRITICAL RECOVERY: If ruleset has 0 rules in DB, discover existing local files!
        if not Rule.objects.filter(ruleset=ruleset).exists():
            print(
                f"\tRuleset {ruleset.name} has no rules in DB, scanning local files..."
            )
            existing_local = [
                (str(x), ruleset.pk)
                for x in Path(repo_local).glob("**/*")
                if x.suffix.lower() in settings.YARA_EXT
            ]
            existing_paths = {r[0] for r in updated_rules}
            for item_rule in existing_local:
                if item_rule[0] not in existing_paths:
                    updated_rules.append(item_rule)
                    existing_paths.add(item_rule[0])

        return updated_rules
    except Exception as e:
        print(style.ERROR(f"\tERROR: {e}"))
        ruleset.enabled = False
        ruleset.save()
        return []


@task(queue_name="default")
def sync_yara_rules():
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
        # Deduplicate updated_rules before compilation
        seen_targets = set()
        deduped_targets = []
        for r_path, r_pk in updated_rules:
            if r_path not in seen_targets:
                seen_targets.add(r_path)
                deduped_targets.append((r_path, r_pk))
        updated_rules = deduped_targets

        BLOCK_SIZE = 500
        total_rules = len(updated_rules)
        total_blocks = (total_rules + BLOCK_SIZE - 1) // BLOCK_SIZE
        print(
            style.SUCCESS(
                f"Processing {total_rules} rules in smaller blocks of {BLOCK_SIZE} ({total_blocks} blocks total)..."
            )
        )

        pool = ThreadPool(Setting.get("THREAD_NO"))
        total_created = 0
        total_updated = 0

        for block_idx in range(total_blocks):
            start_idx = block_idx * BLOCK_SIZE
            end_idx = min(start_idx + BLOCK_SIZE, total_rules)
            block = updated_rules[start_idx:end_idx]

            c_count, u_count = compile_and_commit_block(block, pool)
            total_created += c_count
            total_updated += u_count

            current_db_total = Rule.objects.count()
            print(
                style.SUCCESS(
                    f"[{block_idx + 1}/{total_blocks}] Block committed (+{c_count} created, +{u_count} updated). DB total: {current_db_total} rules"
                )
            )

        pool.close()
        pool.join()
        print(
            style.SUCCESS(
                f"All blocks committed! Created: {total_created}, Updated: {total_updated}."
            )
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


# Aliases for backward compatibility with previously queued tasks
_sync_yara_rules = sync_yara_rules
