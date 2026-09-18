import logging
import os
from pathlib import Path

import yara_x
from django.contrib.auth import get_user_model
from extra_settings.models import Setting

from orochi.website.models import CustomRule
from orochi.ya.models import Rule

logger = logging.getLogger(__name__)


def compile_default_yara_rule():
    """
    Compile all active, enabled YARA rules into the default serialized rule file
    located at Setting.get('DEFAULT_YARA_RULE_PATH').
    """
    default_path = Setting.get("DEFAULT_YARA_RULE_PATH")
    if not default_path:
        default_path = "/yara/default.yara"

    rules = Rule.objects.exclude(ruleset__enabled=False).exclude(ruleset__user__isnull=False).exclude(enabled=False)
    rules_file = {f"{rule.ruleset.name}_{rule.pk}": rule.path for rule in rules if Path(rule.path).exists()}

    compiler = yara_x.Compiler()
    for rulepath in rules_file.values():
        with open(rulepath, errors="ignore") as fp:
            compiler.add_source(fp.read())

    built_rules = compiler.build()

    os.makedirs(os.path.dirname(default_path), exist_ok=True)
    if os.path.exists(default_path):
        os.remove(default_path)

    with open(default_path, "wb") as fo:
        built_rules.serialize_into(fo)

    for user in get_user_model().objects.all():
        try:
            default = CustomRule.objects.get(default=True, user=user)
            set_default = default.path == default_path
        except CustomRule.DoesNotExist:
            set_default = True

        try:
            _ = CustomRule.objects.get(user=user, path=default_path)
        except CustomRule.DoesNotExist:
            CustomRule.objects.create(
                user=user,
                public=False,
                path=default_path,
                default=set_default,
                name="DEFAULT",
            )

    return {
        "success": True,
        "path": default_path,
        "rules_count": len(rules_file),
        "size_bytes": os.path.getsize(default_path) if os.path.exists(default_path) else 0,
    }


def _verify_worker_rules(rule_path):
    """Execution on Dask worker: verify rule file existence and deserializability."""
    import os

    import yara_x

    if not os.path.exists(rule_path):
        return {"status": "missing", "path": rule_path}
    try:
        _ = yara_x.Rules.deserialize_from(rule_path)
        return {
            "status": "ok",
            "path": rule_path,
            "size_bytes": os.path.getsize(rule_path),
        }
    except Exception as exc:
        return {"status": "error", "path": rule_path, "error": str(exc)}


def sync_rules_to_workers():
    """
    Verify and synchronize compiled YARA rules across all connected Dask workers.
    Issue #272 / #1552.
    """
    default_path = Setting.get("DEFAULT_YARA_RULE_PATH") or "/yara/default.yara"
    dask_scheduler = Setting.get("DASK_SCHEDULER")

    try:
        from dask.distributed import Client

        client = Client(dask_scheduler, timeout="5s")
        workers = client.scheduler_info().get("workers", {})
        if not workers:
            return {
                "worker_count": 0,
                "status": "no_workers",
                "message": "No Dask workers connected.",
            }

        worker_addresses = list(workers.keys())
        futures = [
            client.submit(_verify_worker_rules, default_path, workers=[addr], pure=False) for addr in worker_addresses
        ]
        results = client.gather(futures)

        worker_report = {}
        for addr, res in zip(worker_addresses, results, strict=False):
            worker_report[addr] = res

        client.close()
        return {
            "worker_count": len(worker_report),
            "status": "synchronized",
            "workers": worker_report,
        }
    except Exception as exc:
        logger.warning(f"Could not contact Dask scheduler {dask_scheduler}: {exc}")
        return {
            "worker_count": 0,
            "status": "error",
            "error": str(exc),
        }
