# orochi/website/tasks.py
import contextlib
import logging
import os
import shutil
import time
from datetime import datetime
from glob import glob
from pathlib import Path
from zipfile import ZipFile

import requests
import urllib3
import volatility3.plugins
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.tasks import task
from extra_settings.models import Setting
from volatility3 import framework
from volatility3.framework import contexts

from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
)
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.models import Dump, Plugin, Result, SymbolStatus, UserPlugin
from orochi.website.notifications import send_external_notifications

logger = logging.getLogger(__name__)


def _send_task_notification(user, title, message, event_type="task"):
    try:
        channel_layer = get_channel_layer()
        if channel_layer:
            async_to_sync(channel_layer.group_send)(
                f"chat_{user.pk}",
                {
                    "type": "chat_message",
                    "message": f"{datetime.now()} || {message}",
                },
            )
        send_external_notifications(user, title, message, event_type=event_type)
    except Exception as exc:
        logger.warning(f"Failed to send notification to user {user}: {exc}")


@task(queue_name="default")
def sync_volatility_plugins():
    """
    Logic extracted from the management command.
    """
    start_time = time.time()
    logger.info("Starting sync_volatility_plugins")
    plugins = Plugin.objects.all()
    installed_plugins = {x.name for x in plugins}

    _ = contexts.Context()
    _ = framework.import_files(volatility3.plugins, True)
    available_plugins = {x: y for x, y in framework.list_plugins().items() if not x.startswith("volatility3.cli.")}

    # Disable obsolete plugins
    obsolete_plugins = []
    for plugin in plugins:
        if plugin.name not in available_plugins:
            logger.info(f"Disabling obsolete plugin: {plugin.name}")
            plugin.disabled = True
            obsolete_plugins.append(plugin)
    if obsolete_plugins:
        Plugin.objects.bulk_update(obsolete_plugins, ["disabled"])

    # Create/Update plugins
    new_plugins_count = 0
    new_results_count = 0
    for plugin_name, plugin_class in available_plugins.items():
        if plugin_name not in installed_plugins:
            logger.info(f"Installing new plugin: {plugin_name}")
            new_plugins_count += 1
            operating_system = "Other"
            if plugin_name.startswith("linux"):
                operating_system = "Linux"
            elif plugin_name.startswith("windows"):
                operating_system = "Windows"
            elif plugin_name.startswith("mac"):
                operating_system = "Mac"

            plugin = Plugin.objects.create(
                name=plugin_name,
                operating_system=operating_system,
                comment=plugin_class.__doc__,
            )

            dumps = Dump.objects.filter(operating_system__in=[operating_system, "Other"])
            if new_results := [Result(dump=dump, plugin=plugin, result=RESULT_STATUS_NOT_STARTED) for dump in dumps]:
                Result.objects.bulk_create(new_results)
                new_results_count += len(new_results)
        else:
            plugin = Plugin.objects.get(name=plugin_name)
            if not plugin.comment:
                plugin.comment = plugin_class.__doc__
                plugin.save()

    # Add new plugins to users
    all_plugins = list(Plugin.objects.all())
    existing_user_plugins = set(UserPlugin.objects.values_list("user_id", "plugin_id"))
    new_user_plugins = []
    for user in get_user_model().objects.all():
        new_user_plugins.extend(
            UserPlugin(user=user, plugin=plugin)
            for plugin in all_plugins
            if (user.id, plugin.id) not in existing_user_plugins
        )
    if new_user_plugins:
        UserPlugin.objects.bulk_create(new_user_plugins, ignore_conflicts=True)

    duration = time.time() - start_time
    logger.info(
        f"sync_volatility_plugins completed in {duration:.2f}s. "
        f"Disabled {len(obsolete_plugins)} obsolete, "
        f"Installed {new_plugins_count} new plugins, "
        f"Added {new_results_count} results, "
        f"Added {len(new_user_plugins)} user plugins."
    )
    return "Sync completed successfully"


@task(queue_name="default")
def sync_volatility_symbols():
    """
    Sync Volatility Symbols.
    """
    start_time = time.time()
    logger.info("Starting sync_volatility_symbols")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    local_path = Path(Setting.get("VOLATILITY_SYMBOL_PATH"))
    online_path = Setting.get("VOLATILITY_SYMBOL_DOWNLOAD_PATH")
    proxies = None
    if os.environ.get("http_proxy", None) or os.environ.get("https_proxy", None):
        proxies = {
            "http": os.environ.get("http_proxy", None),
            "https": os.environ.get("https_proxy", None),
        }
        logger.info(f"Using proxies: {proxies}")

    def get_hash_local():
        if not Path(local_path, "MD5SUMS").exists():
            return None
        hashes = {}
        with Path(local_path, "MD5SUMS").open() as f:
            for line in f.readlines():
                with contextlib.suppress(Exception):
                    parts = line.split()
                    hashes[parts[1]] = parts[0]
        return hashes

    def get_hash_online(store=False):
        r = requests.get(f"{online_path}/MD5SUMS", proxies=proxies, verify=False)
        if r.status_code == 200:
            if store:
                with Path(local_path, "MD5SUMS").open(mode="w") as f:
                    f.write(r.text)

            hashes = {}
            for line in r.text.split("\n"):
                with contextlib.suppress(Exception):
                    parts = line.split()
                    hashes[parts[1]] = parts[0]
            return hashes
        return None

    def remove(item):
        logger.info(f"Removing old symbol: {item}")
        path = os.path.join(local_path, item.split(".")[0])
        files = glob(f"{path}/*")
        for f in files:
            if os.path.basename(f) in ["__init__.py", "pe.json", "pdb.json", "kdbg.json"]:
                continue
            if os.path.isdir(f):
                shutil.rmtree(f)
            elif f.find("added") != -1:
                os.remove(f)

    def download(item):
        logger.info(f"Downloading symbol: {item}")
        r = requests.get(f"{online_path}/{item}", proxies=proxies, verify=False)
        local_path_file = Path("/tmp", item)
        if r.status_code == 200:
            with local_path_file.open(mode="wb") as f:
                f.write(r.content)
            with ZipFile(local_path_file, "r") as zipObj:
                for name in zipObj.namelist():
                    filetype = item.split(".")[0]
                    ok_path = Path(local_path, filetype) if name.split("/")[0] != filetype else Path(local_path)
                    zipObj.extract(name, ok_path)
            logger.info(f"Successfully downloaded symbol: {item}")
            return True
        return False

    hash_local = get_hash_local()
    hash_online = get_hash_online()

    changed = False

    if not hash_online:
        logger.error("Failed to download remote hashes")
        return "Failed to download remote hashes"

    for item in hash_online:
        if not hash_local or hash_local.get(item) != hash_online.get(item):
            changed = True
            remove(item)
            download(item)

    if changed:
        get_hash_online(store=True)
        framework.clear_cache()

    try:
        from orochi.website.symbols_assistant import (
            distribute_symbols_to_workers,
            ensure_symbol_environment,
        )

        ensure_symbol_environment()
        distribute_symbols_to_workers()
    except Exception as exc:
        logger.warning(f"Error distributing symbols after sync: {exc}")

    duration = time.time() - start_time
    logger.info(f"sync_volatility_symbols completed in {duration:.2f}s. Changes made: {changed}")
    return "Sync completed successfully"


@task(queue_name="default")
def build_cache_in_background():
    """
    Background task to generate the Volatility 3 ISF cache.
    Uses a distributed lock so that only one worker runs this at a time.
    """
    lock_id = "volatility3_cache_build_lock"

    # Acquire lock for 10 minutes (600s)
    if not cache.add(lock_id, "true", timeout=600):
        logger.debug("Cache build already in progress by another worker.")
        return

    try:
        from orochi.utils.volatility_dask_elk import refresh_symbols

        start_time = time.time()
        logger.info("Starting Volatility 3 cache generation in background task...")
        refresh_symbols()
        duration = time.time() - start_time
        logger.info(f"Volatility 3 cache generation completed in {duration:.2f}s.")
    except Exception as e:
        logger.error(f"Background cache creation failed: {e}")
    finally:
        cache.delete(lock_id)


@task(queue_name="default")
def download_symbols_task(
    url_list: list[str] | None = None,
    file_list: list[tuple[str, str]] | None = None,
    dump_pk: int | str | None = None,
    user_pk: int | str | None = None,
):
    """
    Download and compile Volatility 3 symbols in the background using Dask.
    Supports Linux kernel debug packages (deb, ddeb, rpm) compiled via dwarf2json,
    and Windows executable/PDB extraction.
    """
    start_time = time.time()
    logger.info(
        f"Starting download_symbols_task: dump={dump_pk}, user={user_pk}, "
        f"urls={len(url_list) if url_list else 0}, files={len(file_list) if file_list else 0}"
    )

    user = None
    if user_pk:
        with contextlib.suppress(Exception):
            user = get_user_model().objects.get(pk=user_pk)

    dump = None
    if dump_pk:
        with contextlib.suppress(Exception):
            dump = Dump.objects.get(pk=dump_pk)

    from orochi.utils.download_symbols import Downloader
    from orochi.utils.volatility_dask_elk import check_runnable, refresh_symbols
    from orochi.website.symbols_assistant import (
        distribute_symbols_to_workers,
        ensure_symbol_environment,
    )

    try:
        if url_list:
            d = Downloader(url_list=url_list)
            d.download_list()
        elif file_list:
            d = Downloader(file_list=file_list)
            d.process_list()
            for filepath, _ in file_list:
                if filepath and os.path.exists(filepath):
                    with contextlib.suppress(Exception):
                        os.unlink(filepath)
        else:
            logger.warning("download_symbols_task called without url_list or file_list")

        # 1. Distribute compiled symbols across workers and clear caches
        ensure_symbol_environment()
        distribute_symbols_to_workers()
        refresh_symbols()

        # 2. If tied to a dump, verify runnable status and update dump
        status_msg = "Symbols downloaded, compiled with DWARF-ISF, and distributed to workers."
        if dump:
            if check_runnable(dump.pk, dump.operating_system, dump.banner):
                dump.symbol_status = SymbolStatus.OK
                dump.status = DUMP_STATUS_COMPLETED
                dump.result_set.filter(result=RESULT_STATUS_DISABLED).update(result=RESULT_STATUS_NOT_STARTED)
                dump.save(update_fields=["symbol_status", "status"])
                status_msg = f"Symbols for dump <b>{dump.name}</b> compiled and verified successfully."
            else:
                status_msg = f"Symbols compiled for dump <b>{dump.name}</b>, but kernel banner was not satisfied."
                logger.warning(status_msg)

        duration = time.time() - start_time
        logger.info(f"download_symbols_task completed in {duration:.2f}s.")

        # 3. Notify user(s)
        if user:
            _send_task_notification(user, "Symbols Downloaded", status_msg, event_type="task")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "Symbols Downloaded", status_msg, event_type="task")

        return status_msg

    except Exception as exc:
        duration = time.time() - start_time
        err_msg = f"Symbol download/compilation failed: {exc}"
        logger.error(f"download_symbols_task failed after {duration:.2f}s: {exc}")

        if user:
            _send_task_notification(user, "Symbol Task Failed", err_msg, event_type="task")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "Symbol Task Failed", err_msg, event_type="task")

        raise


@task(queue_name="default")
def generate_dwarf_isf_task(
    elf_path: str,
    system_map_path: str | None = None,
    output_name: str | None = None,
    dump_pk: int | str | None = None,
    user_pk: int | str | None = None,
):
    """
    Executes dwarf2json linux directly on Dask workers to generate Volatility 3 ISF symbols
    from an uploaded vmlinux ELF and optional System.map (Issue #1554 / #272).
    """
    start_time = time.time()
    logger.info(f"Starting generate_dwarf_isf_task: elf={elf_path}, map={system_map_path}, dump={dump_pk}")

    user = None
    if user_pk:
        with contextlib.suppress(Exception):
            user = get_user_model().objects.get(pk=user_pk)

    dump = None
    if dump_pk:
        with contextlib.suppress(Exception):
            dump = Dump.objects.get(pk=dump_pk)

    from orochi.utils.download_symbols import Downloader
    from orochi.utils.volatility_dask_elk import check_runnable, refresh_symbols
    from orochi.website.symbols_assistant import (
        distribute_symbols_to_workers,
        ensure_symbol_environment,
    )

    try:
        downloader = Downloader()
        out_file = downloader.process_raw_kernel(
            elf_path=elf_path,
            system_map_path=system_map_path,
            output_name=output_name,
        )

        ensure_symbol_environment()
        dist_res = distribute_symbols_to_workers()
        refresh_symbols()

        status_msg = f"ISF symbol generated successfully ({os.path.basename(out_file)}) and distributed to {dist_res.get('worker_count', 0)} workers."
        if dump:
            if check_runnable(dump.pk, dump.operating_system, dump.banner):
                dump.symbol_status = SymbolStatus.OK
                dump.status = DUMP_STATUS_COMPLETED
                dump.result_set.filter(result=RESULT_STATUS_DISABLED).update(result=RESULT_STATUS_NOT_STARTED)
                dump.save(update_fields=["symbol_status", "status"])
                status_msg = f"Symbols for dump <b>{dump.name}</b> compiled and verified with dwarf2json!"
            else:
                status_msg = (
                    f"dwarf2json completed for <b>{dump.name}</b>, but kernel banner is still missing required symbols."
                )
                logger.warning(status_msg)

        duration = time.time() - start_time
        logger.info(f"generate_dwarf_isf_task finished in {duration:.2f}s.")

        if user:
            _send_task_notification(user, "dwarf2json Completed", status_msg, event_type="task")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "dwarf2json Completed", status_msg, event_type="task")

        return status_msg

    except Exception as exc:
        duration = time.time() - start_time
        err_msg = f"dwarf2json ISF generation failed: {exc}"
        logger.error(f"generate_dwarf_isf_task failed after {duration:.2f}s: {exc}")

        if user:
            _send_task_notification(user, "dwarf2json Failed", err_msg, event_type="task")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "dwarf2json Failed", err_msg, event_type="task")

        raise


@task(queue_name="default")
def run_playbook_task(dump_pk: int | str, playbook_id: str, user_pk: int | str | None = None):
    """
    Execute an incident response Auto-Triage Playbook on a Dump (Issue #1544).
    Orchestrates chained execution of Volatility plugins and evaluates triage findings.
    """
    start_time = time.time()
    logger.info(f"Starting run_playbook_task: dump_pk={dump_pk}, playbook_id={playbook_id}, user_pk={user_pk}")

    from orochi.api.routers.dumps import plugin_f_and_f
    from orochi.website.defaults import RESULT_STATUS_RUNNING
    from orochi.website.models import Dump, Result, Value
    from orochi.website.playbooks import get_playbook, resolve_playbook_plugins

    User = get_user_model()
    user = User.objects.filter(pk=user_pk).first() if user_pk else None
    dump = Dump.objects.filter(pk=dump_pk).first()

    if not dump:
        raise ValueError(f"Dump with primary key {dump_pk} does not exist.")

    playbook = get_playbook(playbook_id)
    if not playbook:
        raise ValueError(f"Playbook '{playbook_id}' not found.")

    if playbook["operating_system"].lower() != dump.operating_system.lower():
        raise ValueError(
            f"Playbook '{playbook['name']}' requires OS '{playbook['operating_system']}', "
            f"but dump is '{dump.operating_system}'."
        )

    plugins = resolve_playbook_plugins(dump, playbook)
    if not plugins:
        msg = f"No installed plugins found matching playbook '{playbook['name']}' for {dump.operating_system}."
        logger.warning(msg)
        if user:
            _send_task_notification(user, "Playbook Warning", msg, event_type="task")
        return {"dump_pk": dump.pk, "playbook_id": playbook_id, "launched_plugins": []}

    launched = []
    for plugin in plugins:
        result, _ = Result.objects.get_or_create(dump=dump, plugin=plugin)
        result.result = RESULT_STATUS_RUNNING
        result.description = None
        result.parameter = {}
        result.save(update_fields=["result", "description", "parameter"])
        Value.objects.filter(result=result).delete()

        try:
            plugin_f_and_f(dump, plugin, {}, user_pk)
            launched.append(plugin.name)
        except Exception as p_err:
            logger.error(f"Error launching plugin {plugin.name} in playbook {playbook_id}: {p_err}")

    # Initial triage evaluation
    try:
        evaluate_dump_triage(dump)
    except Exception as triage_err:
        logger.warning(f"Error updating triage during playbook run: {triage_err}")

    duration = time.time() - start_time
    notification_msg = (
        f"Playbook <b>{playbook['name']}</b> launched for dump <b>{dump.name}</b> "
        f"({len(launched)}/{len(plugins)} plugins queued in {duration:.2f}s)."
    )

    if user:
        _send_task_notification(user, "Playbook Launched", notification_msg, event_type="task")

    return {
        "dump_pk": dump.pk,
        "playbook_id": playbook_id,
        "playbook_name": playbook["name"],
        "launched_plugins": launched,
    }


# Aliases for backward compatibility with previously queued tasks
_build_cache_in_background = build_cache_in_background
_sync_volatility_symbols = sync_volatility_symbols
_sync_volatility_plugins = sync_volatility_plugins
download_symbols = download_symbols_task
_download_symbols_task = download_symbols_task
run_dwarf_task = generate_dwarf_isf_task
_generate_dwarf_isf_task = generate_dwarf_isf_task
_run_playbook_task = run_playbook_task
