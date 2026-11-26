# orochi/website/tasks.py
import contextlib
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime
from glob import glob
from pathlib import Path
from zipfile import ZipFile

import requests
import urllib3
import volatility3.plugins
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.tasks import task
from extra_settings.models import Setting
from volatility3 import framework
from volatility3.framework import contexts

from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    DUMP_STATUS_CREATED,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_SUCCESS,
)
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.models import Dump, Plugin, Result, SymbolStatus, UserPlugin
from orochi.website.notifications import send_external_notifications
from orochi.website.notifier import bold, notify_user

logger = logging.getLogger(__name__)


def _send_task_notification(user, title, message, event_type="task", kind="task"):
    """Toast ``message`` (HTML, dynamic values escaped by the caller) to the user and send it to external channels."""
    notify_user(user, message, html=True, kind=kind)
    try:
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
    summary = (
        f"Plugins sync completed in {duration:.2f}s: "
        f"Disabled {len(obsolete_plugins)} obsolete, "
        f"Installed {new_plugins_count} new plugins, "
        f"Added {new_results_count} results, "
        f"Added {len(new_user_plugins)} user plugins."
    )
    logger.info(summary)
    return summary


@task(queue_name="default")
def sync_volatility_symbols():
    """
    Sync Volatility Symbols.
    """
    start_time = time.time()
    logger.info("Starting sync_volatility_symbols")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    local_path = Path(Setting.get("VOLATILITY_SYMBOL_PATH"))
    online_path = Setting.get("VOLATILITY_SYMBOL_DOWNLOAD_PATH").rstrip("/")
    proxies = None
    if os.environ.get("http_proxy", None) or os.environ.get("https_proxy", None):
        proxies = {
            "http": os.environ.get("http_proxy", None),
            "https": os.environ.get("https_proxy", None),
        }
        logger.info(f"Using proxies: {proxies}")

    def get_hash_local():
        """Read the local ``MD5SUMS`` into ``{file: md5}``; ``None`` when it does not exist."""
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
        """Download the remote ``MD5SUMS`` (GitHub release URLs map to raw.githubusercontent.com).

        With ``store=True`` the file is also saved locally for the next comparison.
        """
        urls_to_try = [f"{online_path}/MD5SUMS"]

        # Support GitHub Releases: hashes are kept under raw.githubusercontent.com/.../symbols/MD5SUMS
        # e.g. https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/
        # -> https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/refs/tags/v0.0.1/symbols/MD5SUMS
        import re

        match = re.search(r"github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)", online_path)
        if match:
            owner, repo, tag = match.groups()
            urls_to_try.extend(
                [
                    f"https://raw.githubusercontent.com/{owner}/{repo}/refs/tags/{tag}/symbols/MD5SUMS",
                    f"https://raw.githubusercontent.com/{owner}/{repo}/refs/tags/{tag}/MD5SUMS",
                    f"https://raw.githubusercontent.com/{owner}/{repo}/{tag}/symbols/MD5SUMS",
                ]
            )

        for url in urls_to_try:
            try:
                r = requests.get(url, proxies=proxies, timeout=30)
                if r.status_code == 200:
                    if store:
                        with Path(local_path, "MD5SUMS").open(mode="w") as f:
                            f.write(r.text)

                    hashes = {}
                    for line in r.text.split("\n"):
                        with contextlib.suppress(Exception):
                            parts = line.split()
                            if len(parts) >= 2:
                                hashes[parts[1]] = parts[0]
                    if hashes:
                        logger.info(f"Loaded remote hashes from {url} ({len(hashes)} packages)")
                        return hashes
                logger.debug(f"Candidate MD5SUMS URL {url} returned HTTP {r.status_code}")
            except Exception as e:
                logger.debug(f"Candidate MD5SUMS URL {url} failed: {e}")

        logger.error(f"Failed to fetch remote hashes from any candidate URL for {online_path}")
        return None

    def remove(item):
        """Delete the extracted files of an outdated symbol pack, keeping the bundled base files."""
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
        """Download a symbol pack zip to a private temporary file and extract it into the symbol folder."""
        logger.info(f"Downloading symbol: {item}")
        url = f"{online_path}/{item}"
        try:
            r = requests.get(url, proxies=proxies, stream=True, timeout=120)
            if r.status_code == 200:
                # Private temporary file: no fixed /tmp name shared between processes
                with tempfile.NamedTemporaryFile(suffix=".zip") as tmp_zip:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            tmp_zip.write(chunk)
                    tmp_zip.flush()
                    with ZipFile(tmp_zip.name, "r") as zipObj:
                        for name in zipObj.namelist():
                            filetype = item.split(".")[0]
                            ok_path = Path(local_path, filetype) if name.split("/")[0] != filetype else Path(local_path)
                            zipObj.extract(name, ok_path)
                logger.info(f"Successfully downloaded and extracted symbol: {item}")
                return True
            logger.error(f"Failed to download symbol from {url}: HTTP {r.status_code}")
        except Exception as e:
            logger.error(f"Error downloading symbol {item} from {url}: {e}")
        return False

    hash_local = get_hash_local()
    hash_online = get_hash_online()

    changed = False

    if not hash_online:
        err_msg = f"Failed to download remote hashes from {online_path}/MD5SUMS"
        logger.error(err_msg)
        raise RuntimeError(err_msg)

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
    summary = f"Symbols sync completed in {duration:.2f}s: {len(hash_online)} symbol packages synchronized. Changes made: {changed}"
    logger.info(summary)
    return summary


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
    run_automatic: bool = False,
):
    """
    Download and compile Volatility 3 symbols in the background using Dask.
    Supports Linux kernel debug packages (deb, ddeb, rpm) compiled via dwarf2json,
    and Windows executable/PDB extraction.

    Progress is pushed to the user over WebSocket. With ``run_automatic`` and a dump whose banner is now satisfied,
    the user's automatic plugins are started on it.
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
        notify_symbols,
    )

    def progress(message: str) -> None:
        if dump is not None:
            notify_symbols(dump, message, user)
        elif user is not None:
            notify_user(user, message, kind="symbols")

    try:
        if url_list:
            d = Downloader(url_list=url_list, progress=progress)
            d.download_list()
        elif file_list:
            d = Downloader(file_list=file_list, progress=progress)
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
                status_msg = f"Symbols for dump {bold(dump.name)} compiled and verified successfully."
                if run_automatic:
                    from orochi.utils.volatility_dask_elk import (
                        dispatch_automatic_plugins,
                        mark_automatic_plugins,
                        trigger_auto_playbooks,
                    )

                    if count := mark_automatic_plugins(dump, user_pk):
                        # Processing until finalize_dump marks it Completed
                        dump.status = DUMP_STATUS_CREATED
                        dump.save(update_fields=["status"])
                        dispatch_automatic_plugins(dump, user_pk or dump.author_id)
                        status_msg += f" Running {count} automatic plugin(s)."
                    if launched := trigger_auto_playbooks(dump, user_pk or dump.author_id):
                        status_msg += f" Auto-run playbooks: {', '.join(launched)}."
            else:
                status_msg = f"Symbols compiled for dump {bold(dump.name)}, but kernel banner was not satisfied."
                logger.warning(status_msg)

        duration = time.time() - start_time
        logger.info(f"download_symbols_task completed in {duration:.2f}s.")

        # 3. Notify user(s)
        if user:
            _send_task_notification(user, "Symbols Downloaded", status_msg, event_type="task", kind="symbols")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "Symbols Downloaded", status_msg, event_type="task", kind="symbols")

        return status_msg

    except Exception as exc:
        duration = time.time() - start_time
        err_msg = f"Symbol download/compilation failed: {exc}"
        logger.error(f"download_symbols_task failed after {duration:.2f}s: {exc}")

        if user:
            _send_task_notification(user, "Symbol Task Failed", err_msg, event_type="task", kind="symbols")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "Symbol Task Failed", err_msg, event_type="task", kind="symbols")

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
                status_msg = f"Symbols for dump {bold(dump.name)} compiled and verified with dwarf2json!"
            else:
                status_msg = (
                    f"dwarf2json completed for {bold(dump.name)}, but kernel banner is still missing required symbols."
                )
                logger.warning(status_msg)

        duration = time.time() - start_time
        logger.info(f"generate_dwarf_isf_task finished in {duration:.2f}s.")

        if user:
            _send_task_notification(user, "dwarf2json Completed", status_msg, event_type="task", kind="symbols")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "dwarf2json Completed", status_msg, event_type="task", kind="symbols")

        return status_msg

    except Exception as exc:
        duration = time.time() - start_time
        err_msg = f"dwarf2json ISF generation failed: {exc}"
        logger.error(f"generate_dwarf_isf_task failed after {duration:.2f}s: {exc}")

        if user:
            _send_task_notification(user, "dwarf2json Failed", err_msg, event_type="task", kind="symbols")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "dwarf2json Failed", err_msg, event_type="task", kind="symbols")
        raise
    finally:
        # Clean up temporary multipart uploads under MEDIA_ROOT/uploads/dwarf
        from django.conf import settings as django_settings

        dwarf_tmp_root = (Path(django_settings.MEDIA_ROOT) / "uploads" / "dwarf").resolve()
        for temp_candidate in (elf_path, system_map_path):
            if not temp_candidate:
                continue
            with contextlib.suppress(Exception):
                cand_path = Path(temp_candidate).resolve()
                if cand_path.is_file() and dwarf_tmp_root in cand_path.parents:
                    cand_path.unlink(missing_ok=True)


@task(queue_name="default")
def generate_btf_isf_task(
    btf_path: str,
    system_map_path: str | None = None,
    banner: str | None = None,
    output_name: str | None = None,
    dump_pk: int | str | None = None,
    user_pk: int | str | None = None,
):
    """
    Executes btf2json directly on Dask workers to generate Volatility 3 ISF symbols
    from a BTF file (or stripped vmlinux), optional System.map, and optional Linux banner.
    """
    start_time = time.time()
    logger.info(f"Starting generate_btf_isf_task: btf={btf_path}, map={system_map_path}, dump={dump_pk}")

    user = None
    if user_pk:
        with contextlib.suppress(Exception):
            user = get_user_model().objects.get(pk=user_pk)

    dump = None
    if dump_pk:
        with contextlib.suppress(Exception):
            dump = Dump.objects.get(pk=dump_pk)

    effective_banner = banner.strip() if banner and banner.strip() else None
    if not effective_banner and dump and dump.banner:
        effective_banner = dump.banner.strip("\"' ")

    from orochi.utils.download_symbols import Downloader
    from orochi.utils.volatility_dask_elk import check_runnable, refresh_symbols
    from orochi.website.symbols_assistant import (
        distribute_symbols_to_workers,
        ensure_symbol_environment,
    )

    try:
        downloader = Downloader()
        out_file = downloader.process_btf_kernel(
            btf_path=btf_path,
            system_map_path=system_map_path,
            banner=effective_banner,
            output_name=output_name,
        )

        ensure_symbol_environment()
        dist_res = distribute_symbols_to_workers()
        refresh_symbols()

        status_msg = (
            f"BTF ISF symbol generated successfully ({os.path.basename(out_file)}) "
            f"and distributed to {dist_res.get('worker_count', 0)} workers."
        )
        if dump:
            if check_runnable(dump.pk, dump.operating_system, dump.banner):
                dump.symbol_status = SymbolStatus.OK
                dump.status = DUMP_STATUS_COMPLETED
                dump.result_set.filter(result=RESULT_STATUS_DISABLED).update(result=RESULT_STATUS_NOT_STARTED)
                dump.save(update_fields=["symbol_status", "status"])
                status_msg = f"Symbols for dump {bold(dump.name)} compiled and verified with btf2json!"
            else:
                status_msg = (
                    f"btf2json completed for {bold(dump.name)}, but kernel banner is still missing required symbols."
                )
                logger.warning(status_msg)

        duration = time.time() - start_time
        logger.info(f"generate_btf_isf_task finished in {duration:.2f}s.")

        if user:
            _send_task_notification(user, "btf2json Completed", status_msg, event_type="task", kind="symbols")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "btf2json Completed", status_msg, event_type="task", kind="symbols")

        return status_msg

    except Exception as exc:
        duration = time.time() - start_time
        err_msg = f"btf2json ISF generation failed: {exc}"
        logger.error(f"generate_btf_isf_task failed after {duration:.2f}s: {exc}")

        if user:
            _send_task_notification(user, "btf2json Failed", err_msg, event_type="task", kind="symbols")
        elif dump:
            from guardian.shortcuts import get_users_with_perms

            for u in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
                _send_task_notification(u, "btf2json Failed", err_msg, event_type="task", kind="symbols")
        raise
    finally:
        # Clean up temporary multipart uploads under MEDIA_ROOT/uploads/btf
        from django.conf import settings as django_settings

        btf_tmp_root = (Path(django_settings.MEDIA_ROOT) / "uploads" / "btf").resolve()
        for temp_candidate in (btf_path, system_map_path):
            if not temp_candidate:
                continue
            with contextlib.suppress(Exception):
                cand_path = Path(temp_candidate).resolve()
                if cand_path.is_file() and btf_tmp_root in cand_path.parents:
                    cand_path.unlink(missing_ok=True)


@task(queue_name="default")
def run_playbook_task(dump_pk: int | str, playbook_id: str, user_pk: int | str | None = None, force: bool = False):
    """
    Execute an incident response Auto-Triage Playbook on a Dump (Issue #1544).
    Orchestrates chained execution of Volatility plugins and evaluates triage findings.
    """
    start_time = time.time()
    logger.info(f"Starting run_playbook_task: dump_pk={dump_pk}, playbook_id={playbook_id}, user_pk={user_pk}")

    from orochi.api.routers.dumps import plugin_f_and_f
    from orochi.website.defaults import RESULT_STATUS_RUNNING
    from orochi.website.models import Dump, Result
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
            _send_task_notification(user, "Playbook Warning", msg, event_type="task", kind="playbook")
        return {"dump_pk": dump.pk, "playbook_id": playbook_id, "launched_plugins": []}

    from orochi.website.result_history import archive_and_clear

    launched = []
    skipped = []
    for plugin in plugins:
        result, _ = Result.objects.get_or_create(dump=dump, plugin=plugin)
        if result.result == RESULT_STATUS_SUCCESS and not force:
            # Completed results are kept: a playbook does not replace them unless forced (#1544, #1674)
            skipped.append(plugin.name)
            continue
        archive_and_clear(result, user_pk=user_pk, reason=f"playbook {playbook_id}")
        result.result = RESULT_STATUS_RUNNING
        result.description = None
        result.parameter = {}
        result.save(update_fields=["result", "description", "parameter"])

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
        f"Playbook {bold(playbook['name'])} launched for dump {bold(dump.name)} "
        f"({len(launched)}/{len(plugins)} plugins queued in {duration:.2f}s)."
        + (f" Already completed, kept: {', '.join(skipped)}." if skipped else "")
    )

    if user:
        _send_task_notification(user, "Playbook Launched", notification_msg, event_type="task", kind="playbook")

    return {
        "dump_pk": dump.pk,
        "playbook_id": playbook_id,
        "playbook_name": playbook["name"],
        "launched_plugins": launched,
        "kept_plugins": skipped,
    }


@task(queue_name="default")
def verify_dump_integrity_task(dump_pk: int | str, user_pk: int | str | None = None):
    """Re-hash a dump's memory image and kept original upload, record the check and notify the user (#1674)."""
    from orochi.website.integrity import verify_dump

    dump = Dump.objects.get(pk=dump_pk)
    user = get_user_model().objects.filter(pk=user_pk).first() if user_pk else None
    check = verify_dump(dump, user=user)
    if user:
        verdict = "verified: hashes match" if check.ok else "FAILED"
        _send_task_notification(
            user, "Integrity check", f"Dump {bold(dump.name)} {verdict}.", event_type="task", kind="dump"
        )
    return {"dump_pk": dump.pk, "ok": check.ok, "detail": check.detail}


@task(queue_name="default")
def purge_recycle_bin_task(days: int | None = None):
    """Purge the dumps whose recycle-bin retention has expired."""
    from orochi.website.recycle_bin import purge_expired

    return purge_expired(days)


# Aliases for backward compatibility with previously queued tasks
_build_cache_in_background = build_cache_in_background
_sync_volatility_symbols = sync_volatility_symbols
_sync_volatility_plugins = sync_volatility_plugins
download_symbols = download_symbols_task
_download_symbols_task = download_symbols_task
run_dwarf_task = generate_dwarf_isf_task
_generate_dwarf_isf_task = generate_dwarf_isf_task
_run_playbook_task = run_playbook_task


@task(queue_name="default")
def manage_upload_task(
    dump_pk: int | str,
    user_pk: int | str | None = None,
    password: str | None = None,
    restart: list | None = None,
    move: bool = False,
):
    """Enqueued wrapper task for memory dump extraction and ingestion."""
    from orochi.utils.volatility_dask_elk import manage_upload as run_manage_upload

    return run_manage_upload(
        dump_pk=int(dump_pk),
        user_pk=int(user_pk) if user_pk else None,
        password=password,
        restart=restart,
        move=move,
    )


manage_upload = manage_upload_task
_manage_upload = manage_upload_task


def _index_result_values_impl(result_pk: int | str):
    """Batch updates search vectors in background without blocking ingestion."""
    from django.contrib.postgres.search import SearchVector

    from orochi.website.models import Value

    count = Value.objects.filter(result_id=int(result_pk), search_vector__isnull=True).update(
        search_vector=SearchVector("value", config="english")
    )
    logger.info("Batch indexed %s Value rows for result %s", count, result_pk)
    return count


index_result_values_task = task(queue_name="default")(_index_result_values_impl)
_index_result_values_task = _index_result_values_impl
index_result_values = _index_result_values_impl


def _parse_forensic_timestamp(val):
    """Parse a plugin timestamp (datetime, ISO 8601 or ``YYYY-MM-DD HH:MM:SS[.f]`` with optional UTC/Z) as aware UTC datetime.

    Unparseable values give ``None``.
    """
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        val = val.strip()
        from django.utils import timezone

        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                clean_val = val.replace(" UTC", "").replace("Z", "").strip()
                dt = datetime.strptime(clean_val, fmt)
                return timezone.make_aware(dt, timezone.utc) if timezone.is_naive(dt) else dt
            except Exception:
                continue
        with contextlib.suppress(Exception):
            from django.utils.dateparse import parse_datetime

            return parse_datetime(val)
    return None


def _build_case_forensic_graph_impl(case_pk: int):
    """
    Extracts process lineage, network sockets, and injections across all dumps in a case.
    """
    from orochi.website.models import Case, Dump, ForensicEdge, ForensicNode, Result, Value

    case = Case.objects.get(pk=int(case_pk))
    dump_ids = set(case.evidences.filter(dump__isnull=False).values_list("dump_id", flat=True))
    if case.folder:
        dump_ids.update(Dump.objects.filter(folder=case.folder).values_list("pk", flat=True))

    dumps = Dump.objects.filter(pk__in=dump_ids)
    nodes_count = 0
    edges_count = 0

    node_map = {}  # canonical_id -> ForensicNode

    for dump in dumps:
        # 1. Process Nodes (pslist / pstree)
        ps_results = Result.objects.filter(dump=dump, plugin__name__icontains="pslist")
        parent_map = {}  # child_canon -> ppid

        for ps_res in ps_results:
            for val_obj in Value.objects.filter(result=ps_res):
                val = val_obj.value or {}
                pid = val.get("PID") or val.get("pid")
                if pid is None:
                    continue
                ppid = val.get("PPID") or val.get("ppid")
                image = val.get("ImageFileName") or val.get("Image") or val.get("Process") or f"PID {pid}"
                canon_id = f"dump:{dump.pk}|pid:{pid}"
                first_seen = _parse_forensic_timestamp(val.get("CreateTime") or val.get("Created"))

                node, _ = ForensicNode.objects.update_or_create(
                    case=case,
                    canonical_id=canon_id,
                    defaults={
                        "dump": dump,
                        "node_type": "process",
                        "label": f"{image} ({pid})",
                        "attributes": {
                            "pid": pid,
                            "ppid": ppid,
                            "image": image,
                            "dump_name": dump.name,
                            "dump_id": dump.pk,
                        },
                        "first_seen": first_seen,
                    },
                )
                node_map[canon_id] = node
                nodes_count += 1
                if ppid:
                    parent_map[canon_id] = (f"dump:{dump.pk}|pid:{ppid}", first_seen)

        # Process Spawns Edges
        for child_canon, (parent_canon, edge_time) in parent_map.items():
            if child_canon in node_map and parent_canon in node_map:
                ForensicEdge.objects.get_or_create(
                    case=case,
                    source=node_map[parent_canon],
                    target=node_map[child_canon],
                    edge_type="spawns",
                    defaults={"timestamp": edge_time},
                )
                edges_count += 1

        # 2. Network Sockets (netscan / netstat / sockscan)
        net_results = Result.objects.filter(dump=dump, plugin__name__iregex=r"(netscan|netstat|sockscan)")
        for net_res in net_results:
            for val_obj in Value.objects.filter(result=net_res):
                val = val_obj.value or {}
                foreign_addr = val.get("ForeignAddress") or val.get("ForeignAddr") or val.get("RemoteAddress")
                foreign_port = val.get("ForeignPort") or val.get("RemotePort")
                local_addr = val.get("LocalAddress") or val.get("LocalAddr")
                local_port = val.get("LocalPort")
                pid = val.get("PID") or val.get("pid")
                state = val.get("State") or "UNKNOWN"
                created = _parse_forensic_timestamp(val.get("Created") or val.get("CreateTime"))

                if foreign_addr and foreign_addr not in ("0.0.0.0", "::", "*", "-", ""):
                    sock_canon = f"socket:{foreign_addr}:{foreign_port}"
                    sock_node, _ = ForensicNode.objects.update_or_create(
                        case=case,
                        canonical_id=sock_canon,
                        defaults={
                            "dump": dump,
                            "node_type": "socket",
                            "label": f"{foreign_addr}:{foreign_port}",
                            "attributes": {
                                "foreign_address": str(foreign_addr),
                                "foreign_port": foreign_port,
                                "local_address": str(local_addr),
                                "local_port": local_port,
                                "state": state,
                                "dump_name": dump.name,
                            },
                            "first_seen": created,
                        },
                    )
                    node_map[sock_canon] = sock_node
                    nodes_count += 1

                    if pid:
                        proc_canon = f"dump:{dump.pk}|pid:{pid}"
                        if proc_canon in node_map:
                            ForensicEdge.objects.get_or_create(
                                case=case,
                                source=node_map[proc_canon],
                                target=sock_node,
                                edge_type="connects",
                                defaults={"timestamp": created, "metadata": {"state": state}},
                            )
                            edges_count += 1

        # 3. Memory Injections (malfind)
        mal_results = Result.objects.filter(dump=dump, plugin__name__icontains="malfind")
        for mal_res in mal_results:
            for val_obj in Value.objects.filter(result=mal_res):
                val = val_obj.value or {}
                pid = val.get("PID") or val.get("pid")
                start_vpn = val.get("Start VPN") or val.get("Start") or val.get("Address") or "unknown"
                if pid:
                    proc_canon = f"dump:{dump.pk}|pid:{pid}"
                    if proc_canon in node_map:
                        node_map[proc_canon].is_malicious = True
                        node_map[proc_canon].save(update_fields=["is_malicious"])

                    inj_canon = f"dump:{dump.pk}|malfind:{pid}:{start_vpn}"
                    inj_node, _ = ForensicNode.objects.update_or_create(
                        case=case,
                        canonical_id=inj_canon,
                        defaults={
                            "dump": dump,
                            "node_type": "file",
                            "label": f"Injected Code {pid} @ {start_vpn}",
                            "is_malicious": True,
                            "attributes": val,
                        },
                    )
                    node_map[inj_canon] = inj_node
                    nodes_count += 1

                    if proc_canon in node_map:
                        ForensicEdge.objects.get_or_create(
                            case=case,
                            source=node_map[proc_canon],
                            target=inj_node,
                            edge_type="injects",
                            defaults={"metadata": val},
                        )
                        edges_count += 1

    logger.info("Forensic graph generated for case %s: %s nodes, %s edges", case_pk, nodes_count, edges_count)
    return {"nodes": nodes_count, "edges": edges_count}


build_case_forensic_graph = task(queue_name="default")(_build_case_forensic_graph_impl)
_build_case_forensic_graph = _build_case_forensic_graph_impl
build_case_forensic_graph_task = build_case_forensic_graph
