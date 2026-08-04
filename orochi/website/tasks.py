# orochi/website/tasks.py
import contextlib
import logging
import os
import shutil
import tempfile
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

from orochi.website.defaults import RESULT_STATUS_NOT_STARTED
from orochi.website.models import Dump, Plugin, Result, UserPlugin

logger = logging.getLogger(__name__)


def _sync_volatility_plugins():
    """
    Logic extracted from the management command.
    """
    logger.info("Starting sync_volatility_plugins")
    plugins = Plugin.objects.all()
    installed_plugins = {x.name for x in plugins}

    _ = contexts.Context()
    _ = framework.import_files(volatility3.plugins, True)
    available_plugins = {
        x: y
        for x, y in framework.list_plugins().items()
        if not x.startswith("volatility3.cli.")
    }

    # Disable obsolete plugins
    for plugin in plugins:
        if plugin.name not in available_plugins:
            logger.info(f"Disabling obsolete plugin: {plugin.name}")
            plugin.disabled = True
            plugin.save()

    # Create/Update plugins
    for plugin_name, plugin_class in available_plugins.items():
        if plugin_name not in installed_plugins:
            logger.info(f"Installing new plugin: {plugin_name}")
            operating_system = "Other"
            if plugin_name.startswith("linux"):
                operating_system = "Linux"
            elif plugin_name.startswith("windows"):
                operating_system = "Windows"
            elif plugin_name.startswith("mac"):
                operating_system = "Mac"

            plugin = Plugin(
                name=plugin_name,
                operating_system=operating_system,
                comment=plugin_class.__doc__,
            )
            plugin.save()

            # Add new plugin to old dumps
            for dump in Dump.objects.filter(
                operating_system__in=[operating_system, "Other"]
            ):
                result, created = Result.objects.get_or_create(dump=dump, plugin=plugin)
                if created:
                    result.result = RESULT_STATUS_NOT_STARTED
                    result.save()
        else:
            plugin = Plugin.objects.get(name=plugin_name)
            if not plugin.comment:
                plugin.comment = plugin_class.__doc__
                plugin.save()

        # Add new plugin to users
        for user in get_user_model().objects.all():
            UserPlugin.objects.get_or_create(user=user, plugin=plugin)

    logger.info("sync_volatility_plugins completed successfully")
    return "Sync completed successfully"


sync_volatility_plugins = task(queue_name="default")(_sync_volatility_plugins)


def _sync_volatility_symbols():
    """
    Sync Volatility Symbols.
    """
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
            if os.path.isdir(f):
                shutil.rmtree(f)
            elif f.find("added") != -1:
                os.remove(f)

    def download(item):
        logger.info(f"Downloading symbol: {item}")
        r = requests.get(f"{online_path}/{item}", proxies=proxies, verify=False)
        if r.status_code == 200:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
                tmp.write(r.content)
                tmp_path = tmp.name
            try:
                with ZipFile(tmp_path, "r") as zipObj:
                    for name in zipObj.namelist():
                        filetype = item.split(".")[0]
                        ok_path = (
                            Path(local_path, filetype)
                            if name.split("/")[0] != filetype
                            else Path(local_path)
                        )
                        zipObj.extract(name, ok_path)
                logger.info(f"Successfully downloaded symbol: {item}")
                return True
            finally:
                os.remove(tmp_path)
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

    logger.info("sync_volatility_symbols completed successfully")
    return "Sync completed successfully"


sync_volatility_symbols = task(queue_name="default")(_sync_volatility_symbols)


def _build_cache_in_background():
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

        logger.info("Starting Volatility 3 cache generation in background task...")
        refresh_symbols()
        logger.info("Volatility 3 cache generation completed.")
    except Exception as e:
        logger.error(f"Background cache creation failed: {e}")
    finally:
        cache.delete(lock_id)


build_cache_in_background = task(queue_name="default")(_build_cache_in_background)
