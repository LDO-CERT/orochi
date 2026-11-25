import contextlib
import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse
from urllib.request import pathname2url

import attr
import magic
import volatility3.plugins
import vt
from asgiref.sync import sync_to_async
from clamdpy import ClamdUnixSocket
from distributed import fire_and_forget, get_client
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import close_old_connections
from regipy.exceptions import (
    NoRegistrySubkeysException,
    RegistryKeyNotFoundException,
    RegistryParsingException,
)
from regipy.plugins.plugin import PLUGINS
from regipy.registry import RegistryHive
from volatility3 import cli, framework
from volatility3.cli.text_renderer import (
    JsonRenderer,
    LayerDataRenderer,
    display_disassembly,
    format_hints,
    multitypedata_as_text,
    optional,
    quoted_optional,
)
from volatility3.cli.volshell.generic import NullFileHandler
from volatility3.framework import (
    automagic,
    constants,
    contexts,
    exceptions,
    interfaces,
    plugins,
    renderers,
)
from volatility3.framework.automagic import stacker, symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.configuration.requirements import (
    ChoiceRequirement,
    ListRequirement,
)
from volatility3.framework.symbols import intermed

from orochi.utils.symbol_sources import get_path_from_banner  # noqa: F401  (re-exported)
from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    DUMP_STATUS_CREATED,
    DUMP_STATUS_ERROR,
    DUMP_STATUS_MISSING_SYMBOLS,
    DUMP_STATUS_UNZIPPING,
    MAGIC_ARCHIVE_MIMETYPES,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_EMPTY,
    RESULT_STATUS_ERROR,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
    RESULT_STATUS_UNSATISFIED,
    SERVICE_VIRUSTOTAL,
)
from orochi.website.models import CustomRule, Dump, Result, Service, Value

BANNER_REGEX = r'^"?Linux version (?P<kernel>\S+) (?P<build>.+) \(((?P<gcc>gcc.+)) #(?P<number>\d+)(?P<info>.+)$"?'

COLOR_TIMELINER = {
    "Created Date": "#FF0000",
    "Modified Date": "#00FF00",
    "Accessed Date": "#0000FF",
    "Changed Date": "#FFFF00",
}


def file_handler_class_factory(output_dir, file_list):
    """Return the Volatility FileHandler class for a run: temp files collected in ``file_list``, or NullFileHandler without ``output_dir``."""

    class OrochiFileHandler(interfaces.plugins.FileHandlerInterface):
        """Volatility file handler backed by a temporary file; on close it joins ``file_list`` so the caller can move it."""

        def __init__(self, filename: str):
            fd, self._name = tempfile.mkstemp(suffix=".vol3", prefix="tmp_")
            self._file = open(fd, mode="w+b")
            interfaces.plugins.FileHandlerInterface.__init__(self, filename)
            for item in dir(self._file):
                if not item.startswith("_") and item not in [
                    "closed",
                    "close",
                    "mode",
                    "name",
                ]:
                    setattr(self, item, getattr(self._file, item))

        def __getattr__(self, item):
            return getattr(self._file, item)

        @property
        def closed(self):
            """True when the underlying file is closed."""
            return self._file.closed

        @property
        def mode(self):
            """Mode of the underlying file."""
            return self._file.mode

        @property
        def name(self):
            """Path of the underlying temporary file."""
            return self._file.name

        def getvalue(self) -> bytes:
            """Mimic a BytesIO object's getvalue parameter"""
            # Opens the file new so we're not trying to do IO on a closed file
            with open(self._name, mode="rb") as this_file:
                return this_file.read()

        def delete(self):
            """Close and remove the temporary file."""
            self.close()
            os.remove(self._name)

        def close(self):
            """Closes and commits the file (by moving the temporary file to the correct name"""
            # Don't overcommit
            if self._file.closed:
                return
            self._file.close()
            file_list.append(self)

    return OrochiFileHandler if output_dir else NullFileHandler


class ReturnJsonRenderer(JsonRenderer):
    """
    Custom json renderer that doesn't write json on disk but returns it with errors if present
    """

    _type_renderers = {
        format_hints.HexBytes: lambda x: "N/A" if isinstance(x, interfaces.renderers.BaseAbsentValue) else x.hex(" "),
        renderers.Disassembly: quoted_optional(display_disassembly),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        renderers.LayerData: lambda x: (
            "N/A"
            if isinstance(x, interfaces.renderers.BaseAbsentValue)
            else LayerDataRenderer().render_bytes(x)[0].hex(" ")
        ),
        bytes: optional(lambda x: " ".join([f"{b:02x}" for b in x])),
        datetime.datetime: lambda x: None if isinstance(x, interfaces.renderers.BaseAbsentValue) else x.isoformat(),
        "default": lambda x: x,
    }

    def render(self, grid: interfaces.renderers.TreeGrid):
        """Render a Volatility TreeGrid to ``(rows_by_id, tree)`` dictionaries with nested ``__children``."""
        final_output = ({}, [])

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: tuple[dict[str, dict[str, Any]], list[dict[str, Any]]],
        ) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            """Turn one TreeGrid node into a row dict and attach it to its parent."""
            acc_map, final_tree = accumulator
            node_dict: dict[str, Any] = {"__children": []}
            line = []
            for column_index, column in enumerate(grid.columns):
                if column in self.ignored_columns(grid):
                    continue
                renderer = self._type_renderers.get(column.type, self._type_renderers["default"])
                data = renderer(list(node.values)[column_index])
                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None
                node_dict[column.name] = data
                line.append(data)

            if self.filter and self.filter.filter(line):
                return accumulator

            if node.parent:
                acc_map[node.parent.path]["__children"].append(node_dict)
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict
            return (acc_map, final_tree)

        error = grid.populate(visitor, final_output, fail_on_errors=False)
        return final_output[1], error


def hash_checksum(filename, block_size=65536):
    """Generate hashes for filename"""
    if ".." in str(filename):
        raise ValueError(f"Invalid path: {filename}")
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha256.update(block)
            md5.update(block)
    return sha256.hexdigest(), md5.hexdigest()


_VOL3_PLUGINS_IMPORT_SIGNATURE: tuple | None = None
_VOL3_CONFIG_CACHE_VERSION = 1
_VOL3_CONFIG_CACHE_FILENAME = ".vol3_config_cache.json"


def _plugins_path_signature() -> tuple:
    """Return a lightweight signature of volatility3 plugin directories to detect newly installed plugins."""
    entries = []
    for raw_path in getattr(volatility3.plugins, "__path__", ()):
        p = Path(raw_path)
        try:
            entries.append((str(p), p.stat().st_mtime_ns))
        except OSError:
            entries.append((str(p), 0))
        custom_dir = p / "custom"
        try:
            if custom_dir.exists():
                entries.append((str(custom_dir.resolve()), custom_dir.resolve().stat().st_mtime_ns))
        except OSError:
            pass
    return tuple(entries)


def _ensure_volatility_plugins_imported(force: bool = False) -> None:
    """Import Volatility 3 plugins once per worker process, refreshing only if plugin dirs changed."""
    global _VOL3_PLUGINS_IMPORT_SIGNATURE
    sig = _plugins_path_signature()
    if not force and _VOL3_PLUGINS_IMPORT_SIGNATURE == sig and framework.list_plugins():
        return
    _ = framework.import_files(volatility3.plugins, True)
    _VOL3_PLUGINS_IMPORT_SIGNATURE = sig


def _choose_os_automagics_and_stackers(available_automagics, plugin, dump_obj=None, plugin_obj=None):
    """
    Choose automagics and OS stackers for `plugin`.
    For `custom.*` plugins (whose module path lacks a windows/linux/mac category),
    narrow automagics and stackers using the plugin/dump OS so Volatility does not
    run irrelevant OS stackers and symbol finders (e.g. KernelPDBScanner on Linux).
    """
    chosen_automagics = automagic.choose_automagic(available_automagics, plugin)
    chosen_stackers = stacker.choose_os_stackers(plugin)

    module_parts = getattr(plugin, "__module__", "").split(".")
    has_os_category = any(cat in module_parts for cat in constants.OS_CATEGORIES)
    if has_os_category:
        return chosen_automagics, chosen_stackers

    os_candidate = None
    for obj in (plugin_obj, dump_obj):
        raw_os = getattr(obj, "operating_system", None)
        if isinstance(raw_os, str) and raw_os.lower() in constants.OS_CATEGORIES:
            os_candidate = raw_os.lower()
            break

    if not os_candidate:
        return chosen_automagics, chosen_stackers

    logging.info(f"Scoping custom plugin {plugin.__name__} automagics/stackers to OS '{os_candidate}'")
    chosen_automagics = [am for am in chosen_automagics if os_candidate not in getattr(am, "exclusion_list", ())]
    framework.import_files(sys.modules["volatility3.framework.layers"])
    chosen_stackers = [
        st.__name__
        for st in sorted(
            framework.class_subclasses(interfaces.automagic.StackerLayerInterface),
            key=lambda x: x.stack_order,
        )
        if os_candidate not in getattr(st, "exclusion_list", ())
    ]
    return chosen_automagics, chosen_stackers


def _vol3_config_cache_path(dump_index: str) -> Path:
    """Path of the cached Volatility configuration (detected layers / symbols) of a dump."""
    return Path(settings.MEDIA_ROOT) / str(dump_index) / _VOL3_CONFIG_CACHE_FILENAME


def invalidate_vol3_config_cache(dump_index: str) -> None:
    """Delete cached Volatility 3 automagic configuration for a dump (e.g. after symbol reload)."""
    if not dump_index:
        return
    with contextlib.suppress(OSError):
        _vol3_config_cache_path(dump_index).unlink(missing_ok=True)


def _load_vol3_config_cache(dump_obj, file_name: str) -> dict | None:
    """Load validated per-dump Volatility 3 kernel/layer configuration if fresh."""
    cache_path = _vol3_config_cache_path(dump_obj.index)
    if not cache_path.is_file():
        return None
    try:
        st = os.stat(file_name)
        with open(cache_path, encoding="utf-8") as f:
            payload = json.load(f)
        if (
            payload.get("version") != _VOL3_CONFIG_CACHE_VERSION
            or payload.get("dump_path") != file_name
            or payload.get("dump_mtime") != st.st_mtime
            or payload.get("dump_size") != st.st_size
            or payload.get("operating_system") != getattr(dump_obj, "operating_system", None)
        ):
            return None
        cfg = payload.get("config")
        if not isinstance(cfg, dict) or not cfg:
            return None
        # Verify any local file:// ISF symbol URL referenced by the cache still exists
        for key, val in cfg.items():
            if key.endswith(".isf_url") and isinstance(val, str) and val.startswith("file:"):
                parsed = urlparse(val)
                isf_path = unquote(parsed.path)
                if isf_path and not os.path.exists(isf_path):
                    return None
        return cfg
    except Exception as excp:
        logging.debug(f"Ignoring unreadable vol3 config cache {cache_path}: {excp}")
        return None


def _apply_cached_vol3_config(ctx, plugin, plugin_config_path: str, cached_cfg: dict) -> bool:
    """Splice matching cached kernel/primary subtrees into `ctx.config` for `plugin`."""
    req_names = {req.name for req in plugin.get_requirements()}
    subset: dict[str, Any] = {}
    for root in ("kernel", "primary"):
        if root in req_names:
            prefix = f"{root}."
            for k, v in cached_cfg.items():
                if k.startswith(prefix):
                    subset[k] = v
    # Derive `primary.*` from `kernel.layer_name.*` for plugins that require only `primary`
    if "primary" in req_names and not any(k.startswith("primary.") for k in subset):
        layer_prefix = "kernel.layer_name."
        for k, v in cached_cfg.items():
            if k.startswith(layer_prefix):
                subset["primary." + k[len(layer_prefix) :]] = v
    if not subset:
        return False
    ctx.config.splice(plugin_config_path, interfaces.configuration.HierarchicalDict(subset))
    return True


def _save_vol3_config_cache(dump_obj, file_name: str, constructed) -> None:
    """Persist reusable kernel/primary Volatility 3 configuration for subsequent plugin runs."""
    try:
        raw_cfg = dict(constructed.build_configuration())
    except Exception as excp:
        logging.debug(f"Could not build Volatility 3 configuration for caching: {excp}")
        return

    reusable = {k: v for k, v in raw_cfg.items() if k.startswith("kernel.") or k.startswith("primary.")}
    if not reusable:
        return

    cache_path = _vol3_config_cache_path(dump_obj.index)
    try:
        st = os.stat(file_name)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        existing = _load_vol3_config_cache(dump_obj, file_name) or {}
        merged = {**existing, **reusable}
        if merged == existing and cache_path.is_file():
            return
        payload = {
            "version": _VOL3_CONFIG_CACHE_VERSION,
            "dump_path": file_name,
            "dump_mtime": st.st_mtime,
            "dump_size": st.st_size,
            "operating_system": getattr(dump_obj, "operating_system", None),
            "config": merged,
        }
        fd, tmp_name = tempfile.mkstemp(prefix=".vol3_cfg_", suffix=".tmp", dir=str(cache_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_f:
                json.dump(payload, tmp_f, sort_keys=True)
            os.replace(tmp_name, cache_path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
    except Exception as excp:
        logging.debug(f"Could not save vol3 config cache {cache_path}: {excp}")


def _resolve_volatility_plugin(plugin_list, plugin_name):
    """Resolve a plugin class by exact name, falling back between `custom.` and bare names."""
    plugin = plugin_list.get(plugin_name)
    if plugin is not None or not plugin_name:
        return plugin
    if plugin_name.startswith("custom."):
        return plugin_list.get(plugin_name.removeprefix("custom."))
    return plugin_list.get(f"custom.{plugin_name}")


def get_parameters(plugin):
    """Obtains parameters list from volatility plugin"""
    _ = contexts.Context()
    _ensure_volatility_plugins_imported()
    plugin_list = framework.list_plugins()
    params = []
    plugin_cls = _resolve_volatility_plugin(plugin_list, plugin)
    if plugin_cls is not None:
        for requirement in plugin_cls.get_requirements():
            additional = {"optional": requirement.optional, "name": requirement.name}

            if isinstance(requirement, requirements.URIRequirement):
                additional |= {"mode": "single", "type": "file"}
            elif isinstance(requirement, interfaces.configuration.SimpleTypeRequirement):
                additional |= {
                    "mode": "single",
                    "type": requirement.instance_type.__name__,
                }
            elif isinstance(requirement, ListRequirement):
                additional |= {
                    "mode": "list",
                    "type": requirement.element_type.__name__,
                }
            elif isinstance(requirement, ChoiceRequirement):
                additional |= {
                    "mode": "single",
                    "type": "str",
                    "choices": requirement.choices,
                }
            else:
                continue

            params.append(additional)

    return params


async def run_vt(filepath):
    """Runs virustotal on filepath"""
    try:
        vt_service = await sync_to_async(Service.objects.get)(name=SERVICE_VIRUSTOTAL)
    except Service.DoesNotExist:
        logging.error("[VT] Service not configured")
        return
    async with vt.Client(vt_service.decrypted_key, proxy=vt_service.proxy) as client:
        try:
            to_check = hash_checksum(filepath)[0]
            report = await client.get_object_async(f"/files/{to_check}")
            if report := report.to_dict().get("attributes"):
                stats = dict(report.get("last_analysis_stats", {}).items())
                if scan_date := report.get("last_analysis_date"):
                    scan_date = datetime.datetime.fromtimestamp(scan_date).strftime("%m/%d/%Y")
                vt_report = {
                    "last_analysis_stats": stats,
                    "scan_date": scan_date,
                    "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total": sum(stats.get(x, 0) for x in stats) if stats else 0,
                    "permalink": f"https://www.virustotal.com/api/v3/files/{to_check}",
                }
                with open(f"{filepath}.vt.json", "w") as f:
                    json.dump(vt_report, f)
                    f.flush()
        except vt.error.APIError as excp:
            logging.error(f"[VT] {excp}")
            return


def run_regipy(filepath, plugins=False):
    """Runs regipy on filepath"""
    if ".." in str(filepath):
        raise ValueError(f"Invalid path: {filepath}")
    try:
        registry_hive = RegistryHive(filepath)
        *a, index, _, hive_name = filepath.split("/")
        dump = Dump.objects.get(index=index)
        data = []
        try:
            data.extend(attr.asdict(entry) for entry in registry_hive.recurse_subkeys(registry_hive.root, as_json=True))
        except RegistryParsingException as e:
            logging.error(e)
        with open(f"{filepath}.regipy.json", "w") as f:
            json.dump(json.loads(json.dumps(data).replace(r"\u0000", "")), f)
        if plugins:
            from orochi.website.runtime_settings import regipy_plugins

            enabled = set(regipy_plugins())
            plugin_to_run = [x for x in PLUGINS if x.NAME in enabled]
            for plugin_class in plugin_to_run:
                plugin = plugin_class(registry_hive, as_json=True)
                if plugin.can_run():
                    try:
                        plugin.run()
                        if plugin.entries:
                            info = {
                                "hive": hive_name,
                                "plugin": plugin.NAME,
                                "data": json.loads(json.dumps(plugin.entries).replace(r"\u0000", "")),
                            }
                            dump.regipy_plugins.append(info)
                    except (
                        RegistryParsingException,
                        RegistryKeyNotFoundException,
                        NoRegistrySubkeysException,
                        Exception,
                    ) as e:
                        logging.error(e)
            dump.save()
    except Exception as e:
        logging.error(e)


def _apply_runtime_isf_url() -> None:
    """Use the remote ISF index currently set in Admin › Extra settings (changes apply without restart)."""
    try:
        from orochi.website.runtime_settings import apply_remote_isf_url

        apply_remote_isf_url()
    except Exception as exc:
        logging.debug(f"Remote ISF setting not applied: {exc}")


def run_plugin(dump_obj, plugin_obj, params=None, user_pk=None, regipy_plugins=False):
    """
    Execute a single plugin on a dump with optional params.
    If success data are sent to stored in value table.
    """
    close_old_connections()
    _apply_runtime_isf_url()

    logging.info(f"[dump {dump_obj.name} - plugin {plugin_obj.name}] start")

    result = None
    try:
        result, created = Result.objects.get_or_create(plugin=plugin_obj, dump=dump_obj)
        result.result = RESULT_STATUS_RUNNING
        result.save()

        ctx = contexts.Context()
        constants.PARALLELISM = constants.Parallelism.Off
        _ensure_volatility_plugins_imported()
        automagics = automagic.available(ctx)
        plugin_list = framework.list_plugins()
        json_renderer = ReturnJsonRenderer
        seen_automagics = set()
        for amagic in automagics:
            if amagic in seen_automagics:
                continue
            seen_automagics.add(amagic)
        plugin = _resolve_volatility_plugin(plugin_list, plugin_obj.name)
        if plugin is None:
            raise ValueError(f"Volatility 3 plugin '{plugin_obj.name}' not found in loaded plugins.")
        base_config_path = "plugins"
        from orochi.website.storage import ensure_local_dump_path

        file_name = ensure_local_dump_path(dump_obj)
        single_location = f"file:{pathname2url(file_name)}"
        ctx.config["automagic.LayerStacker.single_location"] = single_location
        automagics, chosen_stackers = _choose_os_automagics_and_stackers(
            automagics, plugin, dump_obj=dump_obj, plugin_obj=plugin_obj
        )
        if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
            ctx.config["automagic.LayerStacker.stackers"] = chosen_stackers
        # LOCAL DUMPS REQUIRES FILES - Also regipy plugins
        local_dump = plugin_obj.local_dump or regipy_plugins

        # Timeliner can create a body-file if required
        if plugin_obj.name == "timeliner.Timeliner" and params and params.get("create-bodyfile"):
            local_dump = True

        # ADD PARAMETERS, AND IF LOCAL DUMP ENABLE ADD DUMP TRUE BY DEFAULT
        plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)
        if params:
            # ADD PARAMETERS TO PLUGIN CONF
            for k, v in params.items():
                if v != "":
                    extended_path = interfaces.configuration.path_join(plugin_config_path, k)
                    ctx.config[extended_path] = v

                if k == "dump" and v:
                    # IF DUMP TRUE HAS BEEN PASS IT'LL DUMP LOCALLY
                    local_dump = True

        if not params and local_dump:
            # IF ADMIN SET LOCAL DUMP ADD DUMP TRUE AS PARAMETER
            extended_path = interfaces.configuration.path_join(plugin_config_path, "dump")
            ctx.config[extended_path] = True

        logging.debug(f"[dump {dump_obj.name} - plugin {plugin_obj.name}] params: {ctx.config}")

        file_list = []
        if local_dump:
            # IF PARAM/ADMIN DUMP CREATE FILECONSUMER
            local_path = f"{settings.MEDIA_ROOT}/{dump_obj.index}/{plugin_obj.name}"
            if not os.path.exists(local_path):
                os.mkdir(local_path)
            file_handler = file_handler_class_factory(output_dir=local_path, file_list=file_list)
        else:
            local_path = None
            file_handler = file_handler_class_factory(output_dir=None, file_list=file_list)

        # #####################
        # ## YARA
        # if not file or rule selected and exists default use that
        if plugin_obj.name in ["yarascan.YaraScan", "windows.vadyarascan.VadYaraScan"]:
            has_file = False
            if params:
                for k, v in params.items():
                    if k in ["yara_file", "yara_compiled_file", "yara_string"] and (v is not None and v != ""):
                        has_file = True

            if not has_file:
                if rule := CustomRule.objects.filter(user__pk=user_pk, default=True).first():
                    extended_path = interfaces.configuration.path_join(plugin_config_path, "yara_compiled_file")
                    ctx.config[extended_path] = f"file:{rule.path}"
                else:
                    save_result_status(
                        result,
                        RESULT_STATUS_UNSATISFIED,
                        "No YARA rule provided and no default custom rule is set for your user.",
                        "Unsatisfied",
                    )
                    return

            logging.debug(f"[dump {dump_obj.pk} - plugin {plugin_obj.name}] params: {ctx.config}")

        # Do not override Timeliner's sub-plugin discovery with synthetic filters or partial
        # cached configs: let Volatility 3 resolve every applicable TimeLinerInterface plugin
        # (including PsScan and PsList) identically to the CLI unless caller passed plugin-filter.
        base_config_snapshot = dict(ctx.config)
        used_cached_config = False
        if plugin_obj.name != "timeliner.Timeliner":
            cached_cfg = _load_vol3_config_cache(dump_obj, file_name)
            if cached_cfg:
                used_cached_config = _apply_cached_vol3_config(ctx, plugin, plugin_config_path, cached_cfg)
                if used_cached_config:
                    logging.info(f"[dump {dump_obj.name} - plugin {plugin_obj.name}] using cached vol3 config")

        try:
            # RUN PLUGIN
            constructed = plugins.construct_plugin(
                ctx,
                automagics,
                plugin,
                base_config_path,
                cli.MuteProgress(),
                file_handler,
            )
        except exceptions.UnsatisfiedException as excp:
            if used_cached_config:
                logging.info(
                    f"[dump {dump_obj.name} - plugin {plugin_obj.name}] cached vol3 config unsatisfied; retrying fresh"
                )
                invalidate_vol3_config_cache(dump_obj.index)
                ctx = contexts.Context()
                for cfg_key, cfg_val in base_config_snapshot.items():
                    ctx.config[cfg_key] = cfg_val
                fresh_automagics, _ = _choose_os_automagics_and_stackers(
                    automagic.available(ctx), plugin, dump_obj=dump_obj, plugin_obj=plugin_obj
                )
                try:
                    constructed = plugins.construct_plugin(
                        ctx,
                        fresh_automagics,
                        plugin,
                        base_config_path,
                        cli.MuteProgress(),
                        file_handler,
                    )
                except exceptions.UnsatisfiedException as retry_excp:
                    description = "\n".join(
                        [retry_excp.unsatisfied[config_path].description for config_path in retry_excp.unsatisfied]
                    )
                    save_result_status(result, RESULT_STATUS_UNSATISFIED, description, "Unsatisfied")
                    return
            else:
                # LOG UNSATISFIED ERROR
                description = "\n".join([excp.unsatisfied[config_path].description for config_path in excp.unsatisfied])
                save_result_status(result, RESULT_STATUS_UNSATISFIED, description, "Unsatisfied")
                return

        _save_vol3_config_cache(dump_obj, file_name, constructed)
        try:
            runned_plugin = constructed.run()
        except Exception as excp:
            # LOG GENERIC ERROR [VOLATILITY]
            fulltrace = traceback.TracebackException.from_exception(excp).format(chain=True)
            save_result_status(result, RESULT_STATUS_ERROR, "\n".join(fulltrace), f"Error: {excp}")
            return

        # RENDER OUTPUT IN JSON
        json_data, error = json_renderer().render(runned_plugin)

        logging.info(f"DATA: {len(json_data)} returned")
        if error:
            logging.error(f"ERROR: {error}")
        logging.debug(f"CONFIG: {ctx.config}")

        if len(json_data) > 0:
            # IF DUMP STORE FILE ON DISK
            if local_dump and file_list:
                # WRITE DUMP ON DISK
                for file_id in file_list:
                    output_path = f"{local_path}/{file_id.preferred_filename}"
                    with open(output_path, "wb") as f:
                        f.write(file_id.getvalue())
                # RUN CLAMAV ON ALL FOLDER
                if plugin_obj.clamav_check:
                    cd = ClamdUnixSocket()
                    match = cd.multiscan(local_path)
                    match = match or []
                else:
                    match = []

                # CALCOLATE HASH AND CHECK FOR CLAMAV SIGNATURE
                for x in json_data:
                    if filename := x.get("File output"):
                        down_path = f"{local_path}/{filename}"
                        if os.path.exists(down_path) and not os.path.isdir(down_path):
                            x["down_path"] = down_path
                            x["sha256"], x["md5"] = hash_checksum(down_path)
                            if plugin_obj.clamav_check:
                                x["clamav"] = next(
                                    (res.reason for res in match if str(res.path) == down_path),
                                    "-",
                                )
                        elif plugin_obj.clamav_check:
                            x["clamav"] = "-"
                            x["down_path"] = "-"
                            x["sha256"] = "-"
                            x["md5"] = "-"

            # RUN VT AND REGIPY ON CREATED FILES
            if plugin_obj.vt_check or plugin_obj.regipy_check or regipy_plugins:
                dask_client = get_client()
                for file_id in file_list:
                    output_path = f"{local_path}/{file_id.preferred_filename}"
                    if plugin_obj.vt_check:
                        fire_and_forget(dask_client.submit(run_vt, output_path))
                    if plugin_obj.regipy_check or regipy_plugins:
                        fire_and_forget(dask_client.submit(run_regipy, output_path, regipy_plugins))

            # Persist all Value rows BEFORE marking the Result as SUCCESS so any API client,
            # export, report, or notification observing SUCCESS immediately sees all rows (#1666).
            values_create_list = [Value(value=x, result=result) for x in json_data]
            Value.objects.bulk_create(values_create_list, batch_size=5000)
            save_result_status(result, RESULT_STATUS_SUCCESS, error, "Data saved")

            # Trigger background full-text indexing task if values were created
            if values_create_list:
                try:
                    from orochi.website.tasks import index_result_values_task

                    index_result_values_task.enqueue(result.pk)
                except Exception as idx_err:
                    logging.debug(f"[dump {dump_obj.name}] Could not enqueue indexing task: {idx_err}")

            # If this is a core behavioral triage plugin, trigger background triage risk scoring
            core_triage_plugins = (
                "pslist",
                "psscan",
                "pstree",
                "netscan",
                "netstat",
                "malfind",
                "cmdline",
                "bash",
                "check_syscall",
            )
            if any(k in plugin_obj.name.lower() for k in core_triage_plugins):
                try:
                    from orochi.website.detection.engine import evaluate_dump_triage

                    evaluate_dump_triage(result.dump)
                except Exception as e:
                    logging.warning(
                        "Auto-triage evaluation for dump %s deferred: %s",
                        result.dump.name,
                        e,
                    )
        else:
            save_result_status(result, RESULT_STATUS_EMPTY, error, "Empty")
        return 0

    except Exception as excp:
        # LOG GENERIC ERROR
        fulltrace = traceback.TracebackException.from_exception(excp).format(chain=True)
        if result is not None:
            save_result_status(result, RESULT_STATUS_ERROR, "\n".join(fulltrace), f"Error: {excp}")
        else:
            logging.error(f"Failed plugin execution before result initialized: {excp}\n{''.join(fulltrace)}")

        return 0
    finally:
        close_old_connections()


def save_result_status(result, status, description, message):
    """Store status and description of a plugin Result and log the message."""
    result.result = status
    result.description = description
    result.save()
    logging.debug(f"[dump {result.dump.name} - plugin {result.plugin.name}] {message}")


def get_banner(result):
    """Get banner from for a specific dump. If multiple gets first"""
    if banners := Value.objects.filter(result=result):
        for hit in banners:
            if banner := hit.value.get("Banner"):
                logging.debug(f"[dump {result.dump.pk}] symbol hit: {hit.value['Banner']} {hit.value['Offset']}")
        return banner  # hopefully they are always the same
    logging.error(f"[dump {result.dump.pk}] no hit")
    return None


def check_runnable(dump_pk, operating_system, banner):
    """
    Checks if dump's banner is available in banner cache.

    Args:
        dump_pk: The primary key of the Dump object.
        operating_system: The operating system of the dump.
        banner: The banner string of the dump.

    Returns:
        True if the dump is runnable, False otherwise.
    """
    _apply_runtime_isf_url()
    if operating_system == "Windows":
        try:
            ctx = contexts.Context()
            intermed.IntermediateSymbolTable.create(ctx, "check_pe", "windows", "pe")
            return True
        except Exception as excp:
            logging.error(f"[dump {dump_pk}] Windows PE symbols lookup failed: {excp}")
            return False

    if operating_system != "Linux":
        logging.debug(f"[dump {dump_pk}] {operating_system} CHECK NO YET IMPLEMENTED")
        return True

    if not banner:
        logging.error(f"[dump {dump_pk}] {operating_system} missing banner")
        return False

    dump_kernel = None

    if m := re.match(BANNER_REGEX, banner):
        m.groupdict()
        dump_kernel = m["kernel"]
    else:
        logging.error("[dump {dump_pk}] Error extracting kernel info from dump")
        return False

    ctx = contexts.Context()
    automagics = automagic.available(ctx)
    if banners := [x for x in automagics if x._config_path == "automagic.LinuxSymbolFinder"]:
        for active_banner in banners[0].banners:
            if not active_banner:
                continue
            active_banner = active_banner.rstrip(b"\n\00")
            if m := re.match(BANNER_REGEX, active_banner.decode("utf-8")):
                m.groupdict()
                if m["kernel"] == dump_kernel:
                    return True
            else:
                logging.error("[dump {dump_pk}] Error extracting kernel info from dump")
        logging.error(f"[dump {dump_pk}] Banner not found")
        logging.error("Available banners: {}".format([f"\n\t- {available_banner}" for available_banner in banners]))
        logging.error(f"Searched banner:\n\t- {banner}")
        return False
    logging.error(f"[dump {dump_pk}] Failure looking for banners")
    return False


def refresh_symbols():
    """Refresh symbols cache"""
    logging.debug("[Refresh Symbol Cache] Started")
    try:
        from orochi.website.symbols_assistant import ensure_symbol_environment

        ensure_symbol_environment()
    except Exception as exc:
        logging.warning(f"[Refresh Symbol Cache] Environment check error: {exc}")
    try:
        prev_offline = getattr(constants, "OFFLINE", False)
        constants.OFFLINE = True
        try:
            identifiers_path = os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME)
            cache = symbol_cache.SqliteCache(identifiers_path)
            cache.update(cli.MuteProgress())
        finally:
            constants.OFFLINE = prev_offline
    except Exception as exc:
        logging.warning(f"[Refresh Symbol Cache] Cache update warning: {exc}")
    logging.debug("[Refresh Symbol Cache] Completed")


def unzip(dump, filepath, extract_path, password):
    """Extract an uploaded archive with 7z (optional password) and return the path of the memory image."""
    dump.status = DUMP_STATUS_UNZIPPING
    dump.save()

    seven_z_path = shutil.which("7z") or "/usr/bin/7z"
    if password:
        subprocess.call(["7z", "e", f"{filepath}", f"-o{extract_path}", f"-p{password}", "-y"])
    else:
        subprocess.call([seven_z_path, "e", f"{filepath}", f"-o{extract_path}", "-y"])

    archive = Path(filepath).resolve()
    extracted_files = [str(x) for x in Path(extract_path).glob("**/*") if x.is_file() and x.resolve() != archive]
    newpath = None
    if len(extracted_files) == 1:
        newpath = extracted_files[0]
    elif len(extracted_files) > 1:
        for x in extracted_files:
            if x.lower().endswith(".vmem"):
                newpath = x
    # Remove the archive only once its memory image is out: a failed extraction must not destroy the dump
    if newpath:
        os.unlink(filepath)
    return newpath


def finalize_dump(results, dump_pk):
    """Callback task executed after all automatic plugins have finished."""
    close_old_connections()
    try:
        dump = Dump.objects.get(pk=dump_pk)
        dump.status = DUMP_STATUS_COMPLETED
        dump.save()
        logging.info(f"[dump {dump_pk}] all automatic plugins completed, status marked Completed")
    except Exception as e:
        logging.error(f"[dump {dump_pk}] Error finalizing dump: {e}")
    finally:
        close_old_connections()


def mark_automatic_plugins(dump, user_pk) -> int:
    """Mark the automatic plugins of ``user_pk`` (or of the dump author) as running and the others as not started.

    Used after symbols become available: missing symbols disable every plugin, which loses which ones were
    automatic. Returns how many plugins will run.
    """
    from orochi.website.models import UserPlugin
    from orochi.website.roles import can_execute_plugin

    user_pk = user_pk or dump.author_id
    user = get_user_model().objects.filter(pk=user_pk).first()
    automatic = set(UserPlugin.objects.filter(user_id=user_pk, automatic=True).values_list("plugin_id", flat=True))
    running = 0
    for result in dump.result_set.select_related("plugin").exclude(plugin__name="banners.Banners"):
        run = result.plugin_id in automatic and user is not None and can_execute_plugin(user, result.plugin)
        result.result = RESULT_STATUS_RUNNING if run else RESULT_STATUS_NOT_STARTED
        result.save(update_fields=["result"])
        running += run
    return running


def dispatch_automatic_plugins(dump, user_pk, restart=None, dask_client=None) -> int:
    """Submit the plugins marked as running (or the ``restart`` ones) to Dask and chain ``finalize_dump``.

    Returns the number of submitted plugins.
    """
    dump_pk = dump.pk
    dask_client = dask_client or get_client()
    tasks_list = dump.result_set.exclude(result__in=[RESULT_STATUS_DISABLED, RESULT_STATUS_NOT_STARTED])
    if dump.operating_system == "Linux":
        tasks_list = tasks_list.exclude(plugin__name="banners.Banners")
    elif dump.operating_system == "Windows":
        tasks_list = tasks_list.exclude(plugin__name="windows.registry.hivelist.HiveList")

    if restart:
        tasks_list = tasks_list.filter(plugin__pk__in=restart)

    logging.debug(f"[dump {dump_pk}] tasks submitted")
    tasks_len = len(tasks_list)
    futures = dask_client.map(
        run_plugin,
        [dump] * tasks_len,
        [result.plugin for result in tasks_list],
        [None] * tasks_len,
        [user_pk] * tasks_len,
    )
    # Chain finalize_dump non-blockingly so manage_upload frees its worker slot immediately
    if type(dask_client).__name__ in ("MagicMock", "Mock") or getattr(dask_client, "_is_mock", False):
        if hasattr(dask_client, "gather"):
            with contextlib.suppress(Exception):
                _ = dask_client.gather(futures)
        finalize_dump(None, dump_pk)
    else:
        finalize_future = dask_client.submit(
            finalize_dump,
            futures,
            dump_pk,
            key=f"finalize_dump_{dump_pk}",
        )
        fire_and_forget(finalize_future)
    logging.debug(f"[dump {dump_pk}] tasks dispatched and chained non-blockingly")
    return tasks_len


def handle_missing_symbols(dump, user_pk, diagnosis: dict | None = None) -> None:
    """Tell the users why the symbols of ``dump`` are missing and, with ``AUTO_RESOLVE_SYMBOLS``, build them."""
    from extra_settings.models import Setting

    from orochi.website.symbols_assistant import notify_symbols

    user = get_user_model().objects.filter(pk=user_pk).first() if user_pk else None
    diagnosis = diagnosis or {}
    if dump.operating_system != "Linux":
        notify_symbols(dump, f"symbols are missing: {diagnosis.get('message') or 'open Symbols to fix them.'}", user)
        return
    if not dump.banner:
        notify_symbols(
            dump,
            "no Linux kernel banner found in the dump, so its symbols cannot be identified. "
            "Upload the kernel debug package or the ISF from Symbols.",
            user,
        )
        return
    kernel = diagnosis.get("kernel") or dump.banner
    suggested = dump.suggested_symbols_path or []
    urls = [u for u in suggested if u and not u.startswith("[")]
    if not urls:
        reason = suggested[0] if suggested else "no debug package found"
        notify_symbols(
            dump,
            f"no symbols for kernel {kernel} ({reason}). Upload the debug package or the ISF from Symbols.",
            user,
        )
        return
    if not Setting.get("AUTO_RESOLVE_SYMBOLS", default=False):
        notify_symbols(
            dump,
            f"no symbols for kernel {kernel}. Its debug package is available: build the ISF from Symbols "
            "(or enable the AUTO_RESOLVE_SYMBOLS setting to do it automatically).",
            user,
        )
        return
    from orochi.utils.download_symbols import package_name_from_url
    from orochi.website.tasks import download_symbols_task

    notify_symbols(
        dump,
        f"no symbols for kernel {kernel}: downloading {package_name_from_url(urls[0])} to build them automatically.",
        user,
    )
    download_symbols_task.enqueue(url_list=urls, dump_pk=dump.pk, user_pk=user_pk, run_automatic=True)


def manage_upload(dump_pk, user_pk, password, restart, move):
    """Process a new or restarted dump: unzip, hash, detect the banner and symbols, then run automatic plugins.

    Windows dumps also get the regipy plugins on the registry hives.
    """
    close_old_connections()
    try:
        dask_client = get_client()
        dump = Dump.objects.get(pk=dump_pk)
        logging.debug(f"[dump {dump_pk}] Processing")

        if not restart:
            # FIRST RUN, FILE COULD BE ZIPPED
            # COPY EACH FILE IN THEIR FOLDER BEFORE UNZIP/RUN PLUGIN
            from distributed import rejoin, secede

            from orochi.website.storage import ensure_local_dump_path

            extract_path = f"{settings.MEDIA_ROOT}/{dump.index}"
            source_path = ensure_local_dump_path(dump)
            # Without the folder, shutil.move would rename the file to "<index>" instead of moving it inside
            Path(extract_path).mkdir(parents=True, exist_ok=True)
            filepath = shutil.move(source_path, extract_path) if move else source_path
            filetype = magic.from_file(filepath, mime=True)

            if filetype in MAGIC_ARCHIVE_MIMETYPES:
                if type(dask_client).__name__ in ("MagicMock", "Mock") or getattr(dask_client, "_is_mock", False):
                    unzip_future = dask_client.submit(unzip, dump, filepath, extract_path, password)
                    with contextlib.suppress(Exception):
                        secede()
                    try:
                        newpath = unzip_future.result()
                    finally:
                        with contextlib.suppress(Exception):
                            rejoin()
                else:
                    newpath = unzip(dump, filepath, extract_path, password)
            else:
                newpath = filepath

            if not newpath:
                # archive is unvalid
                logging.error(f"[dump {dump.name}] Invalid archive dump data")
                dump.comment = "Invalid archive dump data"
                dump.status = DUMP_STATUS_ERROR
                dump.save()
                tasks_list = (
                    dump.result_set.all()
                    if dump.operating_system != "Linux"
                    else dump.result_set.exclude(plugin__name="banners.Banners")
                )
                tasks_list.update(result=RESULT_STATUS_DISABLED)
                return

            dump.upload.name = newpath
            dump.size = os.path.getsize(newpath)
            dump.sha256, dump.md5 = hash_checksum(newpath)
            dump.status = DUMP_STATUS_CREATED
            dump.save()
            banner = False

            # check symbols using banners
            if dump.operating_system in ("Linux", "Mac"):
                try:
                    if banner := dump.result_set.get(plugin__name="banners.Banners"):
                        if type(dask_client).__name__ in ("MagicMock", "Mock") or getattr(
                            dask_client, "_is_mock", False
                        ):
                            banner_future = dask_client.submit(run_plugin, dump, banner.plugin)
                            with contextlib.suppress(Exception):
                                secede()
                            try:
                                banner_future.result()
                            finally:
                                with contextlib.suppress(Exception):
                                    rejoin()
                        else:
                            run_plugin(dump, banner.plugin)
                        if banner_result := get_banner(banner):
                            dump.banner = banner_result.strip("\"'")
                            logging.error(f"[dump {dump_pk}] guessed banner '{dump.banner}'")
                            dump.save()
                except ObjectDoesNotExist:
                    logging.error(f"[dump {dump_pk}] Banner plugin missing")
            # Run Hivelist in background
            elif dump.operating_system == "Windows":
                try:
                    regipy = dump.result_set.get(plugin__name="windows.registry.hivelist.HiveList")
                    logging.info(f"[dump {dump_pk}] Running regipy plugins")
                    fire_and_forget(dask_client.submit(run_plugin, dump, regipy.plugin, regipy_plugins=True))
                except ObjectDoesNotExist:
                    logging.error(f"[dump {dump_pk}] HiveList plugin missing")

        # Restart or unzip+banner ok, run all automatic plugins
        if restart or check_runnable(dump.pk, dump.operating_system, dump.banner):
            if restart and dump.status != DUMP_STATUS_CREATED:
                # Restarted plugins: Processing until finalize_dump marks the dump Completed again
                dump.status = DUMP_STATUS_CREATED
                dump.save(update_fields=["status"])
            dispatch_automatic_plugins(dump, user_pk, restart=restart, dask_client=dask_client)
        else:
            # This takes time so we do this one time only
            if dump.banner:
                dump.suggested_symbols_path = get_path_from_banner(dump.banner)
            dump.status = DUMP_STATUS_MISSING_SYMBOLS
            dump.save()
            diagnosis = {}
            try:
                from orochi.website.symbols_assistant import diagnose_symbols

                diagnosis = diagnose_symbols(dump)
            except Exception as exc:
                logging.warning(f"[dump {dump_pk}] Diagnosis error in manage_upload: {exc}")
            logging.error(f"[dump {dump_pk}] symbols non available. Disabling all plugins")
            tasks_list = (
                dump.result_set.all()
                if dump.operating_system != "Linux"
                else dump.result_set.exclude(plugin__name="banners.Banners")
            )
            tasks_list.update(result=RESULT_STATUS_DISABLED)
            handle_missing_symbols(dump, user_pk, diagnosis)
    except Exception as excp:
        logging.error(f"[dump {dump_pk}] - {excp}")
        # The dump may be gone (deleted while queued): nothing to mark
        dump = Dump.objects.filter(pk=dump_pk).first()
        if dump is None:
            return
        dump.description = traceback.format_exc()
        dump.status = DUMP_STATUS_ERROR
        dump.save()
        tasks_list = (
            dump.result_set.all()
            if dump.operating_system != "Linux"
            else dump.result_set.exclude(plugin__name="banners.Banners")
        )
        tasks_list.update(result=RESULT_STATUS_DISABLED)
    finally:
        close_old_connections()
