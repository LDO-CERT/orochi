import datetime
import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.request import pathname2url

import attr
import magic
import requests
import volatility3.plugins
import vt
from asgiref.sync import sync_to_async
from bs4 import BeautifulSoup
from clamdpy import ClamdUnixSocket
from distributed import fire_and_forget, get_client
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
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
    display_disassembly,
    format_hints,
    hex_bytes_as_text,
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
)
from volatility3.framework.automagic import stacker, symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.configuration.requirements import (
    ChoiceRequirement,
    ListRequirement,
)

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

    class OrochiFileHandler(interfaces.plugins.FileHandlerInterface):
        def __init__(self, filename: str):
            fd, self._name = tempfile.mkstemp(suffix=".vol3", prefix="tmp_")
            self._file = io.open(fd, mode="w+b")
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
            return self._file.closed

        @property
        def mode(self):
            return self._file.mode

        @property
        def name(self):
            return self._file.name

        def getvalue(self) -> bytes:
            """Mimic a BytesIO object's getvalue parameter"""
            # Opens the file new so we're not trying to do IO on a closed file
            with open(self._name, mode="rb") as this_file:
                return this_file.read()

        def delete(self):
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
        format_hints.HexBytes: quoted_optional(hex_bytes_as_text),
        interfaces.renderers.Disassembly: quoted_optional(display_disassembly),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        format_hints.Hex: optional(lambda x: f"0x{x:x}"),
        format_hints.Bin: optional(lambda x: f"0x{x:b}"),
        bytes: optional(lambda x: " ".join([f"{b:02x}" for b in x])),
        datetime.datetime: lambda x: (
            None
            if isinstance(x, interfaces.renderers.BaseAbsentValue)
            else x.isoformat()
        ),
        "default": lambda x: x,
    }

    def render(self, grid: interfaces.renderers.TreeGrid):
        final_output = ({}, [])

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            acc_map, final_tree = accumulator
            node_dict: Dict[str, Any] = {"__children": []}
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                data = renderer(list(node.values)[column_index])
                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None
                node_dict[column.name] = data
            if node.parent:
                acc_map[node.parent.path]["__children"].append(node_dict)
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict
            return (acc_map, final_tree)

        error = grid.populate(visitor, final_output, fail_on_errors=False)
        return final_output[1], error


def hash_checksum(filename, block_size=65536):
    """
    Generate hashes for filename
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha256.update(block)
            md5.update(block)
    return sha256.hexdigest(), md5.hexdigest()


def get_parameters(plugin):
    """
    Obtains parameters list from volatility plugin
    """
    _ = contexts.Context()
    _ = framework.import_files(volatility3.plugins, True)
    plugin_list = framework.list_plugins()
    params = []
    if plugin in plugin_list:
        for requirement in plugin_list[plugin].get_requirements():
            additional = {"optional": requirement.optional, "name": requirement.name}

            if isinstance(requirement, requirements.URIRequirement):
                additional |= {"mode": "single", "type": "file"}
            elif isinstance(
                requirement, interfaces.configuration.SimpleTypeRequirement
            ):
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
    """
    Runs virustotal on filepath
    """
    try:
        vt_service = await sync_to_async(Service.objects.get)(name=SERVICE_VIRUSTOTAL)
    except Service.DoesNotExist:
        logging.error("[VT] Service not configured")
        return
    async with vt.Client(vt_service.key, proxy=vt_service.proxy) as client:
        try:
            to_check = hash_checksum(filepath)[0]
            report = await client.get_object_async(f"/files/{to_check}")
            if report := report.to_dict().get("attributes"):
                stats = dict(report.get("last_analysis_stats", {}).items())
                if scan_date := report.get("last_analysis_date"):
                    scan_date = datetime.datetime.fromtimestamp(scan_date).strftime(
                        "%m/%d/%Y"
                    )
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
    """
    Runs regipy on filepath
    """
    try:
        registry_hive = RegistryHive(filepath)
        *a, index, _, hive_name = filepath.split("/")
        dump = Dump.objects.get(index=index)
        data = []
        try:
            data.extend(
                attr.asdict(entry)
                for entry in registry_hive.recurse_subkeys(
                    registry_hive.root, as_json=True
                )
            )
        except RegistryParsingException as e:
            logging.error(e)
        with open(f"{filepath}.regipy.json", "w") as f:
            json.dump(json.loads(json.dumps(data).replace(r"\u0000", "")), f)
        if plugins:
            plugin_to_run = [x for x in PLUGINS if x.NAME in settings.REGIPY_PLUGINS]
            for plugin_class in plugin_to_run:
                plugin = plugin_class(registry_hive, as_json=True)
                if plugin.can_run():
                    try:
                        plugin.run()
                        if plugin.entries:
                            info = {
                                "hive": hive_name,
                                "plugin": plugin.NAME,
                                "data": json.loads(
                                    json.dumps(plugin.entries).replace(r"\u0000", "")
                                ),
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


def run_plugin(dump_obj, plugin_obj, params=None, user_pk=None, regipy_plugins=False):
    """
    Execute a single plugin on a dump with optional params.
    If success data are sent to stored in value table.
    """
    logging.info(f"[dump {dump_obj.name} - plugin {plugin_obj.name}] start")

    try:
        result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
        result.result = RESULT_STATUS_RUNNING
        result.save()

        ctx = contexts.Context()
        constants.PARALLELISM = constants.Parallelism.Off
        _ = framework.import_files(volatility3.plugins, True)
        automagics = automagic.available(ctx)
        plugin_list = framework.list_plugins()
        json_renderer = ReturnJsonRenderer
        seen_automagics = set()
        for amagic in automagics:
            if amagic in seen_automagics:
                continue
            seen_automagics.add(amagic)
        plugin = plugin_list.get(plugin_obj.name)
        base_config_path = "plugins"
        file_name = os.path.abspath(dump_obj.upload.path)
        single_location = f"file:{pathname2url(file_name)}"
        ctx.config["automagic.LayerStacker.single_location"] = single_location
        automagics = automagic.choose_automagic(automagics, plugin)
        if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
            ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(
                plugin
            )
        # LOCAL DUMPS REQUIRES FILES - Also regipy plugins
        local_dump = plugin_obj.local_dump or regipy_plugins

        # Timeliner can create a body-file if required
        if (
            plugin_obj.name == "timeliner.Timeliner"
            and params.get("create-bodyfile") == True
        ):
            local_dump = True

        # ADD PARAMETERS, AND IF LOCAL DUMP ENABLE ADD DUMP TRUE BY DEFAULT
        plugin_config_path = interfaces.configuration.path_join(
            base_config_path, plugin.__name__
        )
        if params:
            # ADD PARAMETERS TO PLUGIN CONF
            for k, v in params.items():
                if v != "":
                    extended_path = interfaces.configuration.path_join(
                        plugin_config_path, k
                    )
                    ctx.config[extended_path] = v

                if k == "dump" and v:
                    # IF DUMP TRUE HAS BEEN PASS IT'LL DUMP LOCALLY
                    local_dump = True

        if not params and local_dump:
            # IF ADMIN SET LOCAL DUMP ADD DUMP TRUE AS PARAMETER
            extended_path = interfaces.configuration.path_join(
                plugin_config_path, "dump"
            )
            ctx.config[extended_path] = True

        logging.debug(
            f"[dump {dump_obj.name} - plugin {plugin_obj.name}] params: {ctx.config}"
        )

        file_list = []
        if local_dump:
            # IF PARAM/ADMIN DUMP CREATE FILECONSUMER
            local_path = f"{settings.MEDIA_ROOT}/{dump_obj.index}/{plugin_obj.name}"
            if not os.path.exists(local_path):
                os.mkdir(local_path)
            file_handler = file_handler_class_factory(
                output_dir=local_path, file_list=file_list
            )
        else:
            local_path = None
            file_handler = file_handler_class_factory(
                output_dir=None, file_list=file_list
            )

        # #####################
        # ## YARA
        # if not file or rule selected and exists default use that
        if plugin_obj.name in ["yarascan.YaraScan", "windows.vadyarascan.VadYaraScan"]:
            has_file = False
            if params:
                for k, v in params.items():
                    if k in ["yara_file", "yara_compiled_file", "yara_string"] and (
                        v is not None and v != ""
                    ):
                        has_file = True

            if not has_file:
                if rule := CustomRule.objects.get(user__pk=user_pk, default=True):
                    extended_path = interfaces.configuration.path_join(
                        plugin_config_path, "yara_compiled_file"
                    )
                    ctx.config[extended_path] = f"file:{rule.path}"

            logging.error(
                f"[dump {dump_obj.pk} - plugin {plugin_obj.name}] params: {ctx.config}"
            )

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
            # LOG UNSATISFIED ERROR
            description = "\n".join(
                [
                    excp.unsatisfied[config_path].description
                    for config_path in excp.unsatisfied
                ]
            )
            save_result_status(
                result, RESULT_STATUS_UNSATISFIED, description, "Unsatisfied"
            )
            return
        try:
            runned_plugin = constructed.run()
        except Exception as excp:
            # LOG GENERIC ERROR [VOLATILITY]
            fulltrace = traceback.TracebackException.from_exception(excp).format(
                chain=True
            )
            save_result_status(
                result, RESULT_STATUS_ERROR, "\n".join(fulltrace), f"Error: {excp}"
            )
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
                                    (
                                        res.reason
                                        for res in match
                                        if str(res.path) == down_path
                                    ),
                                    "-",
                                )

            # RUN VT AND REGIPY ON CREATED FILES
            if plugin_obj.vt_check or plugin_obj.regipy_check or regipy_plugins:
                dask_client = get_client()
                for file_id in file_list:
                    output_path = f"{local_path}/{file_id.preferred_filename}"
                    if plugin_obj.vt_check:
                        fire_and_forget(dask_client.submit(run_vt, output_path))
                    if plugin_obj.regipy_check or regipy_plugins:
                        fire_and_forget(
                            dask_client.submit(run_regipy, output_path, regipy_plugins)
                        )

            save_result_status(result, RESULT_STATUS_SUCCESS, error, "Data saved")
            values_create_list = [Value(value=x, result=result) for x in json_data]
            Value.objects.bulk_create(values_create_list)
        else:
            save_result_status(result, RESULT_STATUS_EMPTY, error, "Empty")
        return 0

    except Exception as excp:
        # LOG GENERIC ERROR
        fulltrace = traceback.TracebackException.from_exception(excp).format(chain=True)
        save_result_status(
            result, RESULT_STATUS_ERROR, "\n".join(fulltrace), f"Error: {excp}"
        )

        return 0


def save_result_status(result, status, description, message):
    result.result = status
    result.description = description
    result.save()
    logging.debug(f"[dump {result.dump.name} - plugin {result.plugin.name}] {message}")


def get_path_from_banner(banner):
    """
    Find web url for symbols parsing banner
    """
    if m := re.match(BANNER_REGEX, banner):
        m.groupdict()

        # UBUNTU
        if "ubuntu" in m["gcc"].lower() or "ubuntu" in m["info"].lower():
            arch = None
            if banner.lower().find("amd64") != -1:
                arch = "amd64"
            elif banner.lower().find("arm64") != -1:
                arch = "arm64"
            elif banner.lower().find("i386") != -1:
                arch = "i386"
            else:
                return ["[OS wip] insert here symbols url!"]
            package_name = f"linux-image-{m['kernel']}"
            package_alternative_name = f"linux-image-unsigned-{m['kernel']}"
            url = "http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/"
            try:
                html_text = requests.get(url).text
                soup = BeautifulSoup(html_text, "html.parser")
                for link in soup.find_all("a"):
                    if link.get("href", None):
                        if (
                            link.get("href").find(package_name) != -1
                            and link.get("href").find(arch) != -1
                        ):
                            down_url = f"{url}{link.get('href')}"
                            return [down_url]
                        if (
                            link.get("href").find(package_alternative_name) != -1
                            and link.get("href").find(arch) != -1
                        ):
                            down_url = f"{url}{link.get('href')}"
                            return [down_url]
            except Exception:
                return ["[Download fail] insert here symbols url!"]

        # DEBIAN
        elif "debian" in m["gcc"].lower() or "debian" in m["info"].lower():
            arch = None
            if banner.lower().find("amd64") != -1:
                arch = "amd64"
            elif banner.lower().find("arm64") != -1:
                arch = "arm64"
            elif banner.lower().find("i386") != -1:
                arch = "i386"
            else:
                return ["[OS wip] insert here symbols url!"]
            package_name = f"linux-image-{m['kernel']}-dbg"
            try:
                url = "https://deb.sipwise.com/debian/pool/main/l/linux/"
                html_text = requests.get(url).text
                soup = BeautifulSoup(html_text, "html.parser")
                for link in soup.find_all("a"):
                    href = link.get("href", None)
                    if href and link.get("href").find(package_name) != -1:
                        try:
                            p_kernel, p_info, p_arch = href.split("_")
                            p_arch = p_arch.split(".")[0]
                            if (
                                p_kernel.find(package_name) != -1
                                and m["info"].find(p_info) != -1
                                and p_arch == arch
                            ):
                                down_url = f"{url}{href}"
                                return [down_url]
                        except Exception:
                            print(href.split("_"))
                            return ["[Download fail] insert here symbols url!"]
            except Exception:
                return ["[Download fail] insert here symbols url!"]
        else:
            return ["[OS wip] insert here symbols url!"]
    return ["[Banner parse fail] insert here symbols url!"]


def get_banner(result):
    """
    Get banner from for a specific dump. If multiple gets first
    """
    if banners := Value.objects.filter(result=result):
        for hit in banners:
            if banner := hit.value.get("Banner"):
                logging.debug(
                    f"[dump {result.dump.pk}] symbol hit: {hit.value['Banner']} {hit.value['Offset']}"
                )
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
    if banners := [
        x for x in automagics if x._config_path == "automagic.LinuxSymbolFinder"
    ]:
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
        logging.error(
            "Available banners: {}".format(
                [f"\n\t- {available_banner}" for available_banner in banners]
            )
        )
        logging.error(f"Searched banner:\n\t- {banner}")
        return False
    logging.error(f"[dump {dump_pk}] Failure looking for banners")
    return False


def refresh_symbols():
    """Refresh symbols cache"""
    logging.debug("[Refresh Symbol Cache] Started")
    identifiers_path = os.path.join(
        constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
    )
    cache = symbol_cache.SqliteCache(identifiers_path)
    cache.update(cli.MuteProgress())
    logging.debug("[Refresh Symbol Cache] Completed")


def unzip(dump, filepath, extract_path, password):
    dump.status = DUMP_STATUS_UNZIPPING
    dump.save()

    if password:
        subprocess.call(
            ["7z", "e", f"{filepath}", f"-o{extract_path}", f"-p{password}", "-y"]
        )
    else:
        subprocess.call(["7z", "e", f"{filepath}", f"-o{extract_path}", "-y"])

    os.unlink(filepath)
    extracted_files = [str(x) for x in Path(extract_path).glob("**/*") if x.is_file()]
    newpath = None
    if len(extracted_files) == 1:
        newpath = extracted_files[0]
    elif len(extracted_files) > 1:
        for x in extracted_files:
            if x.lower().endswith(".vmem"):
                newpath = x
    return newpath


def manage_upload(dump_pk, user_pk, password, restart, move):
    try:
        dask_client = get_client()
        dump = Dump.objects.get(pk=dump_pk)
        logging.debug(f"[dump {dump_pk}] Processing")

        if not restart:
            # FIRST RUN, FILE COULD BE ZIPPED
            # COPY EACH FILE IN THEIR FOLDER BEFORE UNZIP/RUN PLUGIN
            extract_path = f"{settings.MEDIA_ROOT}/{dump.index}"
            filepath = (
                shutil.move(dump.upload.path, extract_path)
                if move
                else dump.upload.path
            )
            filetype = magic.from_file(filepath, mime=True)

            newpath = (
                dask_client.submit(
                    unzip, dump, filepath, extract_path, password
                ).result()
                if filetype in MAGIC_ARCHIVE_MIMETYPES
                else filepath
            )
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
                        dask_client.submit(run_plugin, dump, banner.plugin).result()
                        if banner_result := get_banner(banner):
                            dump.banner = banner_result.strip("\"'")
                            logging.error(
                                f"[dump {dump_pk}] guessed banner '{dump.banner}'"
                            )
                            dump.save()
                except ObjectDoesNotExist:
                    logging.error(f"[dump {dump_pk}] Banner plugin missing")
            # Run Hivelist in background
            elif dump.operating_system == "Windows":
                try:
                    regipy = dump.result_set.get(
                        plugin__name="windows.registry.hivelist.HiveList"
                    )
                    logging.info(f"[dump {dump_pk}] Running regipy plugins")
                    fire_and_forget(
                        dask_client.submit(
                            run_plugin, dump, regipy.plugin, regipy_plugins=True
                        )
                    )
                except ObjectDoesNotExist:
                    logging.error(f"[dump {dump_pk}] HiveList plugin missing")

        # Restart or unzip+banner ok, run all automatic plugins
        if restart or check_runnable(dump.pk, dump.operating_system, dump.banner):
            tasks_list = dump.result_set.exclude(
                result__in=[RESULT_STATUS_DISABLED, RESULT_STATUS_NOT_STARTED]
            )
            if dump.operating_system == "Linux":
                tasks_list = tasks_list.exclude(plugin__name="banners.Banners")
            elif dump.operating_system == "Windows":
                tasks_list = tasks_list.exclude(
                    plugin__name="windows.registry.hivelist.HiveList"
                )

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
            _ = dask_client.gather(futures)
            dump.status = DUMP_STATUS_COMPLETED
            dump.save()
            logging.debug(f"[dump {dump_pk}] processing terminated")
        else:
            # This takes time so we do this one time only
            if dump.banner:
                dump.suggested_symbols_path = get_path_from_banner(dump.banner)
            dump.status = DUMP_STATUS_MISSING_SYMBOLS
            dump.save()
            logging.error(
                f"[dump {dump_pk}] symbols non available. Disabling all plugins"
            )
            tasks_list = (
                dump.result_set.all()
                if dump.operating_system != "Linux"
                else dump.result_set.exclude(plugin__name="banners.Banners")
            )
            tasks_list.update(result=RESULT_STATUS_DISABLED)
    except Exception as excp:
        logging.error(f"[dump {dump_pk}] - {excp}")
        dump.description = traceback.format_exc()
        dump.status = DUMP_STATUS_ERROR
        dump.save()
        tasks_list = (
            dump.result_set.all()
            if dump.operating_system != "Linux"
            else dump.result_set.exclude(plugin__name="banners.Banners")
        )
        tasks_list.update(result=RESULT_STATUS_DISABLED)
