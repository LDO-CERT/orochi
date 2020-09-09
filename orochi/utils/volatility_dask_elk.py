import os
import attr
import uuid
import shutil
import traceback
import hashlib
import json
import pathlib

import pyclamd
import virustotal3.core
from regipy.registry import RegistryHive
from regipy.plugins.utils import dump_hive_to_json

from glob import glob
from typing import Any, List, Tuple, Dict, Optional, Union
from urllib.request import pathname2url

import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli.text_renderer import JsonRenderer
from volatility.framework.configuration import requirements

from volatility.framework import (
    automagic,
    contexts,
    constants,
    exceptions,
    interfaces,
    plugins,
)

from zipfile import ZipFile, is_zipfile
from elasticsearch import Elasticsearch, helpers
from orochi.website.models import (
    Dump,
    Plugin,
    Result,
    ExtractedDump,
    UserPlugin,
    Service,
)

from dask import delayed
from distributed import get_client, secede, rejoin

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


class MuteProgress(object):
    """
        Mutes progress for volatility plugin
    """

    def __init__(self):
        self._max_message_len = 0

    def __call__(self, progress: Union[int, float], description: str = None):
        pass


class FileConsumer(interfaces.plugins.FileConsumerInterface):
    """ 
        Fileconsumer, as shown in volumetric
    """

    def __init__(self):
        self.files = []

    def consume_file(self, file: interfaces.plugins.FileInterface):
        self.files.append(file)


class ReturnJsonRenderer(JsonRenderer):
    """
        Custom json renderer that doesn't write json on disk but returns it with errors if present
    """

    def render(self, grid: interfaces.renderers.TreeGrid):
        final_output = ({}, [])

        def visitor(
            node: Optional[interfaces.renderers.TreeNode],
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            acc_map, final_tree = accumulator
            node_dict = {"__children": []}
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


def gendata(index, plugin_name, result):
    """
        Elastic bulk insert generator 
    """
    for item in result:
        yield {
            "_index": index,
            # "_type": plugin_name,
            "_id": uuid.uuid4(),
            "_source": item,
        }


def sha256_checksum(filename, block_size=65536):
    """
        Generate sha256 for filename
    """
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha256.update(block)
    return sha256.hexdigest()


def get_parameters(plugin):
    """
        Obtains parameters list from volatility plugin
    """
    ctx = contexts.Context()
    failures = framework.import_files(volatility.plugins, True)
    plugin_list = framework.list_plugins()
    params = []
    if plugin in plugin_list:
        for requirement in plugin_list[plugin].get_requirements():
            additional = {}
            additional["optional"] = requirement.optional
            additional["name"] = requirement.name
            if isinstance(requirement, requirements.URIRequirement):
                additional["mode"] = "single"
                additional["type"] = "file"
            elif isinstance(
                requirement, interfaces.configuration.SimpleTypeRequirement
            ):
                additional["mode"] = "single"
                additional["type"] = requirement.instance_type
            elif isinstance(
                requirement,
                volatility.framework.configuration.requirements.ListRequirement,
            ):
                additional["mode"] = "list"
                additional["type"] = requirement.element_type
            elif isinstance(
                requirement,
                volatility.framework.configuration.requirements.ChoiceRequirement,
            ):
                additional["type"] = str
                additional["mode"] = "single"
                additional["choices"] = requirement.choices
            else:
                continue
            params.append(additional)
    return params


def run_vt(result_pk, filepath):
    """
        Runs virustotal on filepath
    """
    try:
        vt = Service.objects.get(name=1)
        vt_files = virustotal3.core.Files(vt.key, proxies=vt.proxy)
        try:
            vt_report = json.loads(
                json.dumps(
                    vt_files.info_file(sha256_checksum(filepath))
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
            )
        except virustotal3.errors.VirusTotalApiError as excp:
            vt_report = None
    except ObjectDoesNotExist:
        vt_report = {"error": "Service not configured"}

    ed = ExtractedDump.objects.get(result__pk=result_pk, path=filepath)
    ed.vt_report = vt_report
    ed.save()


def run_regipy(result_pk, filepath):
    """
        Runs regipy on filepath
    """
    try:
        registry_hive = RegistryHive(filepath)
        reg_json = registry_hive.recurse_subkeys(registry_hive.root, as_json=True)
        root = {"values": [attr.asdict(entry) for entry in reg_json]}
        root = json.loads(json.dumps(root).replace(r"\u0000", ""))
    except Exception:
        root = {}

    ed = ExtractedDump.objects.get(result__pk=result_pk, path=filepath)
    ed.reg_array = root
    ed.save()


def run_plugin(dump_obj, plugin_obj, es_url, params=None):
    try:
        ctx = contexts.Context()
        constants.PARALLELISM = constants.Parallelism.Off
        failures = framework.import_files(volatility.plugins, True)
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
        single_location = "file:" + pathname2url(file_name)
        ctx.config["automagic.LayerStacker.single_location"] = single_location
        automagics = automagic.choose_automagic(automagics, plugin)

        # LOCAL DUMPS REQUIRES FILES
        local_dump = plugin_obj.local_dump

        # ADD PARAMETERS, AND IF LOCAL DUMP ENABLE ADD DUMP TRUE BY DEFAULT
        plugin_config_path = interfaces.configuration.path_join(
            base_config_path, plugin.__name__
        )
        if params:
            # ADD PARAMETERS TO PLUGIN CONF
            for k, v in params.items():
                extended_path = interfaces.configuration.path_join(
                    plugin_config_path, k
                )
                ctx.config[extended_path] = v

                if k == "dump" and v == True:
                    # IF DUMP TRUE HAS BEEN PASS IT'LL DUMP LOCALLY
                    local_dump = True

        if not params and local_dump:
            # IF ADMIN SET LOCAL DUMP ADD DUMP TRUE AS PARAMETER
            extended_path = interfaces.configuration.path_join(
                plugin_config_path, "dump"
            )
            ctx.config[extended_path] = True

        if local_dump:
            # IF PARAM/ADMIN DUMP CREATE FILECONSUMER
            consumer = FileConsumer()
            local_path = "/media/{}/{}".format(dump_obj.index, plugin_obj.name)
            if not os.path.exists(local_path):
                os.mkdir(local_path)
        else:
            consumer = None

        try:
            # RUN PLUGIN
            constructed = plugins.construct_plugin(
                ctx, automagics, plugin, base_config_path, MuteProgress(), consumer
            )
        except exceptions.UnsatisfiedException as excp:
            # LOG UNSATISFIED ERROR
            result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
            result.result = 3
            result.description = "\n".join(
                [
                    excp.unsatisfied[config_path].description
                    for config_path in excp.unsatisfied
                ]
            )
            result.save()
            return 0
        try:
            runned_plugin = constructed.run()
        except Exception as excp:
            # LOG GENERIC ERROR [VOLATILITY]
            fulltrace = traceback.TracebackException.from_exception(excp).format(
                chain=True
            )
            result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
            result.result = 4
            result.description = "\n".join(fulltrace)
            result.save()
            return 0

        # RENDER OUTPUT IN JSON AND PUT IT IN ELASTIC
        json_data, error = json_renderer().render(runned_plugin)

        if len(json_data) > 0:

            # IF DUMP STORE FILE ON DISK
            if consumer and consumer.files:
                for filedata in consumer.files:
                    output_path = "{}/{}".format(
                        local_path, filedata.preferred_filename
                    )
                    with open(output_path, "wb") as f:
                        f.write(filedata.data.getvalue())

                ## RUN CLAMAV ON ALL FOLDER
                if plugin_obj.clamav_check:
                    cd = pyclamd.ClamdUnixSocket()
                    match = cd.multiscan_file(local_path)
                    match = {} if not match else match
                else:
                    match = {}

                result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)

                # BULK CREATE EXTRACTED DUMP FOR EACH DUMPED FILE
                ed = ExtractedDump.objects.bulk_create(
                    [
                        ExtractedDump(
                            result=result,
                            path="{}/{}".format(
                                local_path, filedata.preferred_filename
                            ),
                            sha256=sha256_checksum(
                                "{}/{}".format(local_path, filedata.preferred_filename)
                            ),
                            clamav=(
                                match[
                                    "{}/{}".format(
                                        local_path, filedata.preferred_filename
                                    )
                                ][1]
                                if "{}/{}".format(
                                    local_path, filedata.preferred_filename
                                )
                                in match.keys()
                                else None
                            ),
                        )
                        for filedata in consumer.files
                    ]
                )

                ## RUN VT AND REGIPY AS DASK SUBTASKS
                if plugin_obj.vt_check or plugin_obj.regipy_check:
                    dask_client = get_client()
                    secede()
                    tasks = []
                    for filedata in consumer.files:
                        task = dask_client.submit(
                            run_vt if plugin_obj.vt_check else run_regipy,
                            result.pk,
                            "{}/{}".format(local_path, filedata.preferred_filename),
                        )
                        tasks.append(task)
                    results = dask_client.gather(tasks)
                    rejoin()

            es = Elasticsearch(
                [es_url],
                request_timeout=60,
                timeout=60,
                max_retries=10,
                retry_on_timeout=True,
            )
            helpers.bulk(
                es,
                gendata(
                    "{}_{}".format(dump_obj.index, plugin_obj.name.lower()),
                    plugin_obj.name,
                    json_data,
                ),
            )
            # EVERYTHING OK
            result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
            result.result = 2
            result.description = error
            result.save()
        else:
            # OK BUT EMPTY
            result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
            result.result = 1
            result.description = error
            result.save()

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "chat_1", {"type": "chat_message", "message": "Hello!",}
        )
        return 0

    except Exception as excp:
        # LOG GENERIC ERROR [ELASTIC]
        fulltrace = traceback.TracebackException.from_exception(excp).format(chain=True)
        result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
        result.result = 4
        result.description = "\n".join(fulltrace)
        result.save()
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "chat_1", {"type": "chat_message", "message": "Hello error!",}
        )
        return 0


def unzip_then_run(dump_pk, user_pk, es_url):

    dump = Dump.objects.get(pk=dump_pk)

    # Unzip file is zipped
    if is_zipfile(dump.upload.path):
        with ZipFile(dump.upload.path, "r") as zipObj:
            objs = zipObj.namelist()
            extract_path = pathlib.Path(dump.upload.path).parent

            # zip must contain one file with a memory dump
            if len(objs) == 1:
                newpath = zipObj.extract(objs[0], extract_path)

            # or a vmem + vmss + vmsn
            elif any([x.lower().endswith(".vmem") for x in objs]):
                zipObj.extractall(extract_path)
                for x in objs:
                    if x.endswith(".vmem"):
                        newpath = os.path.join(extract_path, x)

            else:
                # zip is unvalid
                dump.status = 4
                dump.save()
                return
    else:
        newpath = dump.upload.path

    dump.upload.name = newpath
    dump.save()

    dask_client = get_client()
    secede()
    tasks = []
    for result in dump.result_set.all():
        if result.result != 5:
            task = dask_client.submit(run_plugin, dump, result.plugin, es_url)
            tasks.append(task)
    results = dask_client.gather(tasks)
    rejoin()
    dump.status = 2
    dump.save()
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "chat_1", {"type": "chat_message", "message": "WOW!",}
    )

