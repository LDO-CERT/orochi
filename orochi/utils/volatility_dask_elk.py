import sys
import os
import django
import pathlib
import pyclamd

os.environ["DATABASE_URL"] = "postgres://{}:{}@{}:{}/{}".format(
    os.environ["POSTGRES_USER"],
    os.environ["POSTGRES_PASSWORD"],
    os.environ["POSTGRES_HOST"],
    os.environ["POSTGRES_PORT"],
    os.environ["POSTGRES_DB"],
)

sys.path.insert(0, "/app/orochi")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")
django.setup()

import uuid
import shutil
import traceback
import hashlib
import json
from typing import Any, List, Tuple, Dict, Optional, Union
from urllib.request import pathname2url

import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli.text_renderer import JsonRenderer
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
from orochi.website.models import Dump, Plugin, Result

from dask import delayed
from distributed import get_client, secede, rejoin
from dask.distributed import Client, fire_and_forget


class MuteProgress(object):
    def __init__(self):
        self._max_message_len = 0

    def __call__(self, progress: Union[int, float], description: str = None):
        pass


class FileConsumer(interfaces.plugins.FileConsumerInterface):
    def __init__(self):
        self.files = []

    def consume_file(self, file: interfaces.plugins.FileInterface):
        self.files.append(file)


class ReturnJsonRenderer(JsonRenderer):
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
    for item in result:
        yield {
            "_index": index,
            "_type": plugin_name,
            "_id": uuid.uuid4(),
            "_source": item,
        }


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha256.update(block)
    return sha256.hexdigest()


def run_plugin(dump_obj, plugin_obj, filepath, es_url):
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
        base_config_path = "/src/volatility/volatility/plugins"
        file_name = os.path.abspath(filepath)
        single_location = "file:" + pathname2url(file_name)
        ctx.config["automagic.LayerStacker.single_location"] = single_location
        automagics = automagic.choose_automagic(automagics, plugin)

        local_dump = plugin_obj.local_dump
        if local_dump:
            consumer = FileConsumer()
            local_path = "/media/{}/{}".format(dump_obj.index, plugin_obj.name)
            os.mkdir(local_path)
        else:
            consumer = None

        try:
            constructed = plugins.construct_plugin(
                ctx, automagics, plugin, base_config_path, MuteProgress(), consumer
            )
        except exceptions.UnsatisfiedException as excp:
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
            run_plugin = constructed.run()
        except Exception as excp:
            fulltrace = traceback.TracebackException.from_exception(excp).format(
                chain=True
            )
            result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
            result.result = 4
            result.description = "".join(fulltrace)
            result.save()
            return 0
        json_data, error = json_renderer().render(run_plugin)

        if consumer and consumer.files:
            for filedata in consumer.files:
                output_path = "{}/{}".format(local_path, filedata.preferred_filename)
                with open(output_path, "wb") as f:
                    f.write(filedata.data.getvalue())
                with open("{}.hash256".format(output_path), "w") as f:
                    f.write(sha256_checksum(output_path))
            ## RUN CLAMAV
            cd = pyclamd.ClamdUnixSocket()
            match = cd.multiscan_file(local_path)
            match = {} if not match else match
            with open("{}/clamav_analysis".format(local_path), "w") as f:
                f.write(json.dumps(match))

        if len(json_data) > 0:
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
            result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
            result.result = 2
            result.description = error
            result.save()
        else:
            result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
            result.result = 1
            result.description = error
            result.save()
        return 0
    except Exception as excp:
        fulltrace = traceback.TracebackException.from_exception(excp).format(chain=True)
        result = Result.objects.get(plugin=plugin_obj, dump=dump_obj)
        result.result = 4
        result.description = "".join(fulltrace)
        result.save()
        return 0


def unzip_then_run(dump, es_url):
    # Unzip file is zipped
    if is_zipfile(dump.upload.path):
        with ZipFile(dump.upload.path, "r") as zipObj:
            objs = zipObj.namelist()
            if len(objs) == 1:
                newpath = zipObj.extract(objs[0], pathlib.Path(dump.upload.path).parent)
    else:
        newpath = dump.upload.path

    plugin_list = []
    for plugin in Plugin.objects.filter(operating_system=dump.operating_system):
        result = Result(plugin=plugin, dump=dump)
        if plugin.disabled:
            result.result = 5
        else:
            plugin_list.append(plugin)
        result.save()

    # Run plugins on dask
    dask_client = get_client()
    secede()
    tasks = []
    for plugin in plugin_list:
        task = dask_client.submit(run_plugin, dump, plugin, newpath, es_url)
        tasks.append(task)
    results = dask_client.gather(tasks)
    rejoin()

    dump.status = 2
    dump.save()
