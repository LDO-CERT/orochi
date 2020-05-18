import os
import uuid
from glob import glob
from typing import Any, List, Tuple, Dict, Optional
from urllib.request import pathname2url

import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli.text_renderer import JsonRenderer
from volatility.framework import (
    automagic,
    contexts,
    exceptions,
    interfaces,
    plugins,
)

from elasticsearch import Elasticsearch, helpers
from tqdm import tqdm

import dask
from multiprocessing import cpu_count
from dask.distributed import Client, progress, LocalCluster


def process_unsatisfied_exceptions(excp):
    for config_path in excp.unsatisfied:
        print(
            "Unsatisfied requirement {}: {}".format(
                config_path, excp.unsatisfied[config_path].description
            )
        )


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

        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)
        return final_output[1]


def gendata(index, plugin_name, result):
    for item in result:
        yield {
            "_index": index,
            "_type": plugin_name,
            "_id": uuid.uuid4(),
            "_source": item,
        }


def run_plugin(plugin_name: str, filepath: str, filename: str) -> str:
    ctx = contexts.Context()
    failures = framework.import_files(volatility.plugins, True)
    automagics = automagic.available(ctx)
    plugin_list = framework.list_plugins()
    json_renderer = ReturnJsonRenderer
    seen_automagics = set()
    configurables_list = {}
    for amagic in automagics:
        if amagic in seen_automagics:
            continue
        seen_automagics.add(amagic)
        if isinstance(amagic, interfaces.configuration.ConfigurableInterface):
            configurables_list[amagic.__class__.__name__] = amagic
    for plugin in sorted(plugin_list):
        configurables_list[plugin] = plugin_list[plugin]
    if not (plugin := plugin_list.get(plugin_name, None)):
        print(plugin_list)
        return
    base_config_path = "volatility/plugins"
    file_name = os.path.abspath(filepath)
    single_location = "file:" + pathname2url(file_name)
    ctx.config["automagic.LayerStacker.single_location"] = single_location
    automagics = automagic.choose_automagic(automagics, plugin)
    try:
        constructed = plugins.construct_plugin(
            ctx, automagics, plugin, base_config_path, None, None
        )
        result = json_renderer().render(constructed.run())
    except exceptions.UnsatisfiedException as excp:
        process_unsatisfied_exceptions(excp)
        return
    except Exception as excp:
        print(f"ERRORE in plugin {plugin_name}:")
        print("\t", excp)
        return
    if len(result) > 0:
        es = Elasticsearch()
        # es.index(index=f"{filename}_{plugin_name.lower()}", id=1, body={"result": result})
        helpers.bulk(
            es, gendata(f"{filename}_{plugin_name.lower()}", plugin_name, result)
        )
        print(filepath, plugin_name, "DONE")
    return


def main(filepath: str, filetype: str):
    cluster = LocalCluster(threads_per_worker=1, n_workers=cpu_count())
    client = Client(cluster)
    filename = uuid.uuid1()
    ctx = contexts.Context()
    failures = framework.import_files(volatility.plugins, True)
    volatility.framework.constants.PARALLELISM = (
        volatility.framework.constants.Parallelism.Off
    )
    futures = [
        client.submit(run_plugin, plugin_name, filepath, filename)
        for plugin_name in framework.list_plugins()
        if plugin_name.startswith(filetype)
        and plugin_name not in ["windows.vaddump.VadDump",]
    ]
    client.gather(futures)


if __name__ == "__main__":
    filetype = "linux"
    for filepath in glob("/home/dadokkio/Downloads/AMF_MemorySamples/linux/*.bin"):
        main(filepath, filetype)
