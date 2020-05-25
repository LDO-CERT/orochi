import os
import sys
import uuid
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


def run_plugin(plugin_name, filepath, filename, es_url):
    ctx = contexts.Context()
    volatility.framework.constants.PARALLELISM = (
        volatility.framework.constants.Parallelism.Off
    )
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
    plugin = plugin_list.get(plugin_name)
    base_config_path = "/src/volatility/volatility/plugins"
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
        return 0
    except Exception as excp:
        return 0
    if len(result) > 0:
        es = Elasticsearch([es_url])
        helpers.bulk(
            es, gendata(f"{filename}_{plugin_name.lower()}", plugin_name, result)
        )
        return 1
    else:
        return 0
