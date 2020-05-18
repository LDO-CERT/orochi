# VOLATILITY & DASK
# ------------------------------------------------------------------------------
import os
import uuid
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

from dask import delayed
from orochi.daskmanager.daskmanager import DaskManager
from typing import Any, List, Tuple, Dict, Optional
from urllib.request import pathname2url

# DJANGO
# ------------------------------------------------------------------------------
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, Http404
from django.template.loader import render_to_string
from django.conf import settings

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search

from django.contrib.auth.decorators import login_required
from guardian.shortcuts import get_objects_for_user

from .models import Analysis
from .forms import AnalysisForm


@login_required
def index(request):
    context = {
        "list_indices": get_objects_for_user(
            request.user, "website.can_see"
        ).values_list("index", "name", "color"),
    }
    return render(request, "website/index.html", context)


@login_required
def plugins(request):
    if request.is_ajax():
        client = Elasticsearch([settings.ELASTICSEARCH_URL])
        indexes = request.GET.getlist("indexes[]")

        doc_types = []

        # CHECK IF I CAN SEE INDEXES
        analyses = Analysis.objects.filter(index__in=indexes)
        for analysis in analyses:
            if analysis not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404

        # LOOK FOR INDEXES ON ES AND GRAB PLUGINS
        for index in indexes:
            if index == None or not index:
                continue
            for x in client.indices.get_alias("*"):
                if x.startswith(index):
                    plugin = "_".join(x.split("_")[1:])
                    if plugin not in doc_types:
                        doc_types.append(plugin)
        return JsonResponse(sorted(doc_types), safe=False)
    else:
        raise Http404("404")


@login_required
def analysis(request):
    if request.is_ajax():
        client = Elasticsearch([settings.ELASTICSEARCH_URL])

        # GET DATA
        indexes = request.GET.getlist("indexes[]")
        plugin = request.GET.get("plugin")

        # GET DICT OF COLOR AND CHECK PERMISSIONS
        analyses = Analysis.objects.filter(index__in=indexes)
        colors = {}
        for analysis in analyses:
            if analysis not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404
            colors[analysis.index] = analysis.color

        # SEARCH FOR ITEMS AND KEEP INDEX
        for index in indexes:
            if (
                f"{index}_{plugin}" not in client.indices.get_alias("*")
                or index == "None"
                or not index
            ):
                print(index, index == "None")
                indexes.remove(index)
        print("SS", indexes)
        indexes_list = ",".join([f"{index}_{plugin}" for index in indexes])
        s = Search(using=client, index=indexes_list).extra(size=10000)
        result = s.execute()
        info = [(hit.to_dict(), hit.meta.index.split("_")[0]) for hit in result]

        data = []
        for item, item_index in info:
            item.update({"color": colors[item_index]})
            data.append(item)

        response = {"data": data}
        return JsonResponse(response, safe=False)
    else:
        raise Http404("404")


@login_required
def create(request):
    data = dict()

    if request.method == "POST":
        form = AnalysisForm(data=request.POST)
        if form.is_valid():
            index = form.save(commit=False)
            index.author = request.user
            index.upload = form.cleaned_data["upload"]
            index.save()
            form.delete_temporary_files()
            data["form_is_valid"] = True

            # Return the new list of available indexes
            data["new_indices"] = [
                x
                for x in get_objects_for_user(
                    request.user, "website.can_see"
                ).values_list("index", "color", "name")
            ]

            # Ok, let's run plugin in dask
            filename = uuid.uuid1()
            ctx = contexts.Context()
            failures = framework.import_files(volatility.plugins, True)
            volatility.framework.constants.PARALLELISM = (
                volatility.framework.constants.Parallelism.Off
            )
            delayed_plugins = []
            for plugin_name in framework.list_plugins():
                if (
                    plugin_name.startswith("windows") or plugin_name.startswith("linux")
                ) and plugin_name not in ["windows.vaddump.VadDump",]:
                    plug_run = delayed(run_plugin)(
                        plugin_name, index.upload.path, filename
                    )
                    delayed_plugins.append(plug_run)
            dask_task = DaskManager().compute(delayed_plugins)
        else:
            data["form_is_valid"] = False
    else:
        form = AnalysisForm()

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_create.html", context, request=request,
    )
    return JsonResponse(data)


# VOLATILITY & DASK
# ------------------------------------------------------------------------------


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
        return
    except Exception as excp:
        return
    if len(result) > 0:
        es = Elasticsearch(settings.ELASTICSEARCH_URL)
        helpers.bulk(
            es, gendata(f"{filename}_{plugin_name.lower()}", plugin_name, result)
        )
    return
