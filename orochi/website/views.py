import uuid
import pathlib
import logging
from asgiref.sync import sync_to_async

from django.core import serializers
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, Http404
from django.template.loader import render_to_string
from django.conf import settings

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search

from django.contrib.auth.decorators import login_required
from guardian.shortcuts import get_objects_for_user

from .models import Dump, Plugin, Result
from .forms import DumpForm

from dask import delayed
from zipfile import ZipFile, is_zipfile
from dask.distributed import Client, fire_and_forget
from orochi.utils.volatility_dask_elk import run_plugin


@login_required
def index(request):
    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see").values_list(
            "index", "name", "color", "operating_system"
        ),
    }
    return render(request, "website/index.html", context)


@login_required
def plugins(request):
    if request.is_ajax():
        indexes = request.GET.getlist("indexes[]")
        # CHECK IF I CAN SEE INDEXES
        dumps = Dump.objects.filter(index__in=indexes)
        for dump in dumps:
            if dump not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404("404")
        results = list(
            Result.objects.filter(dumo__index__in=indexes)
            .order_by("plugin__name")
            .distinct()
            .values_list("plugin__name", flat=True)
        )
        return JsonResponse(results, safe=False)
    else:
        raise Http404("404")


@login_required
def analysis(request):
    if request.is_ajax():
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])

        # GET DATA
        indexes = request.GET.getlist("indexes[]")
        plugin = request.GET.get("plugin")

        # GET DICT OF COLOR AND CHECK PERMISSIONS
        dump = Dump.objects.filter(index__in=indexes)
        colors = {}
        for dump in dumps:
            if dump not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404
            colors[dump.index] = dump.color

        # GET ALL RESULTS
        results = Result.objects.select_related("dump", "plugin").filter(
            plugin__name=plugin, dump__index__in=indexes
        )

        # SEARCH FOR ITEMS AND KEEP INDEX
        indexes_list = [
            f"{res.dump.index}_{res.plugin.name.lower()}"
            for res in results
            if res.result == 2
        ]

        data = []

        note = [
            {
                "dump_name": res.dump.name,
                "plugin": res.plugin.name,
                "result": res.get_result_display(),
                "description": res.description,
                "color": colors[res.dump.index],
            }
            for res in results
            # if res.result > 2
        ]

        if indexes_list:
            s = Search(using=es_client, index=indexes_list).extra(size=10000)
            result = s.execute()
            info = [(hit.to_dict(), hit.meta.index.split("_")[0]) for hit in result]

            for item, item_index in info:
                if item_index != ".kibana":
                    item.update({"color": colors[item_index]})
                    data.append(item)

        response = {"data": data, "note": note}
        return JsonResponse(response, safe=False)
    else:
        raise Http404("404")


async def async_unzip_and_fire(dump, plugin_list):
    # Run plugins on dask
    dask_client = Client(settings.DASK_SCHEDULER_URL)

    # Unzip file is zipped
    if is_zipfile(dump.upload.path):
        with ZipFile(dump.upload.path, "r") as zipObj:
            objs = zipObj.namelist()
            if len(objs) == 1:
                newpath = zipObj.extract(objs[0], pathlib.Path(dump.upload.path).parent)
    else:
        newpath = dump.upload.path

    for plugin in plugin_list:
        a = dask_client.compute(
            delayed(run_plugin)(dump, plugin, newpath, settings.ELASTICSEARCH_URL,)
        )
        fire_and_forget(a)


@login_required
def create(request):
    data = dict()

    if request.method == "POST":
        form = DumpForm(data=request.POST)
        if form.is_valid():
            dump = form.save(commit=False)
            dump.author = request.user
            dump.upload = form.cleaned_data["upload"]
            dump.index = str(uuid.uuid1())
            dump.save()
            form.delete_temporary_files()
            data["form_is_valid"] = True

            plugin_list = []

            for plugin in Plugin.objects.filter(operating_system=dump.operating_system):
                if plugin.disabled:
                    result = Result(plugin=plugin, dump=dump, result=5)
                    result.save()
                else:
                    plugin_list.append(plugin)

            # Try run unzip in async
            sync_to_async(async_unzip_and_fire(dump, plugin_list))

            # Return the new list of available indexes
            data["new_indices"] = [
                x
                for x in get_objects_for_user(
                    request.user, "website.can_see"
                ).values_list("index", "color", "name", "operating_system")
            ]
        else:
            data["form_is_valid"] = False
    else:
        form = DumpForm()

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_create.html", context, request=request,
    )
    return JsonResponse(data)


@login_required
def delete(request):
    if request.is_ajax():
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        index = request.GET.get("index")
        dump = Dump.objects.get(index=index)
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            Http404("404")
        dump.delete()
        es_client.indices.delete(index=f"{index}*", ignore=[400, 404])
        return JsonResponse({"ok": True}, safe=False)
