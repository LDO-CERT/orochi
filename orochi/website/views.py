import uuid
import pathlib
import logging


from django.core import serializers
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, Http404
from django.template.loader import render_to_string
from django.conf import settings

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search

from django.contrib.auth.decorators import login_required
from guardian.shortcuts import get_objects_for_user

from .models import Analysis, Plugin, Result
from .forms import AnalysisForm

from dask import delayed
from zipfile import ZipFile, is_zipfile
from dask.distributed import Client, fire_and_forget
from orochi.utils.volatility_dask_elk import run_plugin


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
        indexes = request.GET.getlist("indexes[]")
        # CHECK IF I CAN SEE INDEXES
        analyses = Analysis.objects.filter(index__in=indexes)
        for analysis in analyses:
            if analysis not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404("404")
        results = list(
            Result.objects.filter(analysis__index__in=indexes)
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
        analyses = Analysis.objects.filter(index__in=indexes)
        colors = {}
        for analysis in analyses:
            if analysis not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404
            colors[analysis.index] = analysis.color

        # GET ALL RESULTS
        results = Result.objects.select_related("analysis", "plugin").filter(
            plugin__name=plugin, analysis__index__in=indexes
        )

        # SEARCH FOR ITEMS AND KEEP INDEX
        indexes_list = [
            f"{res.analysis.index}_{res.plugin.name.lower()}"
            for res in results
            if res.result == 2
        ]

        data = []

        note = [
            {
                "analysis_name": res.analysis.name,
                "result": res.get_result_display(),
                "description": res.description,
            }
            for res in results
            if res.description
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


@login_required
def create(request):
    data = dict()

    if request.method == "POST":
        form = AnalysisForm(data=request.POST)
        if form.is_valid():
            analysis = form.save(commit=False)
            analysis.author = request.user
            analysis.upload = form.cleaned_data["upload"]
            analysis.index = str(uuid.uuid1())
            analysis.save()
            form.delete_temporary_files()
            data["form_is_valid"] = True

            # Run plugins on dask
            dask_client = Client(settings.DASK_SCHEDULER_URL)

            # Unzip file is zipped
            if is_zipfile(analysis.upload.path):
                with ZipFile(analysis.upload.path, "r") as zipObj:
                    objs = zipObj.namelist()
                    if len(objs) == 1:
                        newpath = zipObj.extract(
                            objs[0], pathlib.Path(analysis.upload.path).parent
                        )
            else:
                newpath = analysis.upload.path

            for plugin in Plugin.objects.filter(
                operating_system=analysis.operating_system
            ):
                if plugin.disabled:
                    result = Result(plugin=plugin, analysis=analysis, result=5)
                    result.save()
                else:
                    a = dask_client.compute(
                        delayed(run_plugin)(
                            analysis, plugin, newpath, settings.ELASTICSEARCH_URL,
                        )
                    )
                    fire_and_forget(a)

            # Return the new list of available indexes
            data["new_indices"] = [
                x
                for x in get_objects_for_user(
                    request.user, "website.can_see"
                ).values_list("index", "color", "name")
            ]
        else:
            data["form_is_valid"] = False
    else:
        form = AnalysisForm()

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
        analysis = Analysis.objects.get(index=index)
        if analysis not in get_objects_for_user(request.user, "website.can_see"):
            Http404("404")
        analysis.delete()
        es_client.indices.delete(index=f"{index}*", ignore=[400, 404])
        return JsonResponse({"ok": True}, safe=False)
