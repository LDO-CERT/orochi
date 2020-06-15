import uuid
import logging

from django.db import DatabaseError, transaction
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
from dask.distributed import Client, fire_and_forget
from orochi.utils.volatility_dask_elk import unzip_then_run


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
            Result.objects.filter(dump__index__in=indexes)
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
        dumps = Dump.objects.filter(index__in=indexes)
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

        note = [
            {
                "dump_name": res.dump.name,
                "plugin": res.plugin.name,
                "result": res.get_result_display(),
                "description": res.description,
                "color": colors[res.dump.index],
            }
            for res in results
        ]

        data = []
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
        form = DumpForm(data=request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    dump = form.save(commit=False)
                    dump.author = request.user
                    dump.upload = form.cleaned_data["upload"]
                    dump.index = str(uuid.uuid1())
                    dump.save()
                    form.delete_temporary_files()
            except DatabaseError:
                return JsonResponse({"error": "Failing creating item"})
            data["form_is_valid"] = True

            dask_client = Client(settings.DASK_SCHEDULER_URL)
            fire_and_forget(
                dask_client.submit(unzip_then_run, dump, settings.ELASTICSEARCH_URL)
            )

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
