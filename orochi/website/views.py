import uuid
import os
import logging
import shutil
import json
import shlex

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

from .models import Dump, Plugin, Result, ExtractedDump, UserPlugin
from .forms import DumpForm, EditDumpForm, ParametersForm

from dask import delayed
from dask.distributed import Client, fire_and_forget
from orochi.utils.volatility_dask_elk import unzip_then_run, run_plugin, get_parameters

##############################
# PLUGIN
##############################


@login_required
def plugins(request):
    if request.is_ajax():
        indexes = request.GET.getlist("indexes[]")
        # CHECK IF I CAN SEE INDEXES
        dumps = Dump.objects.filter(index__in=indexes)
        for dump in dumps:
            if dump not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404("404")
        results = (
            Result.objects.filter(dump__index__in=indexes)
            .order_by("plugin__name")
            .distinct()
            .values_list("plugin__name", flat=True)
        )
        return render(request, "website/partial_plugins.html", {"results": results})
    else:
        raise Http404("404")


def plugin_f_and_f(dump, plugin, params):
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    fire_and_forget(
        dask_client.submit(run_plugin, dump, plugin, settings.ELASTICSEARCH_URL, params)
    )


@login_required
def plugin(request):
    if request.method == "POST":
        dump = get_object_or_404(Dump, index=request.POST.get("selected_index"))
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            Http404("404")
        plugin = get_object_or_404(Plugin, name=request.POST.get("selected_plugin"))
        up = get_object_or_404(
            UserPlugin, plugin=plugin, user=request.user, disabled=False
        )

        result = get_object_or_404(Result, dump=dump, plugin=plugin)

        params = {}

        parameters = get_parameters(plugin.name)
        for parameter in parameters:
            if parameter["name"] in request.POST.keys():
                if parameter["mode"] == "list":
                    value = shlex.shlex(request.POST.get(parameter["name"]), posix=True)
                    value.whitespace += ","
                    value.whitespace_split = True
                    value = list(value)
                    if parameter["type"] == int:
                        value = [int(x) for x in value]
                    params[parameter["name"]] = value
                else:
                    params[parameter["name"]] = request.POST.get(parameter["name"])

        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        es_client.indices.delete(
            "{}_{}".format(dump.index, plugin.name.lower()), ignore=[400, 404]
        )
        result.result = 0
        result.parameter = params
        result.save()

        plugin_f_and_f(dump, plugin, params)
        return JsonResponse(
            {
                "ok": True,
                "plugin": plugin.name,
                "name": request.POST.get("selected_name"),
            }
        )
    else:
        raise Http404


# login_required
def parameters(request):
    data = dict()

    if request.method == "POST":
        form = ParametersForm(data=request.POST, dynamic_fields=parameters)
        if form.is_valid():
            data["form_is_valid"] = True
        else:
            data["form_is_valid"] = False
    else:
        data = {
            "selected_plugin": request.GET.get("selected_plugin"),
            "selected_index": request.GET.get("selected_index"),
            "selected_name": request.GET.get("selected_name"),
        }
        parameters = get_parameters(data["selected_plugin"])
        form = ParametersForm(initial=data, dynamic_fields=parameters)

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_params.html", context, request=request,
    )
    return JsonResponse(data)


##############################
# RESULTS
##############################


@login_required
def analysis(request):
    if request.is_ajax():
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])

        # GET DATA
        indexes = request.GET.getlist("indexes[]")
        plugin = request.GET.get("plugin")

        # GET PLUGIN INFO
        plugin = get_object_or_404(Plugin, name=plugin)

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

        # GET ALL EXTRACTED DUMP DUMP
        if plugin.local_dump:
            ex_dumps = {
                x["path"]: x
                for x in ExtractedDump.objects.filter(result__in=results).values(
                    "path", "sha256", "clamav"
                )
            }

        # SEARCH FOR ITEMS AND KEEP INDEX
        indexes_list = [
            f"{res.dump.index}_{res.plugin.name.lower()}"
            for res in results
            if res.result == 2
        ]

        # GENERATE NOTE TO SHOW ON TOP
        note = [
            {
                "dump_name": res.dump.name,
                "plugin": res.plugin.name,
                "index": res.dump.index,
                "result": res.get_result_display(),
                "description": res.description,
                "color": colors[res.dump.index],
                "resubmit": True
                if UserPlugin.objects.filter(
                    plugin=res.plugin, user=request.user, disabled=False
                ).count()
                != 0
                else False,
            }
            for res in results
        ]

        data = []
        if indexes_list:
            s = Search(using=es_client, index=indexes_list).extra(size=10000)
            result = s.execute()
            # ANNOTATE RESULTS WITH INDEX NAME
            info = [
                (
                    hit.to_dict(),
                    hit.meta.index.split("_")[0],
                    hit.meta.index.split("_")[1],
                )
                for hit in result
            ]

            row_colors = {
                "Created Date": "#FF0000",
                "Modified Date": "#00FF00",
                "Accessed Date": "#0000FF",
                "Changed Date": "#FFFF00",
            }

            for item, item_index, plugin_index in info:
                if item_index != ".kibana":

                    # LOCAL DUMPABLE PLUGIN SHOWS DONWLOAD, HASHES AND REPORTS
                    if plugin.local_dump:

                        if item["Result"].find("Stored") != -1:
                            path = "/media/{}/{}/{}".format(
                                item_index, plugin.name, item["Result"].split()[-1]
                            )
                            item["download"] = (
                                '<a href="{}">⬇️</a>'.format(path)
                                if os.path.exists(path)
                                else None
                            )
                            item["sha256"] = ex_dumps.get(path, {}).get("sha256", None)
                            item["clamav"] = ex_dumps.get(path, {}).get("clamav", None)

                        else:
                            item["download"] = None
                            item["sha256"] = None
                            item["clamav"] = None

                    if plugin_index == "timeliner.timeliner":

                        columns = [x for x in item.keys() if x.find("Date") != -1]
                        other_columns = [x for x in item.keys() if x.find("Date") == -1]

                        parsed = False
                        for column in columns:
                            if item[column]:
                                parsed = True
                                row = {"__children": []}
                                row["Date"] = item[column]
                                row["Type"] = column
                                row["row_color"] = row_colors[column]
                                for oc in other_columns:
                                    row[oc] = item[oc]
                                row.update({"color": colors[item_index]})
                                data.append(row)

                        if not parsed:
                            row = {"__children": []}
                            row["Date"] = None
                            row["Type"] = None
                            row["row_color"] = None
                            for oc in other_columns:
                                row[oc] = item[oc]
                            row.update({"color": colors[item_index]})
                            data.append(row)

                    else:
                        item.update({"color": colors[item_index]})
                        data.append(item)

        response = {"data": data, "note": note}
        return JsonResponse(response, safe=False)
    else:
        raise Http404("404")


##############################
# INDEX
##############################


@login_required
def index(request):
    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .values_list("index", "name", "color", "operating_system", "author")
        .order_by("-created_at"),
    }
    return render(request, "website/index.html", context)


@login_required
def edit(request):
    data = dict()

    if request.method == "POST":
        dump = get_object_or_404(Dump, index=request.POST.get("index"))
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            Http404("404")
        form = EditDumpForm(data=request.POST, instance=dump)
        if form.is_valid():
            dump = form.save()
            data["form_is_valid"] = True
            data["dumps"] = render_to_string(
                "website/partial_indices.html",
                {
                    "dumps": [
                        x
                        for x in get_objects_for_user(request.user, "website.can_see")
                        .values_list(
                            "index", "color", "name", "operating_system", "author"
                        )
                        .order_by("-created_at")
                    ]
                },
                request=request,
            )
        else:
            data["form_is_valid"] = False
    else:
        dump = get_object_or_404(Dump, index=request.GET.get("index"))
        form = EditDumpForm(instance=dump)

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_edit.html", context, request=request,
    )
    return JsonResponse(data)


def index_f_and_f(dump_pk, user_pk):
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    fire_and_forget(
        dask_client.submit(unzip_then_run, dump_pk, user_pk, settings.ELASTICSEARCH_URL)
    )


@login_required
def create(request):
    data = dict()

    if request.method == "POST":
        form = DumpForm(data=request.POST)
        if form.is_valid():
            with transaction.atomic():
                dump = form.save(commit=False)
                dump.author = request.user
                dump.upload = form.cleaned_data["upload"]
                dump.index = str(uuid.uuid1())
                dump.save()
                form.delete_temporary_files()
                os.mkdir("/media/{}".format(dump.index))
                data["form_is_valid"] = True
                transaction.on_commit(lambda: index_f_and_f(dump.pk, request.user.pk))

            # Return the new list of available indexes
            data["form_is_valid"] = True
            data["dumps"] = render_to_string(
                "website/partial_indices.html",
                {
                    "dumps": [
                        x
                        for x in get_objects_for_user(request.user, "website.can_see")
                        .values_list(
                            "index", "color", "name", "operating_system", "author"
                        )
                        .order_by("-created_at")
                    ]
                },
                request=request,
            )
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
        shutil.rmtree("/media/{}".format(dump.index))
        return JsonResponse({"ok": True}, safe=False)
