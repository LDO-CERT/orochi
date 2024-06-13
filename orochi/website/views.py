import concurrent.futures
import json
import mmap
import os
import re
import shlex
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import pathname2url

import django
import elasticsearch
import magic
import psycopg2
import requests
from dask.distributed import Client, fire_and_forget
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core import management
from django.db import transaction
from django.db.models import Q
from django.http import Http404, JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.utils.text import slugify
from django.views.decorators.http import require_http_methods
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from guardian.shortcuts import assign_perm, get_objects_for_user, get_perms, remove_perm
from pymisp import MISPEvent, MISPObject, PyMISP
from pymisp.tools import FileObject

from orochi.utils.download_symbols import Downloader
from orochi.utils.volatility_dask_elk import (
    check_runnable,
    get_banner,
    get_parameters,
    refresh_symbols,
    run_plugin,
    unzip_then_run,
)
from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_EMPTY,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
    SERVICE_MISP,
)
from orochi.website.forms import (
    BookmarkForm,
    DumpForm,
    EditBookmarkForm,
    EditDumpForm,
    FolderForm,
    ParametersForm,
    SymbolBannerForm,
    SymbolISFForm,
    SymbolPackageForm,
    SymbolUploadForm,
)
from orochi.website.models import (
    Bookmark,
    CustomRule,
    Dump,
    Plugin,
    Result,
    Service,
    UserPlugin,
)
from volatility3.framework import automagic, contexts

COLOR_TEMPLATE = """
    <svg class="bd-placeholder-img rounded me-2" width="20" height="20"
         xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice"
         focusable="false" role="img">
        <rect width="100%" height="100%" fill="{}"></rect>
    </svg>
"""

SYSTEM_COLUMNS = [
    "orochi_createdAt",
    "orochi_os",
    "orochi_plugin",
    "down_path",
]

PLUGIN_WITH_CHILDREN = {
    "frameworkinfo.frameworkinfo": "Data",
    "linux.iomem.iomem": "Name",
    "linux.pstree.pstree": "PID",
    "windows.devicetree.devicetree": "Offset",
    "windows.mbrscan.mbrscan": "Potential MBR at Physical Offset",
    "windows.mftscan.mftscan": "Offset",
    "windows.pstree.pstree": "PID",
    "windows.registry.userassist.userassist": "Hive Offset",
}

INDEX_VALUES_LIST = [
    "folder__name",
    "index",
    "name",
    "color",
    "operating_system",
    "author",
    "upload",
    "status",
    "description",
]


##############################
# READONLY CHECK
##############################
def is_not_readonly(user):
    """Check if user is readonly"""
    return not user.groups.filter(name="ReadOnly").exists()


##############################
# PLUGIN
##############################
def plugin_f_and_f(dump, plugin, params, user_pk=None):
    """Fire and forget plugin on dask"""
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    fire_and_forget(dask_client.submit(run_plugin, dump, plugin, params, user_pk))


def handle_uploaded_file(index, plugin, f):
    """Manage file upload for plugin that requires file, put them with plugin files"""
    path = Path(f"{settings.MEDIA_ROOT}/{index}/{plugin}")
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
    with open(f"{path}/{f}", "wb+") as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return f"{path}/{f}"


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["POST"])
def plugin(request):
    """Prepares for plugin resubmission on selected index with/without parameters"""
    indexes = request.POST.get("selected_indexes").split(",")
    plugin = get_object_or_404(Plugin, name=request.POST.get("selected_plugin"))
    get_object_or_404(UserPlugin, plugin=plugin, user=request.user)

    for index in indexes:
        dump = get_object_or_404(Dump, index=index)
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return JsonResponse({"status_code": 403, "error": "Unauthorized"})

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

                elif parameter["type"] == bool:
                    params[parameter["name"]] = request.POST.get(parameter["name"]) in [
                        "true",
                        "on",
                    ]

                else:
                    params[parameter["name"]] = request.POST.get(parameter["name"])

        for filename in request.FILES:
            filepath = handle_uploaded_file(
                dump.index, plugin.name, request.FILES.get(filename)
            )
            params[filename] = f"file:{pathname2url(filepath)}"

        # REMOVE OLD DATA
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        es_client.indices.delete(
            index=f"{dump.index}_{plugin.name.lower()}", ignore=[400, 404]
        )

        result.result = RESULT_STATUS_RUNNING
        result.description = None
        result.parameter = params
        result.save()

        plugin_f_and_f(dump, plugin, params, request.user.pk)
    return JsonResponse(
        {
            "ok": True,
            "plugin": plugin.name,
            "names": request.POST.get("selected_names").split(","),
        }
    )


@login_required
@user_passes_test(is_not_readonly)
def parameters(request):
    """Get parameters from volatility api, returns form"""
    data = {}

    if request.method == "POST":
        form = ParametersForm(data=request.POST)
        data["form_is_valid"] = bool(form.is_valid())
    else:
        data = {
            "selected_plugin": request.GET.get("selected_plugin"),
            "selected_indexes": ",".join(request.GET.getlist("selected_indexes[]")),
            "selected_names": ",".join(request.GET.getlist("selected_names[]")),
        }
        parameters = get_parameters(data["selected_plugin"])
        form = ParametersForm(initial=data, dynamic_fields=parameters)

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_params.html",
        context,
        request=request,
    )
    return JsonResponse(data)


##############################
# RESULTS
##############################
@login_required
def generate(request):
    """Sliced data request for analysis ajax datatables request"""
    if request.META.get("HTTP_X_REQUESTED_WITH") != "XMLHttpRequest":
        return JsonResponse({"status_code": 405, "error": "Method Not Allowed"})
    ui_columns = request.GET.getlist("columns[]")
    draw = request.GET.get("draw")

    if ui_columns == ["Loading"]:
        return JsonResponse(
            {
                "draw": draw,
                "recordsTotal": 1,
                "recordsFiltered": 1,
                "data": [["Please wait"]],
            }
        )
    elif ui_columns == ["Empty"]:
        return JsonResponse(
            {
                "draw": draw,
                "recordsTotal": 1,
                "recordsFiltered": 1,
                "data": [["Empty data"]],
            }
        )

    es_client = Elasticsearch([settings.ELASTICSEARCH_URL])

    # GET DATA
    indexes = request.GET.getlist("indexes[]")
    plugin = request.GET.get("plugin")
    start = int(request.GET.get("start"))
    length = int(request.GET.get("length"))
    search = request.GET.get("search[value]")

    # GET PLUGIN INFO
    plugin = get_object_or_404(Plugin, name=plugin)

    # GET DICT OF COLOR AND CHECK PERMISSIONS
    dumps = Dump.objects.filter(index__in=indexes)
    colors = {}
    for dump in dumps:
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return JsonResponse({"status_code": 403, "error": "Unauthorized"})
        colors[dump.index] = dump.color

    # GET ALL RESULTS
    results = (
        Result.objects.select_related("dump", "plugin")
        .filter(plugin__name=plugin, dump__index__in=indexes)
        .order_by("dump__name", "plugin__name")
    )

    # SEARCH FOR ITEMS AND KEEP INDEX
    indexes_list = [
        f"{res.dump.index}_{res.plugin.name.lower()}"
        for res in results
        if res.result == RESULT_STATUS_SUCCESS
    ]

    data = []
    filtered = 0
    total = 0
    if indexes_list:
        s = Search(using=es_client, index=indexes_list).extra(track_total_hits=True)
        total = s.count()
        if search:
            s = s.query("simple_query_string", query=search)
        filtered = s.count()
        s = s[start : start + length]
        result = s.execute()

        # ANNOTATE RESULTS WITH INDEX NAME
        info = [
            (hit.to_dict(), hit.meta.index.split("_")[0])
            for hit in result
            if hit.meta.index.split("_")[0] != ".kibana"
        ]

        try:
            _ = Service.objects.get(name=SERVICE_MISP)
            misp_configured = True
        except Service.DoesNotExist:
            misp_configured = False

        # Add color and actions to each row
        for item, item_index in info:
            if item.get("down_path"):
                item["actions"] = render_to_string(
                    "website/file_download.html",
                    {
                        "down_path": item["down_path"],
                        "misp_configured": misp_configured,
                        "regipy": Path(f"{item['down_path']}.regipy.json").exists(),
                        "vt": (
                            # if empty read is false
                            open(f"{item['down_path']}.vt.json").read()
                            if Path(f"{item['down_path']}.vt.json").exists()
                            else None
                        ),
                    },
                )

            item.update({"color": COLOR_TEMPLATE.format(colors[item_index])})
            list_row = []
            for column in ui_columns:
                if column in item.keys():
                    list_row.append(item[column])
                else:
                    list_row.append("-")
            data.append(list_row)
    return JsonResponse(
        {
            "draw": draw,
            "recordsTotal": total,
            "recordsFiltered": filtered,
            "data": data,
        }
    )


def change_keys(obj, title):
    """Change keys for tree rendering"""
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            if k in SYSTEM_COLUMNS:
                continue
            elif k == "__children":
                if v != []:
                    new["children"] = change_keys(v, title)
                else:
                    continue
            elif k == title:
                new["title"] = v
            else:
                new[k] = v or "-"
    elif isinstance(obj, list):
        new = [change_keys(v, title) for v in obj]
    else:
        return obj
    return new


@login_required
def analysis(request):
    """Get and transform results for selected plugin on selected indexes"""
    if request.META.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest":
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
                return JsonResponse({"status_code": 403, "error": "Unauthorized"})
            colors[dump.index] = dump.color

        # GET ALL RESULTS
        results = (
            Result.objects.select_related("dump", "plugin")
            .filter(plugin__name=plugin, dump__index__in=indexes)
            .order_by("dump__name", "plugin__name")
        )

        # GENERATE NOTE TO SHOW ON TOP
        note = [
            {
                "dump_name": res.dump.name,
                "os": res.dump.operating_system,
                "disabled": res.plugin.disabled,
                "index": res.dump.index,
                "result": res.get_result_display(),
                "description": res.description,
                "color": COLOR_TEMPLATE.format(colors[res.dump.index]),
            }
            for res in results
        ]

        # If table we will generate data dynamically
        if plugin.name.lower() not in PLUGIN_WITH_CHILDREN.keys():
            columns = []
            for res in results:
                if res.result == RESULT_STATUS_NOT_STARTED and columns == []:
                    columns = ["Not started"]
                elif res.result == RESULT_STATUS_RUNNING and columns == []:
                    columns = ["Loading"]
                elif res.result == RESULT_STATUS_EMPTY and columns == []:
                    columns = ["Empty"]
                elif res.result == RESULT_STATUS_SUCCESS:
                    try:
                        index = f"{res.dump.index}_{res.plugin.name.lower()}"

                        # GET COLUMNS FROM ELASTIC
                        mappings = es_client.indices.get_mapping(index=index)
                        columns = (
                            ["color"]
                            + [
                                x
                                for x in mappings[index]["mappings"]["properties"]
                                if x not in SYSTEM_COLUMNS
                            ]
                            + ["actions"]
                        )
                    except elasticsearch.NotFoundError:
                        continue
                elif res.result != RESULT_STATUS_DISABLED and columns == []:
                    columns = ["Disabled"]

            maxmind = (
                os.path.exists("/maxmind/GeoLite2-ASN.mmdb")
                or os.path.exists("/maxmind/GeoLite2-City.mmdb")
                or os.path.exists("/maxmind/GeoLite2-Country.mmdb")
            )
            return render(
                request,
                "website/partial_analysis.html",
                {
                    "note": note,
                    "columns": columns,
                    "plugin": plugin.name,
                    "maxmind": maxmind,
                },
            )

        columns = None
        # SEARCH FOR ITEMS AND KEEP INDEX
        if indexes_list := [
            f"{res.dump.index}_{res.plugin.name.lower()}"
            for res in results
            if res.result == RESULT_STATUS_SUCCESS
        ]:
            s = Search(using=es_client, index=indexes_list).extra(
                size=settings.MAX_ELASTIC_WINDOWS_SIZE
            )
            result = s.execute()
            # ANNOTATE RESULTS WITH INDEX NAME
            if info := [
                (hit.to_dict(), hit.meta.index.split("_")[0]) for hit in result
            ]:
                columns = (
                    [PLUGIN_WITH_CHILDREN[plugin.name.lower()]]
                    + [
                        x
                        for x in info[0][0].keys()
                        if x
                        not in SYSTEM_COLUMNS
                        + [PLUGIN_WITH_CHILDREN[plugin.name.lower()], "__children"]
                    ]
                    + ["color"]
                )

        # If tree we will render tree and get data dynamically
        context = {
            "columns": columns,
            "note": note,
            "empty": not bool(columns),
            "plugin": plugin.name,
        }
        return render(request, "website/partial_tree.html", context)

    raise Http404("404")


@login_required
def tree(request):
    es_client = Elasticsearch([settings.ELASTICSEARCH_URL])

    # GET DATA
    plugin = request.GET.get("plugin")
    indexes = request.GET.getlist("indexes[]")

    # GET PLUGIN INFO
    plugin = get_object_or_404(Plugin, name=plugin)

    # GET DICT OF COLOR AND CHECK PERMISSIONS
    dumps = Dump.objects.filter(index__in=indexes)
    colors = {}
    for dump in dumps:
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return JsonResponse({"status_code": 403, "error": "Unauthorized"})
        colors[dump.index] = dump.color

    # GET ALL RESULTS
    results = (
        Result.objects.select_related("dump", "plugin")
        .filter(plugin__name=plugin, dump__index__in=indexes)
        .order_by("dump__name", "plugin__name")
    )

    data = []
    # SEARCH FOR ITEMS AND KEEP INDEX
    if indexes_list := [
        f"{res.dump.index}_{res.plugin.name.lower()}"
        for res in results
        if res.result == RESULT_STATUS_SUCCESS
    ]:
        s = Search(using=es_client, index=indexes_list).extra(
            size=settings.MAX_ELASTIC_WINDOWS_SIZE
        )
        result = s.execute()

        # column used for icon accordion
        title = PLUGIN_WITH_CHILDREN[plugin.name.lower()]

        # ANNOTATE RESULTS WITH INDEX NAME
        if info := [
            (hit.to_dict(), hit.meta.index.split("_")[0])
            for hit in result
            if hit.meta.index.split("_")[0] != ".kibana"
        ]:
            for item, item_index in info:
                item = change_keys(item, title)
                item["color"] = colors[item_index]
                data.append(item)
    return JsonResponse(data, safe=False)


##############################
# SPECIAL VIEWER
##############################
@login_required
def vt(request):
    """show vt report in dialog"""
    path = request.GET.get("path")
    if Path(path).exists():
        data = json.loads(open(path, "r").read())
        return render(
            request,
            "website/partial_json.html",
            {"data": data, "title": "VirusTotal Report"},
        )
    return render(
        request,
        "website/partial_json.html",
        {"error": "VT report not found", "title": "VirusTotal Repor"},
    )


@login_required
def hex_view(request, index):
    """Render hex view for dump"""
    dump = get_object_or_404(Dump, index=index)
    return render(request, "website/hex_view.html", {"index": index, "name": dump.name})


@login_required
def get_hex(request, index):
    """Return Json data via json"""
    try:
        start = int(request.GET.get("start", 0)) * 16
        draw = int(request.GET.get("draw", 0))
        length = int(request.GET.get("length", 50)) * 16
    except ValueError as e:
        return JsonResponse({"status_code": 404, "error": str(e)})

    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return JsonResponse({"status_code": 403, "error": "Unauthorized"})

    data, size = get_hex_rec(dump.upload.path, length, start)
    return JsonResponse(
        {
            "data": data,
            "recordsTotal": size,
            "recordsFiltered": size,
            "draw": draw,
        },
        status=200,
        safe=False,
    )


@login_required
def search_hex(request, index):
    """Search for string in memory, return occurence following actual position"""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return JsonResponse({"status_code": 403, "error": "Unauthorized"})

    findstr = request.GET.get("findstr", None)
    try:
        last = int(request.GET.get("last", None)) + 1
    except ValueError as e:
        return JsonResponse({"status_code": 404, "error": str(e)})

    with open(dump.upload.path, "r+b") as f:
        map_file = mmap.mmap(f.fileno(), length=0, prot=mmap.PROT_READ)
        if m := re.search(f"(?i){findstr}".encode("utf-8"), map_file[last:]):
            new_offset, _ = m.span()
            return JsonResponse({"found": 1, "pos": new_offset + last}, status=200)
        if m := re.search(f"(?i){findstr}".encode("utf-8"), map_file[:]):
            new_offset, _ = m.span()
            return JsonResponse({"found": 1, "pos": new_offset}, status=200)
        return JsonResponse({"found": -1, "pos": 0}, status=200)


def get_hex_rec(path, length, start):
    """Returns formatted portion of memory"""
    with open(path, "r+b") as f:
        try:
            map_file = mmap.mmap(f.fileno(), length=length + start, prot=mmap.PROT_READ)
        # if start + length > size
        except ValueError:
            map_file = mmap.mmap(f.fileno(), length=0, prot=mmap.PROT_READ)

        map_file.seek(start)
        values = []
        data = map_file.read(length)
        parts = [data[i : i + 16] for i in range(0, len(data), 16)]
        for i, line in enumerate(parts):
            idx = start + i * 16
            values.append(
                (
                    f"{idx:08x}",
                    " ".join([f"{x:02x}" for x in line]),
                    " ".join(
                        [
                            (
                                "<span class='singlechar'>.</span>"
                                if int(f"{x:02x}", 16) <= 32
                                or 127 <= int(f"{x:02x}", 16) <= 160
                                or int(f"{x:02x}", 16) == 173
                                else f"<span class='singlechar'>{chr(x)}</span>"
                            )
                            for x in line
                        ]
                    ),
                )
            )

        return values, map_file.size() / 16


@login_required
def json_view(request, filepath):
    """Render json for hive dump"""
    index = filepath.split("/")[2]
    dump = get_object_or_404(Dump, index=index)
    if not Path(filepath).exists() and dump not in get_objects_for_user(
        request.user, "website.can_see"
    ):
        raise Http404("404")
    with open(filepath, "r") as f:
        values = json.load(f)
        context = {"data": json.dumps(values)}
    return render(request, "website/json_view.html", context)


@login_required
def diff_view(request, index_a, index_b, plugin):
    """Compare json views"""
    dump1 = get_object_or_404(Dump, index=index_a)
    dump2 = get_object_or_404(Dump, index=index_b)
    if dump1 not in get_objects_for_user(
        request.user, "website.can_see"
    ) or dump2 not in get_objects_for_user(request.user, "website.can_see"):
        raise Http404("404")
    es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
    search_a = (
        Search(using=es_client, index=[f"{index_a}_{plugin.lower()}"])
        .extra(size=settings.MAX_ELASTIC_WINDOWS_SIZE)
        .execute()
    )
    info_a = json.dumps([hit.to_dict() for hit in search_a])
    search_b = (
        Search(using=es_client, index=[f"{index_b}_{plugin.lower()}"])
        .extra(size=settings.MAX_ELASTIC_WINDOWS_SIZE)
        .execute()
    )
    info_b = json.dumps([hit.to_dict() for hit in search_b])
    return render(
        request, "website/diff_view.html", {"info_a": info_a, "info_b": info_b}
    )


##############################
# RESTART
##############################
@login_required
@user_passes_test(is_not_readonly)
def restart(request):
    """Restart plugin on index"""
    if request.META.get("HTTP_X_REQUESTED_WITH") != "XMLHttpRequest":
        return JsonResponse({"status_code": 405, "error": "Method Not Allowed"})
    dump = get_object_or_404(Dump, index=request.GET.get("index"))
    with transaction.atomic():
        plugins = UserPlugin.objects.filter(
            plugin__operating_system__in=[
                dump.operating_system,
                "Other",
            ],
            user=request.user,
            plugin__disabled=False,
            automatic=True,
        )
        if plugins.count() > 0:
            plugins_id = [plugin.plugin.id for plugin in plugins]
            results = Result.objects.filter(plugin__pk__in=plugins_id, dump=dump)
            for result in results:
                result.result = RESULT_STATUS_RUNNING
            Result.objects.bulk_update(results, ["result"])
            transaction.on_commit(
                lambda: index_f_and_f(
                    dump.pk, request.user.pk, password=None, restart=plugins_id
                )
            )
    return JsonResponse({"ok": True}, safe=False)


##############################
# EXPORT
##############################
@login_required
@require_http_methods(["GET"])
def export(request):
    """Export extracted dump to misp"""
    filepath = request.GET.get("path")
    _, _, index, plugin, _ = filepath.split("/")
    misp_info = get_object_or_404(Service, name=SERVICE_MISP)
    dump = get_object_or_404(Dump, index=index)
    _ = get_object_or_404(Plugin, name=plugin)

    plugin = plugin.lower()

    # CREATE GENERIC EVENT
    misp = PyMISP(misp_info.url, misp_info.key, False, proxies=misp_info.proxy)
    event = MISPEvent()
    event.info = f"From orochi: {plugin}@{dump.name}"

    # CREATE FILE OBJ
    file_obj = FileObject(filepath)
    event.add_object(file_obj)

    es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
    if s := (
        Search(using=es_client, index=f"{index}_{plugin}")
        .query({"match": {"down_path": filepath}})
        .execute()
    ):
        s = s[0].to_dict()

        # ADD CLAMAV SIGNATURE
        if s.get("clamav"):
            clamav_obj = MISPObject("av-signature")
            clamav_obj.add_attribute("signature", value=s["clamav"])
            clamav_obj.add_attribute("software", value="clamav")
            file_obj.add_reference(clamav_obj.uuid, "attributed-to")
            event.add_object(clamav_obj)

        # ADD VT SIGNATURE
        if Path(f"{filepath}.vt.json").exists():
            with open(f"{filepath}.vt.json", "r") as f:
                vt = json.load(f)
                vt_obj = MISPObject("virustotal-report")
                vt_obj.add_attribute("last-submission", value=vt.get("scan_date", ""))
                vt_obj.add_attribute(
                    "detection-ratio",
                    value=f'{vt.get("positives", 0)}/{vt.get("total", 0)}',
                )
                vt_obj.add_attribute("permalink", value=vt.get("permalink", ""))
                file_obj.add_reference(vt.uuid, "attributed-to")
                event.add_object(vt_obj)

        misp.add_event(event)
        return JsonResponse({"success": True})
    return JsonResponse({"status_code": 404, "error": "No data found"})


##############################
# BOOKMARKS
##############################
@login_required
@require_http_methods(["GET"])
def add_bookmark(request):
    """Add bookmark in user settings"""
    data = {
        "html_form": render_to_string(
            "website/partial_bookmark_create.html",
            {"form": BookmarkForm()},
            request=request,
        )
    }
    return JsonResponse(data)


@login_required
@require_http_methods(["GET"])
def edit_bookmark(request):
    """Edit bookmark information"""
    bookmark = get_object_or_404(Bookmark, pk=request.GET.get("pk"), user=request.user)
    context = {"form": EditBookmarkForm(instance=bookmark), "id": bookmark.pk}
    data = {
        "html_form": render_to_string(
            "website/partial_bookmark_edit.html", context, request=request
        )
    }
    return JsonResponse(data)


@login_required
def bookmarks(request, indexes, plugin, query=None):
    """Open index but from a stored configuration of indexes and plugin"""
    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .values_list(*INDEX_VALUES_LIST)
        .order_by("folder__name", "name"),
        "selected_indexes": indexes,
        "selected_plugin": plugin,
        "selected_query": query,
    }
    return TemplateResponse(request, "website/index.html", context)


##############################
# FOLDER
##############################
@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET"])
def folder_create(request):
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_folder.html",
                {"form": FolderForm()},
                request=request,
            )
        }
    )


##############################
# DUMP
##############################
@login_required
def info(request):
    """Get index info"""
    dump = get_object_or_404(Dump, index=request.GET.get("index"))
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        Http404("404")
    return TemplateResponse(request, "website/partial_index_info.html", {"dump": dump})


@login_required
def index(request):
    """List of available indexes"""
    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .values_list(*INDEX_VALUES_LIST)
        .order_by("folder__name", "name"),
        "selected_indexes": [],
        "selected_plugin": None,
        "selected_query": None,
        "readonly": is_not_readonly(request.user),
    }
    return TemplateResponse(request, "website/index.html", context)


@login_required
def download(request):
    """Download dump data"""
    filepath = request.GET.get("path")
    index = filepath.split("/")[2]
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        raise Http404("404")
    if os.path.exists(filepath):
        with open(filepath, "rb") as fh:
            response = HttpResponse(
                fh.read(), content_type="application/force-download"
            )
            response["Content-Disposition"] = (
                f"inline; filename={os.path.basename(filepath)}"
            )
            return response
    return Http404("404")


@login_required
@user_passes_test(is_not_readonly)
def edit(request):
    """Edit index information"""
    data = {}
    dump = None

    if request.method == "POST":
        dump = get_object_or_404(Dump, index=request.POST.get("index"))
    elif request.method == "GET":
        dump = get_object_or_404(Dump, index=request.GET.get("index"))

    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return JsonResponse({"status_code": 403, "error": "Unauthorized"})

    auth_users = [
        user.pk
        for user in get_user_model().objects.all()
        if "can_see" in get_perms(user, dump) and user != request.user
    ]

    if request.method == "POST":
        form = EditDumpForm(
            data=request.POST,
            instance=dump,
            initial={"authorized_users": auth_users},
            user=request.user,
        )
        if form.is_valid():
            dump = form.save()
            for user_pk in form.cleaned_data["authorized_users"]:
                user = get_user_model().objects.get(pk=user_pk)
                if user.pk not in auth_users:
                    assign_perm(
                        "can_see",
                        user,
                        dump,
                    )
            for user_pk in auth_users:
                if user_pk not in form.cleaned_data["authorized_users"]:
                    user = get_user_model().objects.get(pk=user_pk)
                    remove_perm("can_see", user, dump)

            data["form_is_valid"] = True
            data["dumps"] = render_to_string(
                "website/partial_indices.html",
                {
                    "dumps": get_objects_for_user(request.user, "website.can_see")
                    .values_list(*INDEX_VALUES_LIST)
                    .order_by("folder__name", "name")
                },
                request=request,
            )
        else:
            data["form_is_valid"] = False
    else:
        form = EditDumpForm(
            instance=dump, initial={"authorized_users": auth_users}, user=request.user
        )

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_index_edit.html",
        context,
        request=request,
    )
    return JsonResponse(data)


def index_f_and_f(dump_pk, user_pk, password=None, restart=None, move=True):
    """Run all plugin for a new index on dask"""
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    fire_and_forget(
        dask_client.submit(unzip_then_run, dump_pk, user_pk, password, restart, move)
    )


@login_required
@user_passes_test(is_not_readonly)
def create(request):
    """Manage new index creation"""
    data = {}
    errors = None

    if request.method == "POST":
        form = DumpForm(current_user=request.user, data=request.POST)
        if form.is_valid():
            with transaction.atomic():
                mode = form.cleaned_data["mode"]
                dump_index = str(uuid.uuid1())
                os.mkdir(f"{settings.MEDIA_ROOT}/{dump_index}")

                try:
                    dump = form.save(commit=False)
                    if mode == "upload":
                        dump.upload = form.cleaned_data["upload"]
                        move = True
                    else:
                        filename = os.path.basename(form.cleaned_data["local_folder"])
                        shutil.move(
                            form.cleaned_data["local_folder"],
                            f"{settings.MEDIA_ROOT}/{dump_index}",
                        )
                        dump.upload.name = (
                            f"{settings.MEDIA_URL}{dump_index}/{filename}"
                        )
                        move = False
                    dump.author = request.user

                    dump.index = dump_index
                    dump.save()
                    form.delete_temporary_files()

                    data["form_is_valid"] = True

                    # for each plugin enabled and for that os I create a result
                    # if the user selected that for automation, run it immediately on dask
                    Result.objects.bulk_create(
                        [
                            Result(
                                plugin=up.plugin,
                                dump=dump,
                                result=(
                                    RESULT_STATUS_RUNNING
                                    if up.automatic
                                    else RESULT_STATUS_NOT_STARTED
                                ),
                            )
                            for up in UserPlugin.objects.filter(
                                plugin__operating_system__in=[
                                    dump.operating_system,
                                    "Other",
                                ],
                                user=request.user,
                                plugin__disabled=False,
                            )
                        ]
                    )

                    transaction.on_commit(
                        lambda: index_f_and_f(
                            dump.pk,
                            request.user.pk,
                            password=form.cleaned_data["password"],
                            restart=None,
                            move=move,
                        )
                    )

                    # Return the new list of available indexes
                    data["form_is_valid"] = True
                    data["dumps"] = render_to_string(
                        "website/partial_indices.html",
                        {
                            "dumps": get_objects_for_user(
                                request.user, "website.can_see"
                            )
                            .values_list(*INDEX_VALUES_LIST)
                            .order_by("folder__name", "name")
                        },
                        request=request,
                    )
                except (
                    psycopg2.errors.UniqueViolation,
                    django.db.utils.IntegrityError,
                ):
                    data["form_is_valid"] = False
                    errors = {"name": "Dump name already used!"}
        else:
            errors = form.errors
            data["form_is_valid"] = False
    else:
        form = DumpForm(current_user=request.user)

    context = {"form": form, "errors": errors}
    data["html_form"] = render_to_string(
        "website/partial_index_create.html",
        context,
        request=request,
    )
    return JsonResponse(data)


@login_required
@user_passes_test(is_not_readonly)
def delete(request):
    """Delete an index"""
    if request.META.get("HTTP_X_REQUESTED_WITH") != "XMLHttpRequest":
        return JsonResponse({"status_code": 405, "error": "Method Not Allowed"})
    es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
    index = request.GET.get("index")
    dump = Dump.objects.get(index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return JsonResponse({"status_code": 403, "error": "Unauthorized"})
    dump.delete()
    es_client.indices.delete(index=f"{index}*", ignore=[400, 404])
    shutil.rmtree(f"{settings.MEDIA_ROOT}/{dump.index}")
    return JsonResponse({"ok": True}, safe=False)


##############################
# ADMIN
##############################
def update_plugins(request):
    """Run management command to update plugins"""
    if request.user.is_superuser:
        management.call_command("plugins_sync", verbosity=0)
        messages.add_message(request, messages.INFO, "Sync Plugin done")
        return redirect("/admin")
    raise Http404("404")


def update_symbols(request):
    """Run management command to update symbols"""
    if request.user.is_superuser:
        management.call_command("symbols_sync", verbosity=0)
        messages.add_message(request, messages.INFO, "Sync Symbols done")
        return redirect("/admin")
    raise Http404("404")


##############################
# SYMBOLS
##############################
@login_required
@user_passes_test(is_not_readonly)
def banner_symbols(request):
    """Return suggested banner and a button to download item"""
    data = {}
    if request.method == "POST":
        dump = get_object_or_404(Dump, index=request.POST.get("index"))
        form = SymbolBannerForm(
            instance=dump,
            data=request.POST,
        )
        if form.is_valid():
            d = Downloader(
                url_list=form.data["path"].split(","),
                operating_system=dump.operating_system,
            )
            d.download_list()

            form.delete_temporary_files()

            if check_runnable(dump.pk, dump.operating_system, dump.banner):
                dump.status = DUMP_STATUS_COMPLETED
                dump.save()

            data["form_is_valid"] = True
            data["dumps"] = render_to_string(
                "website/partial_indices.html",
                {
                    "dumps": get_objects_for_user(request.user, "website.can_see")
                    .values_list(*INDEX_VALUES_LIST)
                    .order_by("folder__name", "name")
                },
                request=request,
            )
        else:
            data["form_is_valid"] = False
    else:
        dump = get_object_or_404(Dump, index=request.GET.get("index"))
        form = SymbolBannerForm(
            instance=dump, initial={"path": dump.suggested_symbols_path}
        )

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_symbols_banner.html",
        context,
        request=request,
    )
    return JsonResponse(data)


@login_required
@user_passes_test(is_not_readonly)
def list_symbols(request):
    """Return list of symbols"""
    return render(request, "website/list_symbols.html")


@login_required
@user_passes_test(is_not_readonly)
def iterate_symbols(request):
    """Ajax rules return for datatables"""
    start = int(request.GET.get("start"))
    length = int(request.GET.get("length"))
    search = request.GET.get("search[value]")
    symbols = []

    ctx = contexts.Context()
    automagics = automagic.available(ctx)
    if banners := [x for x in automagics if x._config_path == "automagic.SymbolFinder"]:
        banner = banners[0].banners
    else:
        banner = []
    for k, v in banner.items():
        try:
            k = k.decode("utf-8")
        except AttributeError:
            k = str(k)
        if search and (search not in k and search not in str(v)):
            continue

        if "file://" in str(v):
            path = (
                str(v)
                .replace("file://", "")
                .replace(settings.VOLATILITY_SYMBOL_PATH, "")
            )
            action = ""
            if "/added/" in str(v):
                action = f"<a class='btn btn-sm btn-outline-danger symbol-delete' data-path='{path}' href='#'><i class='fas fa-trash'></i></a>"
        else:
            path = str(v)
            action = f"<a class='btn btn-sm btn-outline-warning' href='{str(v)}'><i class='fas fa-download'></i></a>"

        symbols.append((k, path, action))

    return_data = {
        "recordsTotal": len(banner.keys()),
        "recordsFiltered": len(symbols),
        "data": symbols[start : start + length],
    }
    return JsonResponse(return_data)


@login_required
@user_passes_test(is_not_readonly)
def upload_symbols(request):
    """Upload symbols"""
    data = {}
    if request.method == "POST":
        form = SymbolUploadForm(data=request.POST)
        if form.is_valid():

            # IF ZIP
            for symbol in form.cleaned_data["symbols"]:
                filetype = magic.from_file(symbol.file.path, mime=True)
                path = Path(settings.VOLATILITY_SYMBOL_PATH) / "added"
                path.mkdir(parents=True, exist_ok=True)
                if filetype in [
                    "application/zip",
                    "application/x-7z-compressed",
                    "application/x-rar",
                    "application/gzip",
                    "application/x-tar",
                ]:
                    subprocess.call(
                        ["7z", "e", f"{symbol.file.path}", f"-o{path}", "-y"]
                    )
                else:
                    shutil.move(symbol.file.path, f"{path}/{symbol.name}")
            form.delete_temporary_files()
            refresh_symbols()
            data["form_is_valid"] = True
        else:
            data["form_is_valid"] = False
    else:
        form = SymbolUploadForm()

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_symbols_upload.html",
        context,
        request=request,
    )
    return JsonResponse(data)


@login_required
@user_passes_test(is_not_readonly)
def delete_symbol(request):
    """delete single symbol"""
    path = request.GET.get("path")
    symbol_path = f"{settings.VOLATILITY_SYMBOL_PATH}{path}"
    if Path(symbol_path).exists() and symbol_path.find("/added/") != -1:
        os.unlink(symbol_path)
        refresh_symbols()
        return JsonResponse({"ok": True})
    return JsonResponse({"status_code": 405, "error": "Method Not Allowed"})


@login_required
@user_passes_test(is_not_readonly)
def reload_symbols(request):
    """reload symbols"""
    dump = get_object_or_404(Dump, index=request.GET.get("index"))

    # Try to reload banner from elastic if first time was not successful
    if not dump.banner:
        banner = dump.result_set.get(plugin__name="banners.Banners")
        if banner_result := get_banner(banner):
            dump.banner = banner_result.strip("\"'")
            dump.save()

    change = False
    if check_runnable(dump.pk, dump.operating_system, dump.banner):
        change = True
        dump.status = DUMP_STATUS_COMPLETED
        dump.save()
    return JsonResponse({"ok": True, "change": change})


@login_required
@user_passes_test(is_not_readonly)
def download_isf(request):
    """Download all symbols from provided isf server path"""
    data = {}
    if request.method == "POST":
        form = SymbolISFForm(data=request.POST)
        if form.is_valid():
            path = form.cleaned_data["path"]
            domain = slugify(urlparse(path).netloc)
            media_path = Path(f"{settings.VOLATILITY_SYMBOL_PATH}/{domain}")
            media_path.mkdir(exist_ok=True, parents=True)
            try:
                data = json.loads(requests.get(path).content)
            except Exception:
                return JsonResponse(
                    {"status_code": 404, "error": "Error parsing symbols"}
                )

            def download_file(url, path):
                try:
                    response = requests.get(url)
                    with open(path, "wb") as f:
                        f.write(response.content)
                except Exception as excp:
                    print(excp)

            with concurrent.futures.ThreadPoolExecutor() as executor:
                for key in data:
                    if key not in ["linux", "mac", "windows"]:
                        continue
                    for urls in data[key].values():
                        for url in urls:
                            filename = url.split("/")[-1]
                            filepath = f"{media_path}/{filename}"
                            executor.submit(download_file, url, filepath)

            refresh_symbols()
            data["form_is_valid"] = True
        else:
            data["form_is_valid"] = False
    else:
        form = SymbolISFForm()

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_isf_download.html",
        context,
        request=request,
    )
    return JsonResponse(data)


@login_required
@user_passes_test(is_not_readonly)
def upload_packages(request):
    """Generate symbols from uploaded file"""
    data = {}
    if request.method == "POST":
        form = SymbolPackageForm(data=request.POST)
        if form.is_valid():
            d = Downloader(
                file_list=[
                    (package.file.path, package.name)
                    for package in form.cleaned_data["packages"]
                ]
            )
            d.process_list()
            form.delete_temporary_files()
            refresh_symbols()
            data["form_is_valid"] = True
        else:
            data["form_is_valid"] = False
    else:
        form = SymbolPackageForm()

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_packages_upload.html",
        context,
        request=request,
    )
    return JsonResponse(data)


##############################
# RULES
##############################
@login_required
@user_passes_test(is_not_readonly)
def list_custom_rules(request):
    """Ajax rules return for datatables"""
    start = int(request.GET.get("start"))
    length = int(request.GET.get("length"))
    search = request.GET.get("search[value]")

    sort_column = int(request.GET.get("order[0][column]"))
    sort_order = request.GET.get("order[0][dir]")

    sort = ["pk", "name", "path", "public", "user"][sort_column]
    if sort_order == "desc":
        sort = f"-{sort}"

    rules = CustomRule.objects.filter(Q(public=True) | Q(user=request.user))

    filtered_rules = rules.filter(Q(name__icontains=search) | Q(path__icontains=search))

    data = filtered_rules.order_by(sort)[start : start + length]

    return_data = {
        "recordsTotal": rules.count(),
        "recordsFiltered": filtered_rules.count(),
        "data": [
            [x.pk, x.name, x.path, x.user.username, x.public, x.default] for x in data
        ],
    }
    return JsonResponse(return_data)
