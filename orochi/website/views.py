import json
import mmap
import os
import re
import shlex
import shutil
import urllib
import uuid
from datetime import datetime
from glob import glob
from tempfile import NamedTemporaryFile
from urllib.request import pathname2url

import elasticsearch
import requests
from dask.distributed import Client, fire_and_forget
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core import management
from django.db import transaction
from django.db.models import Q
from django.http import Http404, JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from guardian.shortcuts import assign_perm, get_objects_for_user, get_perms, remove_perm
from pymisp import MISPEvent, MISPObject, PyMISP
from pymisp.tools import FileObject

from orochi.utils.download_symbols import Downloader
from orochi.utils.plugin_install import plugin_install
from orochi.utils.volatility_dask_elk import (
    check_runnable,
    get_parameters,
    run_plugin,
    unzip_then_run,
)
from orochi.website.forms import (
    BookmarkForm,
    DumpForm,
    EditBookmarkForm,
    EditDumpForm,
    MispExportForm,
    ParametersForm,
    SymbolForm,
)
from orochi.website.models import (
    Bookmark,
    CustomRule,
    Dump,
    ExtractedDump,
    Plugin,
    Result,
    Service,
    UserPlugin,
)

COLOR_TEMPLATE = """
    <svg class="bd-placeholder-img rounded mr-2" width="20" height="20"
         xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice"
         focusable="false" role="img">
        <rect width="100%" height="100%" fill="{}"></rect>
    </svg>
"""

COLOR_TIMELINER = {
    "Created Date": "#FF0000",
    "Modified Date": "#00FF00",
    "Accessed Date": "#0000FF",
    "Changed Date": "#FFFF00",
}

SYSTEM_COLUMNS = ["orochi_createdAt", "orochi_os", "orochi_plugin"]


##############################
# CHANGELOG
##############################
@login_required
def changelog(request):
    """Returns changelog"""
    changelog_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "CHANGELOG.md"
    )
    with open(changelog_path, "r") as f:
        changelog_content = "".join(f.readlines())
    return JsonResponse({"note": changelog_content})


##############################
# DASK STATUS
##############################
@login_required
def dask_status(request):
    """Return workers status"""
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    res = dask_client.run_on_scheduler(
        lambda dask_scheduler: {
            w: [(ts.key, ts.state) for ts in ws.processing]
            for w, ws in dask_scheduler.workers.items()
        }
    )
    dask_client.close()
    return JsonResponse(
        {"running": sum(len(running_tasks) for running_tasks in res.values())}
    )


##############################
# PLUGIN
##############################
@login_required
def plugins(request):
    """Return list of plugin for selected indexes"""
    if request.META.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest":
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
    raise Http404("404")


def plugin_f_and_f(dump, plugin, params, user_pk=None):
    """Fire and forget plugin on dask"""
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    fire_and_forget(dask_client.submit(run_plugin, dump, plugin, params, user_pk))


@login_required
def enable_plugin(request):
    """Enable/disable plugin in user settings"""
    if request.method == "POST":
        plugin = request.POST.get("plugin")
        enable = request.POST.get("enable")
        up = get_object_or_404(UserPlugin, pk=plugin, user=request.user)
        up.automatic = enable == "true"
        up.save()
        return JsonResponse({"ok": True})
    raise Http404("404")


def handle_uploaded_file(index, plugin, f):
    """Manage file upload for plugin that requires file, put them with plugin files"""
    if not os.path.exists(f"{settings.MEDIA_ROOT}/{index}/{plugin}"):
        os.mkdir(f"{settings.MEDIA_ROOT}/{index}/{plugin}")
    with open(f"{settings.MEDIA_ROOT}/{index}/{plugin}/{f}", "wb+") as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return f"{settings.MEDIA_ROOT}/{index}/{plugin}/{f}"


@login_required
def plugin(request):
    """Prepares for plugin resubmission on selected index with/without parameters"""
    if request.method == "POST":
        dump = get_object_or_404(Dump, index=request.POST.get("selected_index"))
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            raise Http404("404")
        plugin = get_object_or_404(Plugin, name=request.POST.get("selected_plugin"))
        get_object_or_404(UserPlugin, plugin=plugin, user=request.user)

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

        eds = ExtractedDump.objects.filter(result=result)
        eds.delete()

        result.result = 0
        request.description = None
        result.parameter = params
        result.save()

        plugin_f_and_f(dump, plugin, params, request.user.pk)
        return JsonResponse(
            {
                "ok": True,
                "plugin": plugin.name,
                "name": request.POST.get("selected_name"),
            }
        )
    raise Http404("404")


@login_required
def parameters(request):
    """Get parameters from volatility api, returns form"""
    data = {}

    if request.method == "POST":
        form = ParametersForm(data=request.POST)
        data["form_is_valid"] = bool(form.is_valid())
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
        "website/partial_params.html",
        context,
        request=request,
    )
    return JsonResponse(data)


@login_required
def install_plugin(request):
    """Install plugin from url"""
    plugin_path = request.POST.get("plugin")
    operating_system = request.POST.get("operating_system")
    r = requests.get(plugin_path, allow_redirects=True)
    if r.ok:
        f = NamedTemporaryFile(mode="wb", suffix=".zip", delete=False)
        f.write(r.content)
        f.close()
        plugin_name = plugin_install(f.name)
        Plugin(
            name=plugin_name,
            operating_system=operating_system,
            local=True,
            local_date=datetime.now(),
        )
        return JsonResponse({"ok": True})
    return Http404


##############################
# RESULTS
##############################
@login_required
def generate(request):
    """Sliced data request for analysis ajax datatables request"""
    if request.META.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest":
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
                raise Http404("404")
            colors[dump.index] = dump.color

        # GET ALL RESULTS
        results = (
            Result.objects.select_related("dump", "plugin")
            .filter(plugin__name=plugin, dump__index__in=indexes)
            .order_by("dump__name", "plugin__name")
        )

        # GET ALL EXTRACTED DUMP DUMP
        ex_dumps = {
            x["path"]: x
            for x in ExtractedDump.objects.filter(result__in=results).values(
                "path", "sha256", "md5", "clamav", "vt_report", "pk"
            )
        }

        # SEARCH FOR ITEMS AND KEEP INDEX
        indexes_list = [
            f"{res.dump.index}_{res.plugin.name.lower()}"
            for res in results
            if res.result == 2
        ]

        data = []
        filtered = 0
        if indexes_list:
            s = Search(using=es_client, index=indexes_list).extra(track_total_hits=True)
            total = s.count()
            if search:
                s = s.query("simple_query_string", query=search)
            filtered = s.count()
            s = s[start : start + length]
            result = s.execute()

            # ANNOTATE RESULTS WITH INDEX NAME
            info = [(hit.to_dict(), hit.meta.index.split("_")[0]) for hit in result]

            for item, item_index in info:
                if item_index == ".kibana":
                    continue

                if "File output" in item.keys():
                    glob_path = None
                    base_path = "{}/{}/{}".format(
                        settings.MEDIA_ROOT, item_index, plugin.name
                    )

                    if plugin.name == "windows.dlllist.dlllist":
                        glob_path = "{}/pid.{}.{}.*.{}.dmp".format(
                            base_path,
                            item["PID"],
                            item["Name"],
                            item["Base"],
                        )
                    elif plugin.name.lower() in (
                        "windows.malfind.malfind",
                        "linux.malfind.malfind",
                        "mac.malfind.malfind",
                    ):
                        glob_path = "{}/pid.{}.vad.{}-{}.dmp".format(
                            base_path,
                            item["PID"],
                            item["Start VPN"],
                            item["End VPN"],
                        )
                    elif plugin.name.lower() in [
                        "windows.modscan.modscan",
                        "windows.modules.modules",
                    ]:
                        glob_path = "{}/{}.{}.{}.dmp".format(
                            base_path,
                            item["Path"].split("\\")[-1]
                            if item["Name"]
                            else "UnreadbleDLLName",
                            item["Offset"],
                            item["Base"],
                        )
                    elif plugin.name.lower() in [
                        "windows.pslist.pslist",
                        "linux.pslist.pslist",
                    ]:
                        glob_path = "{}/{}{}.*.dmp".format(
                            base_path,
                            "pid."
                            if plugin.name.lower() != "windows.pslist.pslist"
                            else "",
                            item["PID"],
                        )
                    elif plugin.name.lower() == "linux.proc.maps":
                        glob_path = "{}/pid.{}.*.{}.dmp".format(
                            base_path, item["PID"], f'{item["Start"]}-{item["End"]}'
                        )
                    elif plugin.name.lower() == "windows.registry.hivelist.hivelist":
                        glob_path = "{}/registry.*.{}.hive".format(
                            base_path,
                            item["Offset"],
                        )

                    if glob_path:
                        try:
                            path = glob(glob_path)[0]
                            down_path = path.replace(
                                settings.MEDIA_ROOT, settings.MEDIA_URL.rstrip("/")
                            )

                            item["sha256"] = ex_dumps.get(path, {}).get("sha256", "")
                            item["md5"] = ex_dumps.get(path, {}).get("md5", "")

                            if plugin.clamav_check:
                                value = ex_dumps.get(path, {}).get("clamav", "")
                                item["clamav"] = value or ""

                            if plugin.vt_check:
                                vt_data = ex_dumps.get(path, {}).get("vt_report", {})
                                item["vt_report"] = render_to_string(
                                    "website/small_vt_report.html",
                                    {"vt_data": vt_data},
                                )

                            if plugin.regipy_check:
                                value = ex_dumps.get(path, {}).get("pk", None)
                                item["regipy_report"] = render_to_string(
                                    "website/small_regipy.html", {"value": value}
                                )

                            try:
                                _ = Service.objects.get(name=2)
                                misp_configured = True
                            except Service.DoesNotExist:
                                misp_configured = False

                            item["actions"] = render_to_string(
                                "website/small_file_download.html",
                                {
                                    "pk": ex_dumps.get(path, {}).get("pk", None),
                                    "exists": os.path.exists(down_path),
                                    "index": item_index,
                                    "plugin": plugin.name,
                                    "misp_configured": misp_configured,
                                },
                            )

                        except IndexError as err:
                            print("*" * 100)
                            print(err, glob_path)
                            print("*" * 100)
                            item["sha256"] = ""
                            item["md5"] = ""
                            if plugin.clamav_check:
                                item["clamav"] = ""
                            if plugin.vt_check:
                                item["vt_report"] = ""
                            if plugin.regipy_check:
                                item["regipy_report"] = ""
                            item["actions"] = ""

                # TIMELINER PAINT ROW BY TYPE
                if plugin.name == "timeliner.timeliner":
                    columns = [x for x in item.keys() if x.find("Date") != -1]
                    other_columns = [x for x in item.keys() if x.find("Date") == -1]

                    parsed = False
                    for column in columns:
                        if item[column]:
                            parsed = True
                            row = {
                                "__children": [],
                                "Date": item[column],
                                "Type": column,
                                "row_color": COLOR_TIMELINER[column],
                            }
                            for oc in other_columns:
                                row[oc] = item[oc]

                    if not parsed:
                        row = {
                            "__children": [],
                            "Date": None,
                            "Type": None,
                            "row_color": None,
                        }
                        for oc in other_columns:
                            row[oc] = item[oc]
                    item = row

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
    raise Http404("404")


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
                raise Http404("404")
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
                "plugin": res.plugin.name,
                "disabled": res.plugin.disabled,
                "index": res.dump.index,
                "result": res.get_result_display(),
                "description": res.description,
                "color": COLOR_TEMPLATE.format(colors[res.dump.index]),
            }
            for res in results
        ]

        # If table we will generate data dynamically
        if plugin.name not in ["windows.pstree.PsTree", "linux.pstree.PsTree"]:
            columns = []
            for res in results:
                if res.result == 2:
                    try:
                        index = f"{res.dump.index}_{res.plugin.name.lower()}"
                        mappings = es_client.indices.get_mapping(index=index)
                        columns = [
                            x
                            for x in mappings[index]["mappings"]["properties"]
                            if x not in SYSTEM_COLUMNS
                        ]
                        if res.plugin.vt_check:
                            columns += ["vt_report"]
                        if res.plugin.regipy_check:
                            columns += ["regipy_report"]
                        if res.plugin.clamav_check:
                            columns += ["clamav"]
                        if res.plugin.local_dump:
                            columns += ["sha256", "md5"]
                        columns += ["color", "actions"]
                    except elasticsearch.NotFoundError:
                        continue
                elif res.result != 5:
                    if not columns:
                        columns = ["Loading"]
            return render(
                request,
                "website/partial_analysis.html",
                {"note": note, "columns": columns},
            )

        # SEARCH FOR ITEMS AND KEEP INDEX
        indexes_list = [
            f"{res.dump.index}_{res.plugin.name.lower()}"
            for res in results
            if res.result == 2
        ]

        data = []
        if indexes_list:
            s = Search(using=es_client, index=indexes_list).extra(
                size=settings.MAX_ELASTIC_WINDOWS_SIZE
            )
            result = s.execute()
            # ANNOTATE RESULTS WITH INDEX NAME
            info = [(hit.to_dict(), hit.meta.index.split("_")[0]) for hit in result]

            for item, item_index in info:
                if item_index != ".kibana":
                    item.update({"color": COLOR_TEMPLATE.format(colors[item_index])})
                    data.append(item)

        def change_keys(obj):
            if isinstance(obj, dict):
                new = {}
                for k, v in obj.items():
                    if k == "__children" and v != []:
                        new["children"] = change_keys(v)
                    elif k == "PID":
                        new["text"] = v
                    elif not v:
                        new.setdefault("data", {})[k] = "-"
                    else:
                        new.setdefault("data", {})[k] = v

            elif isinstance(obj, list):
                new = []
                for v in obj:
                    new.append(change_keys(v))
            else:
                return obj
            return new

        new_data = [change_keys(item) for item in data]
        if new_data:
            columns = [{"header": "PID", "value": "text", "width": 100}] + [
                {"header": x, "value": x, "width": 100}
                for x in new_data[0].get("data", {}).keys()
            ]
        else:
            columns = None

        context = {
            "data": json.dumps(new_data),
            "columns": json.dumps(columns),
            "note": note,
            "empty": not bool(new_data),
        }
        return render(request, "website/partial_pstree.html", context)

    raise Http404("404")


@login_required
def download_ext(request, pk):
    """Download selected Extracted Dump"""
    ext = get_object_or_404(ExtractedDump, pk=pk)
    if os.path.exists(ext.path):
        with open(ext.path, "rb") as fh:
            response = HttpResponse(
                fh.read(), content_type="application/force-download"
            )
            response[
                "Content-Disposition"
            ] = f"inline; filename={os.path.basename(ext.path)}"

            return response
    return None


##############################
# SPECIAL VIEWER
##############################
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
        raise Http404("404") from e

    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        raise Http404("404")

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
        raise Http404("404")

    findstr = request.GET.get("findstr", None)
    try:
        last = int(request.GET.get("last", None)) + 1
    except ValueError as e:
        raise Http404("404") from e

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
                            "<span class='singlechar'>.</span>"
                            if int(f"{x:02x}", 16) <= 32
                            or 127 <= int(f"{x:02x}", 16) <= 160
                            or int(f"{x:02x}", 16) == 173
                            else f"<span class='singlechar'>{chr(x)}</span>"
                            for x in line
                        ]
                    ),
                )
            )

        return values, map_file.size() / 16


@login_required
def json_view(request, pk):
    """Render json for hive dump"""
    ed = get_object_or_404(ExtractedDump, pk=pk)
    if ed.result.dump not in get_objects_for_user(request.user, "website.can_see"):
        raise Http404("404")

    values = json.dumps(ed.reg_array.get("values", None)) if ed.reg_array else None
    context = {"data": values}

    return render(request, "website/json_view.html", context)


@login_required
def diff_view(request, index_a, index_b, plugin):
    """Compare json views"""
    get_object_or_404(Dump, index=index_a)
    get_object_or_404(Dump, index=index_b)
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

    context = {"info_a": info_a, "info_b": info_b}

    return render(request, "website/diff_view.html", context)


##############################
# RESTART
##############################
def restart(request):
    """Restart plugin on index"""
    if request.META.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest":
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
                    result.result = 0
                Result.objects.bulk_update(results, ["result"])
                transaction.on_commit(
                    lambda: index_f_and_f(
                        dump.pk, request.user.pk, password=None, restart=plugins_id
                    )
                )
        return JsonResponse({"ok": True}, safe=False)
    raise Http404("404")


##############################
# EXPORT
##############################
@login_required
def export(request):
    """Export extracteddump to misp"""
    if request.method == "POST":
        extracted_dump = get_object_or_404(
            ExtractedDump, pk=request.POST.get("selected_exdump")
        )
        misp_info = get_object_or_404(Service, name=2)

        # CREATE GENERIC EVENT
        misp = PyMISP(misp_info.url, misp_info.key, False, proxies=misp_info.proxy)
        event = MISPEvent()
        event.info = f"From orochi: {extracted_dump.result.plugin.name}@{extracted_dump.result.dump.name}"

        # CREATE FILE OBJ
        file_obj = FileObject(extracted_dump.path)
        event.add_object(file_obj)

        # ADD CLAMAV SIGNATURE
        if extracted_dump.clamav:
            clamav_obj = MISPObject("av-signature")
            clamav_obj.add_attribute("signature", value=extracted_dump.clamav)
            clamav_obj.add_attribute("software", value="clamav")
            file_obj.add_reference(clamav_obj.uuid, "attributed-to")
            event.add_object(clamav_obj)

        # ADD VT SIGNATURE
        if extracted_dump.vt_report:
            vt_obj = MISPObject("virustotal-report")
            vt_obj.add_attribute(
                "last-submission", value=extracted_dump.vt_report.get("scan_date", "")
            )
            vt_obj.add_attribute(
                "detection-ratio",
                value=f'{extracted_dump.vt_report.get("positives", 0)}/{extracted_dump.vt_report.get("total", 0)}',
            )

            vt_obj.add_attribute(
                "permalink", value=extracted_dump.vt_report.get("permalink", "")
            )
            file_obj.add_reference(vt_obj.uuid, "attributed-to")
            event.add_object(vt_obj)

        misp.add_event(event)
        return JsonResponse({"success": True})

    extracted_dump = get_object_or_404(
        ExtractedDump, path=urllib.parse.unquote(request.GET.get("path"))
    )
    form = MispExportForm(
        instance=extracted_dump,
        initial={
            "selected_exdump": extracted_dump.pk,
            "selected_index_name": extracted_dump.result.dump.name,
            "selected_plugin_name": extracted_dump.result.plugin.name,
        },
    )
    context = {"form": form}
    data = {
        "html_form": render_to_string(
            "website/partial_export.html", context, request=request
        )
    }

    return JsonResponse(data)


##############################
# BOOKMARKS
##############################
@login_required
def add_bookmark(request):
    """Add bookmark in user settings"""
    data = {}

    if request.method == "POST":
        updated_request = {
            "name": request.POST.get("name"),
            "query": request.POST.get("query"),
            "star": request.POST.get("star"),
            "icon": request.POST.get("icon"),
        }

        id_indexes = request.POST.get("selected_indexes")
        indexes = []
        for id_index in id_indexes.split(","):
            index = get_object_or_404(Dump, index=id_index)
            indexes.append(index)

        id_plugin = request.POST.get("selected_plugin")
        plugin = get_object_or_404(Plugin, name=id_plugin)

        form = BookmarkForm(data=updated_request)
        if form.is_valid():
            bookmark = form.save(commit=False)
            bookmark.user = request.user
            bookmark.plugin = plugin
            bookmark.save()
            for index in indexes:
                bookmark.indexes.add(index)
            data["form_is_valid"] = True
        else:
            data["form_is_valid"] = False
    else:
        form = BookmarkForm()

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_bookmark_create.html",
        context,
        request=request,
    )
    return JsonResponse(data)


@login_required
def edit_bookmark(request):
    """Edit bookmark information"""
    data = {}
    bookmark = None

    if request.method == "POST":
        bookmark = get_object_or_404(
            Bookmark, name=request.POST.get("selected_bookmark"), user=request.user
        )
    elif request.method == "GET":
        bookmark = get_object_or_404(
            Bookmark, pk=request.GET.get("pk"), user=request.user
        )

    if request.method == "POST":
        form = EditBookmarkForm(
            data=request.POST,
            instance=bookmark,
        )
        if form.is_valid():
            bookmark = form.save()
            data["form_is_valid"] = True
            data["data"] = {
                "name": bookmark.name,
                "icon": bookmark.icon,
                "query": bookmark.query,
            }
        else:
            data["form_is_valid"] = False
    else:
        form = EditBookmarkForm(
            instance=bookmark,
            initial={"selected_bookmark": bookmark.name},
        )

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_bookmark_edit.html",
        context,
        request=request,
    )
    return JsonResponse(data)


@login_required
def delete_bookmark(request):
    """Delete bookmark in user settings"""
    if request.method == "POST":
        bookmark = request.POST.get("bookmark")
        up = get_object_or_404(Bookmark, pk=bookmark, user=request.user)
        up.delete()
        return JsonResponse({"ok": True})
    raise Http404("404")


@login_required
def star_bookmark(request):
    """Star/unstar bookmark in user settings"""
    if request.method == "POST":
        bookmark = request.POST.get("bookmark")
        enable = request.POST.get("enable")
        up = get_object_or_404(Bookmark, pk=bookmark, user=request.user)
        up.star = enable == "true"
        up.save()
        return JsonResponse({"ok": True})
    raise Http404("404")


@login_required
def bookmarks(request, indexes, plugin, query=None):
    """Open index but from a stored configuration of indexes and plugin"""
    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .values_list(
            "index",
            "name",
            "color",
            "operating_system",
            "author",
            "missing_symbols",
            "md5",
            "sha256",
            "size",
            "upload",
        )
        .order_by("-created_at"),
        "selected_indexes": indexes,
        "selected_plugin": plugin,
        "selected_query": query,
    }
    return TemplateResponse(request, "website/index.html", context)


##############################
# DUMP
##############################
@login_required
def index(request):
    """List of available indexes"""
    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .values_list(
            "index",
            "name",
            "color",
            "operating_system",
            "author",
            "missing_symbols",
            "md5",
            "sha256",
            "size",
            "upload",
        )
        .order_by("-created_at"),
        "selected_indexes": [],
        "selected_plugin": None,
        "selected_query": None,
    }
    return TemplateResponse(request, "website/index.html", context)


@login_required
def edit(request):
    """Edit index information"""
    data = {}
    dump = None

    if request.method == "POST":
        dump = get_object_or_404(Dump, index=request.POST.get("index"))
    elif request.method == "GET":
        dump = get_object_or_404(Dump, index=request.GET.get("index"))

    if dump not in get_objects_for_user(request.user, "website.can_see"):
        raise Http404("404")

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
                    .values_list(
                        "index",
                        "name",
                        "color",
                        "operating_system",
                        "author",
                        "missing_symbols",
                        "md5",
                        "sha256",
                        "size",
                        "upload",
                    )
                    .order_by("-created_at")
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
        "website/partial_edit.html",
        context,
        request=request,
    )
    return JsonResponse(data)


def index_f_and_f(dump_pk, user_pk, password=None, restart=None):
    """Run all plugin for a new index on dask"""
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    fire_and_forget(
        dask_client.submit(unzip_then_run, dump_pk, user_pk, password, restart)
    )


@login_required
def create(request):
    """Manage new index creation"""
    data = {}

    if request.method == "POST":
        form = DumpForm(data=request.POST)
        if form.is_valid():
            with transaction.atomic():
                upload = form.cleaned_data["upload"]
                dump = form.save(commit=False)
                dump.author = request.user
                dump.upload = upload
                dump.index = str(uuid.uuid1())
                dump.save()
                form.delete_temporary_files()
                os.mkdir(f"{settings.MEDIA_ROOT}/{dump.index}")
                data["form_is_valid"] = True

                # for each plugin enabled and for that os I create a result
                # if the user selected that for automation, run it immediately on dask
                Result.objects.bulk_create(
                    [
                        Result(
                            plugin=up.plugin, dump=dump, result=0 if up.automatic else 5
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
                    )
                )

            # Return the new list of available indexes
            data["form_is_valid"] = True
            data["dumps"] = render_to_string(
                "website/partial_indices.html",
                {
                    "dumps": get_objects_for_user(request.user, "website.can_see")
                    .values_list(
                        "index",
                        "name",
                        "color",
                        "operating_system",
                        "author",
                        "missing_symbols",
                        "md5",
                        "sha256",
                        "size",
                        "upload",
                    )
                    .order_by("-created_at")
                },
                request=request,
            )
        else:
            data["form_is_valid"] = False
    else:
        form = DumpForm()

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_create.html",
        context,
        request=request,
    )
    return JsonResponse(data)


@login_required
def delete(request):
    """Delete an index"""
    if request.META.get("HTTP_X_REQUESTED_WITH") == "XMLHttpRequest":
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        index = request.GET.get("index")
        dump = Dump.objects.get(index=index)
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            Http404("404")
        dump.delete()
        es_client.indices.delete(index=f"{index}*", ignore=[400, 404])
        shutil.rmtree(f"{settings.MEDIA_ROOT}/{dump.index}")
        return JsonResponse({"ok": True}, safe=False)
    raise Http404("404")


##############################
# SYMBOLS
##############################
@login_required
def symbols(request):
    """Return suggested banner and a button to download item"""
    data = {}
    if request.method == "POST":
        dump = get_object_or_404(Dump, index=request.POST.get("index"))
        form = SymbolForm(
            instance=dump,
            data=request.POST,
        )
        if form.is_valid():
            method = int(request.POST.get("method"))

            # USER SELECTED A LIST OF PATH TO DOWNLOAD
            if method == 0:
                d = Downloader(
                    url_list=form.data["path"].split(","),
                    operating_system=dump.operating_system,
                )
                d.download_list()

            # USER UPLOADED LINUX PACKAGES
            elif method == 1:
                d = Downloader(
                    file_list=[
                        (package.file.path, package.name)
                        for package in form.cleaned_data["packages"]
                    ],
                    operating_system=dump.operating_system,
                )
                d.process_list()

            # USER UPLOADED ALREADY VALID SYMBOLS
            elif method == 2:
                symbol = form.cleaned_data["symbol"]
                shutil.move(
                    symbol.file.path,
                    f'{settings.VOLATILITY_SYMBOL_PATH}/{form.cleaned_data["operating_system"].lower()}/added_{symbol.name}',
                )

            else:
                raise Http404

            form.delete_temporary_files()

            if check_runnable(dump.pk, dump.operating_system, dump.banner):
                dump.missing_symbols = False
                dump.save()

            data["form_is_valid"] = True
            data["dumps"] = render_to_string(
                "website/partial_indices.html",
                {
                    "dumps": get_objects_for_user(request.user, "website.can_see")
                    .values_list(
                        "index",
                        "name",
                        "color",
                        "operating_system",
                        "author",
                        "missing_symbols",
                        "md5",
                        "sha256",
                        "size",
                        "upload",
                    )
                    .order_by("-created_at")
                },
                request=request,
            )
        else:
            data["form_is_valid"] = False
    else:
        dump = get_object_or_404(Dump, index=request.GET.get("index"))
        form = SymbolForm(instance=dump, initial={"path": dump.suggested_symbols_path})

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_symbols.html",
        context,
        request=request,
    )
    return JsonResponse(data)


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
# RULES
##############################
@login_required
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


@login_required
def delete_rules(request):
    """Delete selected rules if yours"""
    rules_id = request.GET.getlist("rules[]")
    rules = CustomRule.objects.filter(pk__in=rules_id, user=request.user)
    for rule in rules:
        os.remove(rule.path)
    rules.delete()
    return JsonResponse({"ok": True})


@login_required
def publish_rules(request):
    """Publish/Unpublish selected rules if your"""
    rules_id = request.GET.getlist("rules[]")
    action = request.GET.get("action")
    rules = CustomRule.objects.filter(pk__in=rules_id, user=request.user)
    for rule in rules:
        rule.public = action == "Publish"
        rule.save()
    return JsonResponse({"ok": True})


@login_required
def make_rule_default(request):
    """Makes selected rule as default for user"""
    rule_id = request.GET.get("rule")

    old_default = CustomRule.objects.filter(user=request.user, default=True)
    if old_default.count() == 1:
        old = old_default.first()
        old.default = False
        old.save()

    rule = CustomRule.objects.get(pk=rule_id)
    if rule.user == request.user:
        rule.default = True
        rule.save()
    else:
        # Make a copy
        user_path = f"{settings.LOCAL_YARA_PATH}/{request.user.username}-Ruleset"
        os.makedirs(user_path, exist_ok=True)
        new_path = f"{user_path}/{rule.name}"
        filename, extension = os.path.splitext(new_path)
        counter = 1
        while os.path.exists(new_path):
            new_path = f"{filename}{counter}{extension}"
            counter += 1

        shutil.copy(rule.path, new_path)
        CustomRule.objects.create(
            user=request.user, name=rule.name, path=new_path, default=True
        )
    return JsonResponse({"ok": True})


@login_required
def download_rule(request, pk):
    """Download selected Rule"""
    rule = CustomRule.objects.filter(pk=pk).filter(
        Q(user=request.user) | Q(public=True)
    )
    if rule.count() == 1:
        rule = rule.first()
    else:
        raise Http404

    if os.path.exists(rule.path):
        with open(rule.path, "rb") as fh:
            response = HttpResponse(
                fh.read(), content_type="application/force-download"
            )
            response[
                "Content-Disposition"
            ] = f"inline; filename={os.path.basename(rule.path)}"

            return response
    return None
