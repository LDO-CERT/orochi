import json
import mmap
import os
import re
from pathlib import Path

from dask.distributed import Client, fire_and_forget
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.db.models import F, Q
from django.http import Http404, JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user, get_perms
from pymisp import MISPEvent, MISPObject, PyMISP
from pymisp.tools import FileObject

from orochi.utils.timeliner import clean_bodywork
from orochi.utils.volatility_dask_elk import get_parameters, unzip_then_run
from orochi.website.defaults import (
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
    Dump,
    Plugin,
    Result,
    Service,
    UserPlugin,
    Value,
)

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
@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET"])
def parameters(request):
    """Get parameters from volatility api, returns form"""
    data = {
        "html_form": render_to_string(
            "website/partial_params.html",
            {
                "form": ParametersForm(
                    dynamic_fields=get_parameters(request.GET.get("selected_plugin"))
                ),
                "plugin_name": request.GET.get("selected_plugin"),
                "pks": ",".join(request.GET.getlist("selected_indexes[]")),
            },
            request=request,
        ),
    }
    return JsonResponse(data)


##############################
# RESULTS
##############################
@login_required
def generate(request):
    """Sliced data request for analysis ajax datatables request"""
    if request.META.get("HTTP_X_REQUESTED_WITH") != "XMLHttpRequest":
        return JsonResponse({"status_code": 405, "error": "Method Not Allowed"})

    # obtain list of columns
    ui_columns = request.GET.getlist("columns[]")

    # sorting
    sort_column = request.GET.get("order[0][column]") or 0
    sort_column = int(sort_column)
    sort_order = request.GET.get("order[0][dir]") or "asc"

    # manage filters on single columns
    filters = request.GET.getlist("filters[]")
    dict_filters = {}
    if filters:
        for filter in filters:
            name, value = filter.split("___")
            dict_filters[name] = value

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
    for dump in dumps:
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return JsonResponse({"status_code": 403, "error": "Unauthorized"})

    # GET ALL RESULTS
    res = (
        Value.objects.select_related("result__plugin", "result__dump")
        .filter(result__plugin__name=plugin, result__dump__index__in=indexes)
        .filter(result__result=RESULT_STATUS_SUCCESS)
        .annotate(
            orochi_plugin=F("result__plugin__name"),
            orochi_index=F("result__dump__index"),
            orochi_name=F("result__dump__name"),
            orochi_os=F("result__dump__operating_system"),
            orochi_color=F("result__dump__color"),
            orochi_createdAt=F("result__updated_at"),
        )
        .values(
            "orochi_plugin",
            "orochi_index",
            "orochi_name",
            "orochi_os",
            "orochi_color",
            "orochi_createdAt",
            "value",
        )
    )

    total = res.count()

    # first filtering main search
    if search:
        res = res.filter(
            Q(value__icontains=search)
            | Q(orochi_plugin__icontains=search)
            | Q(orochi_name__icontains=search)
            | Q(orochi_os__icontains=search)
            | Q(orochi_createdAt__icontains=search)
        )

    # second filtering on each column (dump/plugin)
    if filters:
        for k, v in dict_filters.items():
            if k.startswith("orochi_"):
                res = res.filter(**{f"{k}__icontains": v})

    try:
        _ = Service.objects.get(name=SERVICE_MISP)
        misp_configured = True
    except Service.DoesNotExist:
        misp_configured = False

    data = []

    # EXPLODE RES
    for item in res:
        tmp = {k: item[k] for k in item.keys() - {"value"}}
        tmp["orochi_color"] = COLOR_TEMPLATE.format(tmp["orochi_color"])

        # third filtering on each column (volatility result)
        filtered = False
        for k, v in item["value"].items():
            if k_filter := dict_filters.get(k):
                if v and v.find(k_filter) != -1:
                    tmp[k] = v
                else:
                    filtered = True
            else:
                tmp[k] = v

        if filtered:
            continue

        if item["value"].get("down_path"):
            tmp["actions"] = render_to_string(
                "website/file_download.html",
                {
                    "down_path": item["value"]["down_path"],
                    "misp_configured": misp_configured,
                    "regipy": Path(
                        f"{item['value']['down_path']}.regipy.json"
                    ).exists(),
                    "vt": (
                        # if empty read is false
                        open(f"{item['value']['down_path']}.vt.json").read()
                        if Path(f"{item['value']['down_path']}.vt.json").exists()
                        else None
                    ),
                },
            )

        list_row = []
        for column in ui_columns:
            if column in tmp:
                list_row.append(tmp[column])
            else:
                list_row.append("-")

        data.append(list_row)

    filtered = len(data)

    data = sorted(data, key=lambda d: d[sort_column], reverse=sort_order == "asc")

    data = data[start : start + length]

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
                    value_columns = (
                        Value.objects.filter(result=res).values("value").first()
                    ) or {}
                    # GET COLUMNS FROM ELASTIC
                    columns = (
                        [
                            "orochi_color",
                            "orochi_name",
                            "orochi_plugin",
                            "orochi_os",
                            "orochi_createdAt",
                        ]
                        + [
                            x
                            for x in value_columns.get("value", {}).keys()
                            if x not in SYSTEM_COLUMNS
                        ]
                        + ["actions"]
                    )
                elif res.result != RESULT_STATUS_DISABLED and columns == []:
                    columns = ["Disabled"]

            maxmind = (
                os.path.exists("/maxmind/GeoLite2-ASN.mmdb")
                or os.path.exists("/maxmind/GeoLite2-City.mmdb")
                or os.path.exists("/maxmind/GeoLite2-Country.mmdb")
            )

            bodyfile = None
            bodyfile_chart = None
            if plugin.name == "timeliner.Timeliner":
                bodyfile_path = (
                    Path(res.dump.upload.path).parent
                    / "timeliner.Timeliner/volatility.body"
                )
                if bodyfile_path.exists():
                    bodyfile = bodyfile_path
                    bodyfile_chart = clean_bodywork(bodyfile_path)

            return render(
                request,
                "website/partial_analysis.html",
                {
                    "note": note,
                    "columns": columns,
                    "plugin": plugin.name,
                    "maxmind": maxmind,
                    "bodyfile": bodyfile,
                    "bodyfile_chart": bodyfile_chart,
                },
            )

        columns = None
        # SEARCH FOR ITEMS AND KEEP INDEX
        for res in results:
            if res.result != RESULT_STATUS_SUCCESS:
                continue

            if value_columns := (
                Value.objects.filter(result=res).values("value").first()
            ):
                columns = (
                    [PLUGIN_WITH_CHILDREN[plugin.name.lower()]]
                    + [
                        x
                        for x in value_columns["value"].keys()
                        if x
                        not in SYSTEM_COLUMNS
                        + [PLUGIN_WITH_CHILDREN[plugin.name.lower()], "__children"]
                    ]
                    + ["orochi_name", "orochi_color"]
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
    # GET DATA
    plugin = request.GET.get("plugin")
    indexes = request.GET.getlist("indexes[]")

    # GET PLUGIN INFO
    plugin = get_object_or_404(Plugin, name=plugin)
    title = PLUGIN_WITH_CHILDREN[plugin.name.lower()]

    # GET DICT OF COLOR AND CHECK PERMISSIONS
    dumps = Dump.objects.filter(index__in=indexes)
    for dump in dumps:
        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return JsonResponse({"status_code": 403, "error": "Unauthorized"})

    # GET ALL RESULTS
    res = (
        Value.objects.select_related("result__plugin", "result__dump")
        .filter(result__plugin__name=plugin, result__dump__index__in=indexes)
        .filter(result__result=RESULT_STATUS_SUCCESS)
        .annotate(
            orochi_plugin=F("result__plugin__name"),
            orochi_name=F("result__dump__name"),
            orochi_os=F("result__dump__operating_system"),
            orochi_color=F("result__dump__color"),
            orochi_createdAt=F("result__updated_at"),
        )
        .values(
            "orochi_plugin",
            "orochi_name",
            "orochi_os",
            "orochi_color",
            "orochi_createdAt",
            "value",
        )
    )
    data = []
    for item in res:
        tmp = {k: item[k] for k in item.keys() - {"value"}}
        for k, v in item["value"].items():
            tmp[k] = v
        tmp = change_keys(tmp, title)
        tmp["orochi_color"] = tmp["orochi_color"]
        data.append(tmp)
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

    search_a = (
        Value.objects.select_related("result__plugin", "result__dump")
        .filter(result__plugin__name=plugin, result__dump=dump1)
        .filter(result__result=RESULT_STATUS_SUCCESS)
        .annotate(
            orochi_plugin=F("result__plugin__name"),
            orochi_name=F("result__dump__name"),
            orochi_os=F("result__dump__operating_system"),
            orochi_color=F("result__dump__color"),
            orochi_createdAt=F("result__updated_at"),
        )
        .values(
            "orochi_plugin",
            "orochi_name",
            "orochi_os",
            "orochi_color",
            "orochi_createdAt",
            "value",
        )
    )
    info_a = []
    for item in search_a:
        tmp = {k: item[k] for k in item.keys() - {"value"}}
        for k, v in item["value"].items():
            tmp[k] = v
        info_a.append(tmp)

    search_b = (
        Value.objects.select_related("result__plugin", "result__dump")
        .filter(result__plugin__name=plugin, result__dump=dump2)
        .filter(result__result=RESULT_STATUS_SUCCESS)
        .annotate(
            orochi_plugin=F("result__plugin__name"),
            orochi_name=F("result__dump__name"),
            orochi_os=F("result__dump__operating_system"),
            orochi_color=F("result__dump__color"),
            orochi_createdAt=F("result__updated_at"),
        )
        .values(
            "orochi_plugin",
            "orochi_name",
            "orochi_os",
            "orochi_color",
            "orochi_createdAt",
            "value",
        )
    )
    info_b = []
    for item in search_b:
        tmp = {k: item[k] for k in item.keys() - {"value"}}
        for k, v in item["value"].items():
            tmp[k] = v
        info_b.append(tmp)
    return render(
        request,
        "website/diff_view.html",
        {
            "info_a": json.dumps(info_a, cls=DjangoJSONEncoder),
            "info_b": json.dumps(info_b, cls=DjangoJSONEncoder),
        },
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

    if s := []:  # TODO
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
        "main_page": True,
        "selected_indexes": indexes,
        "selected_plugin": plugin,
        "selected_query": query,
        "readonly": is_not_readonly(request.user),
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
        "main_page": True,
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
    dump = get_object_or_404(Dump, index=request.GET.get("index"))

    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return JsonResponse({"status_code": 403, "error": "Unauthorized"})

    data = {
        "html_form": render_to_string(
            "website/partial_index_edit.html",
            {
                "form": EditDumpForm(
                    instance=dump,
                    initial={
                        "authorized_users": [
                            user.pk
                            for user in get_user_model().objects.all()
                            if "can_see" in get_perms(user, dump)
                            and user != request.user
                        ]
                    },
                    user=request.user,
                ),
                "index": dump.index,
            },
            request=request,
        )
    }
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
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_index_create.html",
                {"form": DumpForm(current_user=request.user), "errors": None},
                request=request,
            )
        }
    )


##############################
# SYMBOLS
##############################
@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET"])
def banner_symbols(request):
    """Return suggested banner and a button to download item"""
    dump = get_object_or_404(Dump, index=request.GET.get("index"))
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_symbols_banner.html",
                {
                    "form": SymbolBannerForm(
                        instance=dump, initial={"path": dump.suggested_symbols_path}
                    )
                },
                request=request,
            )
        }
    )


@login_required
@user_passes_test(is_not_readonly)
def list_symbols(request):
    """Return list of symbols"""
    return render(request, "website/list_symbols.html")


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET"])
def upload_symbols(request):
    """Upload symbols"""
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_symbols_upload.html",
                {"form": SymbolUploadForm()},
                request=request,
            )
        }
    )


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET"])
def download_isf(request):
    """Download all symbols from provided isf server path"""
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_isf_download.html",
                {"form": SymbolISFForm()},
                request=request,
            )
        }
    )


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET"])
def upload_packages(request):
    """Generate symbols from uploaded file"""
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_packages_upload.html",
                {"form": SymbolPackageForm()},
                request=request,
            )
        }
    )
