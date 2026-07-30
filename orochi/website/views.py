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
from django.db.utils import IntegrityError
from django.http import Http404, JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user, get_perms
from pymisp import MISPEvent, MISPObject, PyMISP
from pymisp.tools import FileObject

from orochi.utils.timeliner import clean_bodywork
from orochi.utils.volatility_dask_elk import get_parameters, manage_upload
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
    CaseForm,
    DumpForm,
    EditBookmarkForm,
    EditDumpForm,
    EvidenceForm,
    FindingForm,
    FolderForm,
    ParametersForm,
    SymbolBannerForm,
    SymbolISFForm,
    SymbolPackageForm,
    SymbolUploadForm,
)
from orochi.website.models import (
    Bookmark,
    Case,
    Dump,
    Evidence,
    Finding,
    Plugin,
    ReportTemplate,
    Result,
    Service,
    UserPlugin,
    Value,
)

COLOR_TEMPLATE = """<div class="w-4 h-4 rounded shadow-inner ring-1 ring-black/10 dark:ring-white/10 shrink-0 mr-2" style="background-color: {};"></div>"""

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
    "has_auto",
    "host__name",
]


##############################
# NGIN AUTH CHECK
##############################
def auth_check(request):
    """
    A view for Nginx's auth_request.

    The @login_required decorator handles everything. If the user is authenticated,
    Django will execute this view and return a 200 OK. If they are not,
    the decorator will redirect to the login page, which for an auth_request
    results in a non-200 status that Nginx can interpret as "unauthorized".
    """
    if request.user.is_authenticated:
        return HttpResponse(status=200)
    else:
        return HttpResponse(status=401)


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
    context = {
        "form": ParametersForm(
            dynamic_fields=get_parameters(request.GET.get("selected_plugin"))
        ),
        "plugin_name": request.GET.get("selected_plugin"),
        "pks": ",".join(request.GET.getlist("selected_indexes[]")),
    }

    if getattr(request, "htmx", False):
        return render(request, "website/partial_params.html", context)

    data = {
        "html_form": render_to_string(
            "website/partial_params.html",
            context,
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
                if v and k_filter in str(v):
                    tmp[k] = v
                else:
                    filtered = True
            else:
                tmp[k] = v

        if filtered:
            continue

        import base64

        encoded_row = base64.b64encode(
            json.dumps(item["value"]).encode("utf-8")
        ).decode("utf-8")
        tmp["actions"] = render_to_string(
            "website/row_actions.html",
            {
                "down_path": item["value"].get("down_path"),
                "misp_configured": misp_configured,
                "regipy": (
                    Path(f"{item['value'].get('down_path', '')}.regipy.json").exists()
                    if item["value"].get("down_path")
                    else False
                ),
                "vt": (
                    Path(f"{item['value'].get('down_path', '')}.vt.json").read_text()
                    if item["value"].get("down_path")
                    and Path(f"{item['value'].get('down_path', '')}.vt.json").exists()
                    else None
                ),
                "dump": tmp.get("orochi_index"),
                "plugin": tmp.get("orochi_plugin"),
                "result_row": encoded_row,
                "extracted_file": item["value"].get("down_path"),
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
        if plugin.name.lower() not in PLUGIN_WITH_CHILDREN:
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
        with open(path, "r") as f:
            data = json.loads(f.read())
        return render(
            request,
            "website/partial_json.html",
            {"data": data, "title": "VirusTotal Report"},
        )
    return render(
        request,
        "website/partial_json.html",
        {"error": "VT report not found", "title": "VirusTotal Report"},
    )


@login_required
def hex_view(request, index):
    """Render hex view for dump"""
    dump = get_object_or_404(Dump, index=index)
    return TemplateResponse(
        request, "website/hex_view.html", {"index": index, "name": dump.name}
    )


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
    return TemplateResponse(request, "website/json_view.html", context)


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
    if (
        not getattr(request, "htmx", False)
        and request.META.get("HTTP_X_REQUESTED_WITH") != "XMLHttpRequest"
    ):
        return JsonResponse({"status_code": 405, "error": "Method Not Allowed"})

    index = request.GET.get("index") or request.POST.get("index")
    dump = get_object_or_404(Dump, index=index)

    plugins = UserPlugin.objects.filter(
        plugin__operating_system__in=[
            dump.operating_system,
            "Other",
        ],
        user=request.user,
        plugin__disabled=False,
        automatic=True,
    ).select_related("plugin")

    if request.method == "GET":
        context = {
            "plugins": plugins,
            "index": index,
            "dump": dump,
        }
        return render(request, "website/partial_restart_auto.html", context)

    if request.method == "POST":
        restart_failed = request.POST.get("restart_failed") == "on"
        with transaction.atomic():
            plugins_id = []
            if plugins.count() > 0:
                plugins_id.extend([plugin.plugin.id for plugin in plugins])

            if restart_failed:
                failed_results = Result.objects.filter(
                    dump=dump, result=5
                )  # 5 = RESULT_STATUS_ERROR
                plugins_id.extend(failed_results.values_list("plugin_id", flat=True))

            if plugins_id := list(set(plugins_id)):
                results = Result.objects.filter(plugin__pk__in=plugins_id, dump=dump)
                for result in results:
                    result.result = 2  # 2 = RESULT_STATUS_RUNNING
                Result.objects.bulk_update(results, ["result"])
                transaction.on_commit(
                    lambda: index_f_and_f(
                        dump.pk, request.user.pk, password=None, restart=plugins_id
                    )
                )
        if getattr(request, "htmx", False):
            # Close the modal and show success toast
            return HttpResponse(
                "",
                headers={
                    "HX-Trigger": '{"showMessage": {"title": "Restart successful!", "content": "Plugin has been restarted", "type": "success"}, "closeModal": true}'
                },
            )
    return JsonResponse({"ok": True}, safe=False)


##############################
# EXPORT
##############################
@login_required
@require_http_methods(["GET"])
def export(request):
    """Export extracted dump to misp"""
    try:
        filepath = request.GET.get("path")
        _, _, index, plugin, _ = filepath.split("/")
        misp_info = get_object_or_404(Service, name=SERVICE_MISP)
        dump = get_object_or_404(Dump, index=index)
        _ = get_object_or_404(Plugin, name=plugin)

        # CREATE GENERIC EVENT
        misp = PyMISP(misp_info.url, misp_info.key, False, proxies=misp_info.proxy)
        event = MISPEvent()
        event.info = f"From orochi: {plugin}@{dump.name}"

        # CREATE FILE OBJ
        file_obj = FileObject(filepath)
        event.add_object(file_obj)

        if s := Value.objects.get(
            result__plugin__name=plugin, result__dump=dump, value__down_path=filepath
        ):
            s = s.value

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
                    vt_obj.add_attribute(
                        "last-submission", value=vt.get("scan_date", "")
                    )
                    vt_obj.add_attribute(
                        "detection-ratio",
                        value=f"{vt.get('positives', 0)}/{vt.get('total', 0)}",
                    )
                    vt_obj.add_attribute("permalink", value=vt.get("permalink", ""))
                    file_obj.add_reference(vt_obj.uuid, "attributed-to")
                    event.add_object(vt_obj)

        misp.add_event(event)
        return JsonResponse({"success": True, "message": "MISP export successful"})
    except Exception as e:
        return JsonResponse({"detail": f"{e}"}, status=404, safe=False)


##############################
# BOOKMARKS
##############################
@login_required
@require_http_methods(["GET", "POST"])
def add_bookmark(request):
    """Add bookmark in user settings"""
    if request.method == "POST":
        form = BookmarkForm(request.POST)
        if form.is_valid():
            try:
                indexes = []
                ok_indexes = list(
                    get_objects_for_user(request.user, "website.can_see").values_list(
                        "index", flat=True
                    )
                )
                selected = form.cleaned_data.get("selected_indexes", "")
                for index_id in selected.split(","):
                    index_id = str(index_id).strip()
                    if not index_id:
                        continue
                    if index_id not in ok_indexes:
                        continue
                    index = get_object_or_404(Dump, index=index_id)
                    indexes.append(index)

                if indexes:
                    plugin = get_object_or_404(
                        Plugin, name=form.cleaned_data.get("selected_plugin")
                    )
                    bookmark = form.save(commit=False)
                    bookmark.user = request.user
                    bookmark.plugin = plugin
                    bookmark.save()
                    for index in indexes:
                        bookmark.indexes.add(index)
                    return HttpResponse(
                        "",
                        headers={
                            "HX-Trigger": '{"showMessage": {"title": "Bookmark saved!", "content": "Bookmark has been created", "type": "success"}, "closeModal": true}'
                        },
                    )
                else:
                    form.add_error(None, "No valid indexes selected")
            except IntegrityError:
                form.add_error("name", "Bookmark already exists")
        return render(request, "website/partial_bookmark_create.html", {"form": form})

    if getattr(request, "htmx", False):
        initial = request.GET.dict()
        if "selected_indexes" in initial:
            try:
                import json

                indexes = json.loads(initial["selected_indexes"])
                if isinstance(indexes, list):
                    initial["selected_indexes"] = ",".join(indexes)
            except Exception:
                pass
        return render(
            request,
            "website/partial_bookmark_create.html",
            {"form": BookmarkForm(initial=initial)},
        )

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
    from django.db.models import Exists, OuterRef

    has_auto_plugins = UserPlugin.objects.filter(
        plugin__operating_system__in=[OuterRef("operating_system"), "Other"],
        user=request.user,
        plugin__disabled=False,
        automatic=True,
    )

    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .annotate(has_auto=Exists(has_auto_plugins))
        .values_list(*INDEX_VALUES_LIST)
        .order_by("folder__name", "name"),
        "main_page": True,
        "selected_indexes": indexes,
        "selected_plugin": plugin,
        "selected_query": query,
        "cases": Case.objects.filter(user=request.user).prefetch_related("evidences"),
        "readonly": is_not_readonly(request.user),
    }
    return TemplateResponse(request, "website/index.html", context)


##############################
# FOLDER
##############################
@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET", "POST"])
def folder_create(request):
    if request.method != "POST":
        return (
            render(request, "website/partial_folder.html", {"form": FolderForm()})
            if getattr(request, "htmx", False)
            else JsonResponse(
                {
                    "html_form": render_to_string(
                        "website/partial_folder.html",
                        {"form": FolderForm()},
                        request=request,
                    )
                }
            )
        )
    form = FolderForm(request.POST)
    if form.is_valid():
        try:
            folder = form.save(commit=False)
            folder.user = request.user
            folder.save()
            return HttpResponse(
                "",
                headers={
                    "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Folder has been created", "type": "success"}, "closeModal": true}'
                },
            )
        except IntegrityError:
            form.add_error("name", "Folder already exists")
    return render(request, "website/partial_folder.html", {"form": form})


##############################
# CASES / EVIDENCE
##############################
@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET", "POST"])
def case_create(request):
    if request.method != "POST":
        return (
            render(
                request,
                "website/partial_case.html",
                {
                    "form": CaseForm(request.user),
                    "url": reverse("website:case_create"),
                },
            )
            if getattr(request, "htmx", False)
            else JsonResponse(
                {
                    "html_form": render_to_string(
                        "website/partial_case.html",
                        {
                            "form": CaseForm(request.user),
                            "url": reverse("website:case_create"),
                        },
                        request=request,
                    )
                }
            )
        )
    form = CaseForm(request.user, request.POST)
    if form.is_valid():
        try:
            case = form.save(commit=False)
            case.user = request.user
            case.save()
            return HttpResponse(
                "",
                headers={
                    "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been created", "type": "success"}, "closeModal": true, "refreshCases": true}'
                },
            )
        except IntegrityError:
            form.add_error("name", "Case already exists")
    return render(request, "website/partial_case.html", {"form": form})


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET", "POST"])
def case_edit(request):
    case = get_object_or_404(Case, pk=request.GET.get("pk"), user=request.user)
    if request.method == "POST":
        form = CaseForm(request.user, request.POST, instance=case)
        if form.is_valid():
            try:
                form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been updated", "type": "success"}, "closeModal": true, "refreshCases": true}'
                    },
                )
            except IntegrityError:
                form.add_error("name", "Case already exists")
        return render(request, "website/partial_case.html", {"form": form})

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_case.html",
            {
                "form": CaseForm(request.user, instance=case),
                "url": reverse("website:case_edit") + f"?pk={case.pk}",
            },
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_case.html",
                {
                    "form": CaseForm(request.user, instance=case),
                    "url": reverse("website:case_edit") + f"?pk={case.pk}",
                },
                request=request,
            )
        }
    )


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["POST"])
def case_delete(request, pk):
    case = get_object_or_404(Case, pk=pk, user=request.user)
    case.delete()
    return HttpResponse(
        '<div class="flex items-center justify-center h-full p-10"><p class="text-zinc-500 text-lg">Case deleted.</p></div>',
        headers={
            "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been deleted", "type": "success"}, "refreshCases": true}'
        },
    )


@login_required
def case_detail(request, pk):
    case = get_object_or_404(Case, pk=pk, user=request.user)
    related_dumps = (
        Dump.objects.filter(folder=case.folder) if case.folder else Dump.objects.none()
    )
    templates = ReportTemplate.objects.all()
    context = {
        "case": case,
        "evidences": case.evidences.all(),
        "findings": case.findings.all(),
        "timeline_events": case.timeline_events.all(),
        "related_dumps": related_dumps,
        "report_templates": templates,
    }

    if getattr(request, "htmx", False) and request.headers.get("HX-Target") != "body":
        return TemplateResponse(request, "website/partial_case_detail.html", context)

    from django.db.models import Exists, OuterRef

    has_auto_plugins = UserPlugin.objects.filter(
        user=request.user,
        automatic=True,
        plugin__operating_system__in=[OuterRef("operating_system"), "Other"],
        plugin__disabled=False,
    )
    context |= {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .annotate(has_auto=Exists(has_auto_plugins))
        .values_list(*INDEX_VALUES_LIST)
        .order_by("folder__name", "name"),
        "main_page": True,
        "selected_indexes": [],
        "selected_plugin": None,
        "selected_query": None,
        "cases": Case.objects.filter(user=request.user).prefetch_related("evidences"),
        "readonly": is_not_readonly(request.user),
    }
    return TemplateResponse(request, "website/index.html", context)


@login_required
@user_passes_test(is_not_readonly)
def case_export(request, pk):
    import io
    import json
    import tarfile
    from pathlib import Path

    from django.core.serializers.json import DjangoJSONEncoder
    from django.http import FileResponse

    case = get_object_or_404(Case, pk=pk)

    # Collect all data
    data = {
        "case": {
            "name": case.name,
            "description": case.description,
            "status": case.status,
            "created_at": case.created_at,
        },
        "evidences": list(
            case.evidences.values(
                "name", "description", "created_at", "plugin", "result_row"
            )
        ),
        "findings": list(
            case.findings.values(
                "severity", "tags", "note", "mitre_attack_technique", "created_at"
            )
        ),
        "timeline": list(
            case.timeline_events.values("timestamp", "event_type", "description")
        ),
    }

    json_data = json.dumps(data, cls=DjangoJSONEncoder, indent=4)

    # Create tar.gz in memory
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        # Add json data
        json_file = io.BytesIO(json_data.encode("utf-8"))
        info = tarfile.TarInfo(name=f"case_{case.pk}_export.json")
        info.size = len(json_file.getvalue())
        tar.addfile(tarinfo=info, fileobj=json_file)

        # We could also append actual downloaded files if they exist in evidence
        for ev in case.evidences.all():
            if (
                ev.result_row
                and isinstance(ev.result_row, dict)
                and "down_path" in ev.result_row
            ):
                down_path = ev.result_row["down_path"]
                if down_path and Path(down_path).exists():
                    tar.add(down_path, arcname=f"files/{Path(down_path).name}")

    tar_stream.seek(0)
    return FileResponse(
        tar_stream, as_attachment=True, filename=f"case_{case.pk}_bundle.tar.gz"
    )


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["POST"])
def case_report(request, pk):
    import requests
    from django.http import HttpResponse
    from django.template import engines

    from orochi.website.defaults import SERVICE_OLLAMA

    case = get_object_or_404(Case, pk=pk, user=request.user)
    template_id = request.POST.get("template_id")
    use_ai = request.POST.get("use_ai") == "true"

    report_template = get_object_or_404(ReportTemplate, pk=template_id)

    context = {
        "case": case,
        "evidences": case.evidences.all(),
        "findings": case.findings.all(),
        "timeline_events": case.timeline_events.all(),
        "ai_summary": None,
    }

    if use_ai:
        ollama_service = Service.objects.filter(name=SERVICE_OLLAMA).first()
        if ollama_service and ollama_service.url:
            findings_text = "\n".join(
                [
                    f"- [{f.severity}] {f.mitre_attack_technique or 'No Technique'}: {f.note}"
                    for f in case.findings.all()
                ]
            )
            prompt = f"Write a professional executive summary for a digital forensics case named '{case.name}'. Findings:\n{findings_text}\nProvide a concise analysis in markdown format."

            model_name = (
                ollama_service.key or "llama3"
            )  # Use key for model name if provided

            try:
                response = requests.post(
                    f"{ollama_service.url}/api/generate",
                    json={"model": model_name, "prompt": prompt, "stream": False},
                    timeout=60,
                )
                if response.status_code == 200:
                    context["ai_summary"] = response.json().get("response", "")
                else:
                    context["ai_summary"] = f"Error from Ollama: {response.text}"
            except Exception as e:
                context["ai_summary"] = f"Error connecting to Ollama: {str(e)}"

    try:
        with report_template.template.open("r") as f:
            template_content = f.read()
            if isinstance(template_content, bytes):
                template_content = template_content.decode("utf-8")

        django_engine = engines["django"]
        template = django_engine.from_string(template_content)
        rendered_html = template.render(context, request)

        return HttpResponse(rendered_html)
    except Exception as e:
        return HttpResponse(f"Error rendering template: {str(e)}", status=500)


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET", "POST"])
def evidence_create(request):
    if request.method == "POST":
        form = EvidenceForm(request.user, request.POST)
        if form.is_valid():
            try:
                _ = form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Evidence has been created", "type": "success"}, "closeModal": true, "refreshCases": true}'
                    },
                )
            except IntegrityError:
                form.add_error("name", "Evidence already exists")
        return render(request, "website/partial_evidence.html", {"form": form})

    initial = {}
    if request.GET.get("dump"):
        initial["dump"] = request.GET.get("dump")
    if request.GET.get("plugin"):
        initial["plugin"] = request.GET.get("plugin")
    if request.GET.get("result_row"):
        import base64

        try:
            initial["result_row"] = base64.b64decode(
                request.GET.get("result_row")
            ).decode("utf-8")
        except Exception:
            initial["result_row"] = request.GET.get("result_row")
    if request.GET.get("extracted_file"):
        initial["extracted_file"] = request.GET.get("extracted_file")
    if request.GET.get("case"):
        initial["case"] = request.GET.get("case")

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_evidence.html",
            {"form": EvidenceForm(request.user, initial=initial)},
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_evidence.html",
                {"form": EvidenceForm(request.user, initial=initial)},
                request=request,
            )
        }
    )


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET", "POST"])
def finding_create(request, evidence_pk):
    evidence = get_object_or_404(Evidence, pk=evidence_pk)

    if request.method == "POST":
        form = FindingForm(request.POST)
        if form.is_valid():
            try:
                _ = form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Finding has been created", "type": "success"}, "closeModal": true, "refreshCaseDetail": true}'
                    },
                )
            except IntegrityError:
                form.add_error("note", "Error creating finding")
        return render(
            request,
            "website/partial_finding.html",
            {"form": form, "evidence": evidence},
        )

    initial = {
        "evidence": evidence.pk,
        "case": evidence.case.pk,
    }

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_finding.html",
            {
                "form": FindingForm(initial=initial),
                "evidence": evidence,
                "url": reverse("website:finding_create", args=[evidence.pk]),
            },
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_finding.html",
                {
                    "form": FindingForm(initial=initial),
                    "evidence": evidence,
                    "url": reverse("website:finding_create", args=[evidence.pk]),
                },
                request=request,
            )
        }
    )


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET", "POST"])
def finding_edit(request, pk):
    finding = get_object_or_404(Finding, pk=pk)

    case = finding.case
    if case.user != request.user and request.user not in case.collaborators.all():
        raise Http404("Not authorized")

    if request.method == "POST":
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            try:
                form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Finding has been updated", "type": "success"}, "closeModal": true, "refreshCaseDetail": true}'
                    },
                )
            except IntegrityError:
                form.add_error("note", "Error updating finding")
        return render(
            request,
            "website/partial_finding.html",
            {
                "form": form,
                "evidence": finding.evidence,
                "url": reverse("website:finding_edit", args=[finding.pk]),
            },
        )

    form = FindingForm(instance=finding)

    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_finding.html",
            {
                "form": form,
                "evidence": finding.evidence,
                "url": reverse("website:finding_edit", args=[finding.pk]),
            },
        )

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_finding.html",
                {
                    "form": form,
                    "evidence": finding.evidence,
                    "url": reverse("website:finding_edit", args=[finding.pk]),
                },
                request=request,
            )
        }
    )


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["POST"])
def finding_delete(request, pk):
    finding = get_object_or_404(Finding, pk=pk)

    case = finding.case
    if case.user != request.user and request.user not in case.collaborators.all():
        raise Http404("Not authorized")

    finding.delete()
    return HttpResponse(
        "",
        headers={
            "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Finding has been deleted", "type": "success"}, "refreshCaseDetail": true}'
        },
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
def indices(request):
    """List of available indexes for sidebar refresh"""
    from django.db.models import Exists, OuterRef

    has_auto_plugins = UserPlugin.objects.filter(
        user=request.user,
        automatic=True,
        plugin__operating_system__in=[OuterRef("operating_system"), "Other"],
        plugin__disabled=False,
    )

    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .annotate(has_auto=Exists(has_auto_plugins))
        .values_list(*INDEX_VALUES_LIST)
        .order_by("folder__name", "name"),
        "cases": Case.objects.filter(user=request.user).prefetch_related("evidences"),
        "readonly": is_not_readonly(request.user),
    }
    return TemplateResponse(request, "website/partial_indices.html", context)


@login_required
def index(request):
    """List of available indexes"""
    from django.db.models import Exists, OuterRef

    has_auto_plugins = UserPlugin.objects.filter(
        user=request.user,
        automatic=True,
        plugin__operating_system__in=[OuterRef("operating_system"), "Other"],
        plugin__disabled=False,
    )

    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .annotate(has_auto=Exists(has_auto_plugins))
        .values_list(*INDEX_VALUES_LIST)
        .order_by("folder__name", "name"),
        "main_page": True,
        "selected_indexes": [],
        "selected_plugin": None,
        "selected_query": None,
        "cases": Case.objects.filter(user=request.user).prefetch_related("evidences"),
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

    context = {
        "form": EditDumpForm(
            instance=dump,
            initial={
                "authorized_users": [
                    user.pk
                    for user in get_user_model().objects.all()
                    if "can_see" in get_perms(user, dump) and user != request.user
                ]
            },
            user=request.user,
        ),
        "index": dump.index,
    }

    if getattr(request, "htmx", False):
        return render(request, "website/partial_index_edit.html", context)

    data = {
        "html_form": render_to_string(
            "website/partial_index_edit.html",
            context,
            request=request,
        )
    }
    return JsonResponse(data)


def index_f_and_f(dump_pk, user_pk, password=None, restart=None, move=True):
    """Run all plugin for a new index on dask"""
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    fire_and_forget(
        dask_client.submit(manage_upload, dump_pk, user_pk, password, restart, move)
    )


@login_required
@user_passes_test(is_not_readonly)
@never_cache
def create(request):
    """Manage new index creation"""
    if getattr(request, "htmx", False):
        return render(
            request,
            "website/partial_index_create.html",
            {"form": DumpForm(current_user=request.user), "errors": None},
        )
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
    context = {
        "form": SymbolBannerForm(
            instance=dump, initial={"path": dump.suggested_symbols_path}
        )
    }
    if getattr(request, "htmx", False):
        return render(request, "website/partial_symbols_banner.html", context)

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_symbols_banner.html",
                context,
                request=request,
            )
        }
    )


@login_required
@user_passes_test(is_not_readonly)
def list_symbols(request):
    """Return list of symbols"""
    return TemplateResponse(request, "website/list_symbols.html")


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
