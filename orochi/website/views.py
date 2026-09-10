import base64
import contextlib
import json
import mmap
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

from dask.distributed import Client, fire_and_forget
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.db.models import F, Q
from django.db.utils import IntegrityError
from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.text import slugify
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user, get_perms
from pymisp import MISPEvent, MISPObject, PyMISP
from pymisp.tools import FileObject

from orochi.utils.timeliner import (
    build_timeline_feed,
    clean_bodywork,
    extract_timeline_entries,
)
from orochi.utils.volatility_dask_elk import get_parameters, manage_upload
from orochi.website.ai_narrative import generate_dump_narrative, get_local_ollama_config
from orochi.website.attack import (
    generate_navigator_layer,
    get_all_technique_choices,
    get_case_attack_coverage,
)
from orochi.website.defaults import (
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_EMPTY,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
    SERVICE_MISP,
)
from orochi.website.detection.engine import evaluate_dump_triage
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
    DumpNarrative,
    DumpSecret,
    Evidence,
    Finding,
    Folder,
    Plugin,
    ReportTemplate,
    Result,
    Service,
    TriageFinding,
    UserPlugin,
    Value,
    ValueAnnotation,
)
from orochi.website.roles import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_READONLY,
    can_execute_plugin,
    get_user_role,
    has_role,
)
from orochi.website.search import execute_vector_search
from orochi.website.secrets_scanner import scan_dump_for_secrets
from orochi.website.temporal import compute_temporal_diff

COLOR_TEMPLATE = """<div class="w-3.5 h-3.5 rounded shadow-xs ring-1 ring-black/10 dark:ring-white/10 shrink-0" style="background-color: {};"></div>"""

SYSTEM_COLUMNS = [
    "orochi_createdAt",
    "orochi_os",
    "orochi_plugin",
    "down_path",
]

PLUGIN_WITH_CHILDREN = {
    "frameworkinfo.frameworkinfo": "Data",
    "linux.iomem.iomem": "Name",
    "linux.mountinfo.mountinfo": "MOUNT_POINT",
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

DUMP_ORDER_BY = (
    "folder__name",
    F("host__name").asc(nulls_last=True),
    "created_at",
    "name",
)


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
# ROLES & READONLY CHECK
##############################
def is_not_readonly(user):
    """Check if user is not readonly"""
    return get_user_role(user) != ROLE_READONLY


def is_analyst_or_admin(user):
    """Check if user is Analyst or Admin"""
    return has_role(user, ROLE_ANALYST)


def is_admin(user):
    """Check if user is Admin"""
    return has_role(user, ROLE_ADMIN)


##############################
# PLUGIN
##############################
@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["GET"])
def parameters(request):
    """Get parameters from volatility api, returns form"""
    plugin_name = request.GET.get("selected_plugin")
    plugin = Plugin.objects.filter(name=plugin_name).first()
    if plugin:
        if not can_execute_plugin(request.user, plugin):
            return HttpResponseForbidden(f"Permission Denied: Execution restricted for plugin '{plugin.name}'.")
    elif not has_role(request.user, ROLE_ANALYST):
        return HttpResponseForbidden(f"Permission Denied: Execution restricted for plugin '{plugin_name}'.")

    context = {
        "form": ParametersForm(dynamic_fields=get_parameters(plugin_name)),
        "plugin_name": plugin_name,
        "plugin_obj": plugin,
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
            "id",
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

    raw_data = []

    has_actions = "actions" in ui_columns
    actions_idx = ui_columns.index("actions") if has_actions else -1

    # EXPLODE RES
    for item in res:
        val = item["value"]
        color = item["orochi_color"]

        # third filtering on each column (volatility result)
        if dict_filters:
            filtered = False
            for k, k_filter in dict_filters.items():
                if not k.startswith("orochi_"):
                    v = val.get(k)
                    if not (v and k_filter in str(v)):
                        filtered = True
                        break
            if filtered:
                continue

        list_row = []
        for column in ui_columns:
            if column == "actions":
                list_row.append(None)
            elif column == "orochi_color":
                list_row.append(COLOR_TEMPLATE.format(color) if color else "-")
            elif column in val:
                list_row.append(val[column])
            elif column in item:
                list_row.append(item[column])
            else:
                list_row.append("-")

        raw_data.append((list_row, item))

    filtered = len(raw_data)

    if sort_column < len(ui_columns):
        raw_data.sort(
            key=lambda d: (
                d[0][sort_column] is None,
                str(d[0][sort_column]) if d[0][sort_column] is not None else "",
            ),
            reverse=sort_order == "asc",
        )

    paged_data = raw_data[start : start + length]

    annotations_by_val = defaultdict(list)
    if has_actions and paged_data:
        if paged_val_ids := [item.get("id") for _, item in paged_data if item.get("id")]:
            for anno in ValueAnnotation.objects.filter(value_id__in=paged_val_ids).select_related("user"):
                annotations_by_val[anno.value_id].append(anno)

    data = []
    for list_row, item in paged_data:
        if has_actions:
            item_val = item["value"]
            down_path = item_val.get("down_path")
            regipy_exists = False
            vt_content = None
            if down_path:
                regipy_path = Path(f"{down_path}.regipy.json")
                if regipy_path.exists():
                    regipy_exists = True
                vt_path = Path(f"{down_path}.vt.json")
                if vt_path.exists():
                    try:
                        vt_content = vt_path.read_text()
                    except Exception:
                        vt_content = None

            encoded_row = base64.b64encode(json.dumps(item_val).encode("utf-8")).decode("utf-8")
            val_id = item.get("id")
            val_annos = annotations_by_val.get(val_id, [])
            latest_anno = val_annos[0] if val_annos else None

            actions_html = render_to_string(
                "website/row_actions.html",
                {
                    "down_path": down_path,
                    "misp_configured": misp_configured,
                    "regipy": regipy_exists,
                    "vt": vt_content,
                    "dump": item.get("orochi_index"),
                    "plugin": item.get("orochi_plugin"),
                    "result_row": encoded_row,
                    "extracted_file": down_path,
                    "value_id": val_id,
                    "annotation_count": len(val_annos),
                    "latest_annotation": latest_anno,
                },
            )
            list_row[actions_idx] = actions_html

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
            if k not in SYSTEM_COLUMNS and k == "__children" and v != []:
                new["children"] = change_keys(v, title)
            elif k not in SYSTEM_COLUMNS and k == "__children" or k in SYSTEM_COLUMNS:
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
            Result.objects.select_related("dump__host", "plugin")
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
                "host_id": res.dump.host_id,
                "host_name": res.dump.host.name if res.dump.host else "",
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
                    value_columns = (Value.objects.filter(result=res).values("value").first()) or {}
                    # GET COLUMNS FROM ELASTIC
                    columns = (
                        [
                            "orochi_color",
                            "orochi_name",
                            "orochi_plugin",
                            "orochi_os",
                            "orochi_createdAt",
                        ]
                        + [x for x in value_columns.get("value", {}).keys() if x not in SYSTEM_COLUMNS]
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
            bodyfile_charts = []
            timeliner_summary = None
            timeline_feed = None
            if plugin.name == "timeliner.Timeliner":
                timeline_entries = []
                for r in results.filter(result=RESULT_STATUS_SUCCESS):
                    dump_bodyfile_path = Path(r.dump.upload.path).parent / "timeliner.Timeliner/volatility.body"
                    chart_html = None
                    dump_color = colors.get(r.dump.index, "#3b82f6")
                    if dump_bodyfile_path.exists():
                        bodyfile = dump_bodyfile_path
                        extracted = extract_timeline_entries(
                            file_path=dump_bodyfile_path,
                            dump_name=r.dump.name,
                            dump_index=r.dump.index,
                            dump_color=dump_color,
                        )
                        timeline_entries.extend(extracted)
                        chart_html = clean_bodywork(
                            values=extracted,
                            title=f"Interactive Event Timeline - {r.dump.name}",
                        )
                    else:
                        db_vals = list(Value.objects.filter(result=r).values("id", "value"))
                        if db_vals:
                            chart_html = clean_bodywork(
                                values=db_vals,
                                title=f"Interactive Event Timeline - {r.dump.name}",
                            )
                            timeline_entries.extend(
                                extract_timeline_entries(
                                    values=db_vals,
                                    dump_name=r.dump.name,
                                    dump_index=r.dump.index,
                                    dump_color=dump_color,
                                )
                            )

                    if chart_html:
                        bodyfile_charts.append(
                            {
                                "dump_name": r.dump.name,
                                "dump_index": r.dump.index,
                                "color": dump_color,
                                "chart": chart_html,
                            }
                        )

                if bodyfile_charts:
                    bodyfile_chart = bodyfile_charts[0]["chart"]

                if timeline_entries:
                    summary_counts = Counter(e.get("Plugin", "Unknown") for e in timeline_entries)
                    timeliner_summary = {
                        "total": len(timeline_entries),
                        "categories": sorted(summary_counts.items(), key=lambda x: x[1], reverse=True),
                    }

                if timeline_entries:
                    active_dumps = list({r.dump for r in results.filter(result=RESULT_STATUS_SUCCESS)})
                    triage_findings = list(TriageFinding.objects.filter(dump__in=active_dumps))
                    dump_secrets = list(DumpSecret.objects.filter(dump__in=active_dumps))
                    timeline_feed = build_timeline_feed(
                        timeline_entries,
                        limit=100,
                        threat_findings=triage_findings,
                        secrets=dump_secrets,
                    )

            terminal_data = None
            if plugin.name in [
                "linux.bash.Bash",
                "mac.bash.Bash",
                "windows.consoles.Consoles",
                "windows.cmdline.CmdLine",
            ]:
                terminal_data = []
                for r in results.filter(result=RESULT_STATUS_SUCCESS):
                    for val in Value.objects.filter(result=r):
                        v = val.value
                        cmd = v.get("Command") or v.get("Args") or v.get("CommandHistory") or v.get("ScreenBuffer")
                        if cmd:
                            terminal_data.append(
                                {
                                    "pid": v.get("PID"),
                                    "process": v.get("Process"),
                                    "command": cmd,
                                    "time": v.get("CommandTime"),
                                    "dump": r.dump.name,
                                    "color": colors.get(r.dump.index),
                                }
                            )

            integrity_summary = None
            if plugin.name in [
                "linux.check_syscall.Check_syscall",
                "windows.ssdt.SSDT",
                "windows.callbacks.Callbacks",
                "windows.driverirp.DriverIrp",
                "mac.check_syscall.Check_syscall",
            ]:
                total = 0
                hooked = []
                for r in results.filter(result=RESULT_STATUS_SUCCESS):
                    for val in Value.objects.filter(result=r):
                        v = val.value
                        total += 1
                        symbol = str(v.get("Handler Symbol") or v.get("Symbol") or "").upper()
                        module = str(v.get("Module") or "").upper()
                        if not symbol or "UNKNOWN" in symbol or "HOOK" in symbol or "UNKNOWN" in module:
                            hooked.append(v)
                integrity_summary = {
                    "total": total,
                    "hooked_count": len(hooked),
                    "clean": len(hooked) == 0,
                    "hooked": hooked[:10],
                }

            network_summary = None
            if plugin.name in [
                "linux.sockstat.Sockstat",
                "windows.netscan.NetScan",
                "windows.netstat.NetStat",
                "mac.netstat.Netstat",
            ]:
                total = 0
                listening = 0
                established = 0
                external_ips = set()
                for r in results.filter(result=RESULT_STATUS_SUCCESS):
                    for val in Value.objects.filter(result=r):
                        v = val.value
                        total += 1
                        state = str(v.get("State") or "").upper()
                        if state == "LISTEN":
                            listening += 1
                        elif state in {"ESTABLISHED", "CONNECTED"}:
                            established += 1
                        remote = v.get("ForeignAddr") or v.get("Destination Addr")
                        if (
                            remote
                            and str(remote)
                            not in [
                                "0.0.0.0",
                                "127.0.0.1",
                                "::",
                                "::1",
                                "-",
                                "None",
                            ]
                            and (not str(remote).startswith("127.") and not str(remote).startswith("groups:"))
                        ):
                            external_ips.add(str(remote).split(":")[0])
                network_summary = {
                    "total": total,
                    "listening": listening,
                    "established": established,
                    "external_ips_count": len(external_ips),
                }

            privilege_summary = None
            if plugin.name in [
                "linux.capabilities.Capabilities",
                "windows.privileges.Privs",
            ]:
                high_risk_count = 0
                total_procs = 0
                for r in results.filter(result=RESULT_STATUS_SUCCESS):
                    for val in Value.objects.filter(result=r):
                        v = val.value
                        total_procs += 1
                        eff = str(v.get("cap_effective") or v.get("Privilege") or "").lower()
                        if eff == "all" or any(
                            k in eff
                            for k in [
                                "sys_admin",
                                "net_admin",
                                "sys_ptrace",
                                "sys_module",
                                "sedebugprivilege",
                                "seimpersonateprivilege",
                                "setcbprivilege",
                            ]
                        ):
                            high_risk_count += 1
                privilege_summary = {
                    "total": total_procs,
                    "high_risk": high_risk_count,
                }

            malfind_data = None
            if plugin.name in [
                "windows.malware.malfind.Malfind",
                "linux.malware.malfind.Malfind",
                "mac.malfind.Malfind",
            ]:
                malfind_data = []
                for r in results.filter(result=RESULT_STATUS_SUCCESS):
                    for val in Value.objects.filter(result=r):
                        v = val.value
                        hexdump = v.get("HexDump") or v.get("HexBytes") or ""
                        has_pe = "4d 5a" in str(hexdump).lower() or "MZ" in str(hexdump)
                        has_elf = "7f 45 4c 46" in str(hexdump).lower() or ".ELF" in str(hexdump)
                        malfind_data.append(
                            {
                                "pid": v.get("PID"),
                                "process": v.get("Process"),
                                "start": v.get("Start") or v.get("Start VPN"),
                                "end": v.get("End") or v.get("End VPN"),
                                "protection": v.get("Protection") or v.get("Flags"),
                                "hexdump": hexdump,
                                "disassembly": v.get("Disasm") or v.get("Disassembly"),
                                "has_pe": has_pe,
                                "has_elf": has_elf,
                                "dump": r.dump.name,
                                "color": colors.get(r.dump.index),
                            }
                        )

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
                    "bodyfile_charts": bodyfile_charts,
                    "timeliner_summary": timeliner_summary,
                    "timeline_feed": timeline_feed,
                    "terminal_data": terminal_data,
                    "integrity_summary": integrity_summary,
                    "network_summary": network_summary,
                    "privilege_summary": privilege_summary,
                    "malfind_data": malfind_data,
                },
            )

        columns = None
        # SEARCH FOR ITEMS AND KEEP INDEX
        for res in results:
            if res.result != RESULT_STATUS_SUCCESS:
                continue

            if value_columns := (Value.objects.filter(result=res).values("value").first()):
                columns = (
                    [PLUGIN_WITH_CHILDREN[plugin.name.lower()]]
                    + [
                        x
                        for x in value_columns["value"].keys()
                        if x not in SYSTEM_COLUMNS + [PLUGIN_WITH_CHILDREN[plugin.name.lower()], "__children"]
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

    if plugin.name.lower() == "linux.mountinfo.mountinfo":
        items = []
        for item in res:
            tmp = {k: item[k] for k in item.keys() - {"value"}}
            for k, v in item["value"].items():
                tmp[k] = v
            tmp["__children"] = []
            tmp["orochi_color"] = tmp["orochi_color"]
            items.append(tmp)

        nodes_by_id = {(node.get("orochi_name"), node.get("MOUNT ID")): node for node in items}
        roots = []
        for node in items:
            parent_id = node.get("PARENT_ID")
            mount_id = node.get("MOUNT ID")
            parent_key = (node.get("orochi_name"), parent_id)
            if parent_id != mount_id and parent_key in nodes_by_id:
                nodes_by_id[parent_key]["__children"].append(node)
            else:
                roots.append(node)

        data = [change_keys(r, title) for r in roots]
        return JsonResponse(data, safe=False)

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
        with open(path) as f:
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
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        raise Http404("404")

    initial_offset = (request.GET.get("offset") or request.GET.get("goto") or "").strip()
    initial_search = (request.GET.get("search") or request.GET.get("findstr") or "").strip()
    back_to = request.GET.get("back", "").strip()

    context = {
        "index": index,
        "name": dump.name,
        "initial_offset": initial_offset,
        "initial_search": initial_search,
        "back_to": back_to,
    }
    return TemplateResponse(request, "website/hex_view.html", context)


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
    if not findstr:
        return JsonResponse({"found": -1, "pos": 0}, status=200)

    try:
        last_param = request.GET.get("last", "0")
        last = int(last_param) + 1 if last_param is not None and str(last_param).isdigit() else 0
    except (ValueError, TypeError) as e:
        return JsonResponse({"status_code": 404, "error": str(e)})

    pattern = re.compile(re.escape(findstr.encode("utf-8")), re.IGNORECASE)

    with open(dump.upload.path, "r+b") as f:
        map_file = mmap.mmap(f.fileno(), length=0, prot=mmap.PROT_READ)
        if m := pattern.search(map_file[last:]):
            new_offset, _ = m.span()
            return JsonResponse({"found": 1, "pos": new_offset + last}, status=200)
        if m := pattern.search(map_file[:]):
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
    if not Path(filepath).exists() and dump not in get_objects_for_user(request.user, "website.can_see"):
        raise Http404("404")
    with open(filepath) as f:
        values = json.load(f)
        context = {"data": json.dumps(values)}
    return TemplateResponse(request, "website/json_view.html", context)


@login_required
def diff_view(request, index_a, index_b, plugin):
    """Compare json views"""
    dump1 = get_object_or_404(Dump, index=index_a)
    dump2 = get_object_or_404(Dump, index=index_b)
    if dump1 not in get_objects_for_user(request.user, "website.can_see") or dump2 not in get_objects_for_user(
        request.user, "website.can_see"
    ):
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
            "index_a": index_a,
            "index_b": index_b,
            "dump_a": dump1,
            "dump_b": dump2,
            "plugin": plugin,
        },
    )


@login_required
def temporal_diff(request, index_a, index_b):
    """Temporal diff view for comparing two captures (same host T1 vs T2)."""
    dump1 = get_object_or_404(Dump, index=index_a)
    dump2 = get_object_or_404(Dump, index=index_b)
    user_dumps = get_objects_for_user(request.user, "website.can_see")
    if dump1 not in user_dumps or dump2 not in user_dumps:
        raise Http404("404")

    reverse_order = request.GET.get("reverse") in ["1", "true", "True"]
    diff_data = compute_temporal_diff(dump1, dump2, reverse=reverse_order)

    user_cases = Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct()

    return render(
        request,
        "website/temporal_diff.html",
        {
            "diff": diff_data,
            "index_a": index_a,
            "index_b": index_b,
            "reverse_order": reverse_order,
            "cases": user_cases,
        },
    )


##############################
# RESTART
##############################
@login_required
@user_passes_test(is_not_readonly)
def restart(request):
    """Restart plugin on index"""
    if not getattr(request, "htmx", False) and request.META.get("HTTP_X_REQUESTED_WITH") != "XMLHttpRequest":
        return JsonResponse({"status_code": 405, "error": "Method Not Allowed"})

    index = request.GET.get("index") or request.POST.get("index")
    dump = get_object_or_404(Dump, index=index)

    user_plugins_qs = UserPlugin.objects.filter(
        plugin__operating_system__in=[
            dump.operating_system,
            "Other",
        ],
        user=request.user,
        plugin__disabled=False,
        automatic=True,
    ).select_related("plugin")
    plugins = [up for up in user_plugins_qs if can_execute_plugin(request.user, up.plugin)]

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
            if plugins:
                plugins_id.extend([plugin.plugin.id for plugin in plugins])

            if restart_failed:
                failed_results = Result.objects.filter(dump=dump, result=5).select_related(
                    "plugin"
                )  # 5 = RESULT_STATUS_ERROR
                plugins_id.extend(
                    [res.plugin_id for res in failed_results if can_execute_plugin(request.user, res.plugin)]
                )

            if plugins_id := list(set(plugins_id)):
                results = Result.objects.filter(plugin__pk__in=plugins_id, dump=dump)
                for result in results:
                    result.result = 2  # 2 = RESULT_STATUS_RUNNING
                Result.objects.bulk_update(results, ["result"])
                transaction.on_commit(
                    lambda: index_f_and_f(dump.pk, request.user.pk, password=None, restart=plugins_id)
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

        if s := Value.objects.get(result__plugin__name=plugin, result__dump=dump, value__down_path=filepath):
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
                with open(f"{filepath}.vt.json") as f:
                    vt = json.load(f)
                    vt_obj = MISPObject("virustotal-report")
                    vt_obj.add_attribute("last-submission", value=vt.get("scan_date", ""))
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
                ok_indexes = list(get_objects_for_user(request.user, "website.can_see").values_list("index", flat=True))
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
                    plugin = get_object_or_404(Plugin, name=form.cleaned_data.get("selected_plugin"))
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
            with contextlib.suppress(Exception):
                import json

                indexes = json.loads(initial["selected_indexes"])
                if isinstance(indexes, list):
                    initial["selected_indexes"] = ",".join(indexes)
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
    data = {"html_form": render_to_string("website/partial_bookmark_edit.html", context, request=request)}
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
        .order_by(*DUMP_ORDER_BY),
        "main_page": True,
        "selected_indexes": indexes,
        "selected_plugin": plugin,
        "selected_query": query,
        "cases": Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user))
        .prefetch_related("evidences", "collaborators")
        .distinct(),
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
            form.save_m2m()
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
    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        pk=request.GET.get("pk"),
    )
    if request.method == "POST":
        form = CaseForm(request.user, request.POST, instance=case)
        if form.is_valid():
            try:
                form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Case has been updated", "type": "success"}, "closeModal": true, "refreshCaseDetail": true, "refreshCases": true}'
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
@user_passes_test(is_not_readonly)
@require_http_methods(["POST"])
def case_change_status(request, pk):
    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        pk=pk,
    )
    new_status = request.POST.get("status") or request.GET.get("status")
    valid_statuses = [choice[0] for choice in Case.STATUS_CHOICES]
    if new_status in valid_statuses:
        case.status = new_status
        case.save(update_fields=["status"])
        return HttpResponse(
            "",
            headers={
                "HX-Trigger": json.dumps(
                    {
                        "showMessage": {
                            "title": "Operation successful!",
                            "content": f"Case status updated to {new_status}",
                            "type": "success",
                        },
                        "refreshCaseDetail": True,
                        "refreshCases": True,
                    }
                )
            },
        )
    return HttpResponse("Invalid status", status=400)


@login_required
def case_detail(request, pk):
    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        pk=pk,
    )
    related_dumps = Dump.objects.filter(folder=case.folder) if case.folder else Dump.objects.none()
    templates = ReportTemplate.objects.all()
    context = {
        "case": case,
        "evidences": case.evidences.all(),
        "findings": case.findings.all(),
        "timeline_events": case.timeline_events.all(),
        "related_dumps": related_dumps,
        "report_templates": templates,
        "attack_coverage": get_case_attack_coverage(case.findings.all()),
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
        .order_by(*DUMP_ORDER_BY),
        "main_page": True,
        "selected_indexes": [],
        "selected_plugin": None,
        "selected_query": None,
        "cases": Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user))
        .prefetch_related("evidences", "collaborators")
        .distinct(),
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

    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        pk=pk,
    )

    # Collect all data
    data = {
        "case": {
            "name": case.name,
            "description": case.description,
            "status": case.status,
            "created_at": case.created_at,
        },
        "evidences": list(case.evidences.values("name", "description", "created_at", "plugin", "result_row")),
        "findings": list(case.findings.values("severity", "tags", "note", "mitre_attack_technique", "created_at")),
        "timeline": list(case.timeline_events.values("timestamp", "event_type", "description")),
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
            if ev.result_row and isinstance(ev.result_row, dict) and "down_path" in ev.result_row:
                down_path = ev.result_row["down_path"]
                if down_path and Path(down_path).exists():
                    tar.add(down_path, arcname=f"files/{Path(down_path).name}")

    tar_stream.seek(0)
    return FileResponse(tar_stream, as_attachment=True, filename=f"case_{case.pk}_bundle.tar.gz")


@login_required
def case_mitre_export(request, pk):
    case = get_object_or_404(Case, pk=pk)
    if case.user != request.user and request.user not in case.collaborators.all():
        raise Http404("Not authorized")

    layer_data = generate_navigator_layer(case, case.findings.all())
    json_bytes = json.dumps(layer_data, indent=2).encode("utf-8")

    response = HttpResponse(json_bytes, content_type="application/json")
    safe_name = slugify(case.name) or f"case_{case.pk}"
    response["Content-Disposition"] = f'attachment; filename="case_{safe_name}_mitre_layer.json"'
    return response


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["POST"])
def case_report(request, pk):
    import io

    import requests
    from django.http import HttpResponse
    from django.template import engines
    from docxtpl import DocxTemplate

    from orochi.website.defaults import SERVICE_OLLAMA

    case = get_object_or_404(
        Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        pk=pk,
    )
    template_id = request.POST.get("template_id")
    use_ai = request.POST.get("use_ai") == "true"

    report_template = get_object_or_404(ReportTemplate, pk=template_id)

    context = {
        "case": case,
        "evidences": case.evidences.all(),
        "findings": case.findings.all(),
        "timeline_events": case.timeline_events.all(),
        "ai_summary": None,
        "ai_summary_html": None,
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
            prompt = (
                f"Write a professional executive summary for a digital forensics case named '{case.name}'. "
                f"Findings:\n{findings_text}\nProvide a concise analysis in markdown format."
            )

            model_name = ollama_service.key or "llama3"  # Use key for model name if provided

            try:
                proxies = ollama_service.proxy or None
                response = requests.post(
                    f"{ollama_service.url.rstrip('/')}/api/generate",
                    json={"model": model_name, "prompt": prompt, "stream": False},
                    proxies=proxies,
                    timeout=60,
                )
                if response.status_code == 200:
                    context["ai_summary"] = response.json().get("response", "")
                else:
                    context["ai_summary"] = f"Error from Ollama: {response.text}"
            except Exception as e:
                context["ai_summary"] = f"Error connecting to Ollama: {str(e)}"
        else:
            context["ai_summary"] = (
                "Ollama service is not configured in Admin > Services. "
                "Please configure Ollama with URL (e.g. http://ollama:11434) and a downloaded model name (e.g. llama3)."
            )

    if context["ai_summary"]:
        try:
            import marko

            context["ai_summary_html"] = marko.convert(context["ai_summary"])
        except Exception:
            context["ai_summary_html"] = context["ai_summary"]

    try:
        template_name = report_template.template.name.lower()
        if template_name.endswith(".docx"):
            with report_template.template.open("rb") as f:
                doc = DocxTemplate(f)
                doc.render(context)
                bio = io.BytesIO()
                doc.save(bio)
                bio.seek(0)

            safe_name = (
                "".join(c for c in case.name if c.isalnum() or c in (" ", "-", "_")).strip().replace(" ", "_")
                or f"case_{case.pk}"
            )
            response = HttpResponse(
                bio.getvalue(),
                content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
            response["Content-Disposition"] = f'attachment; filename="{safe_name}_report.docx"'
            return response
        else:
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
        data = request.POST.copy()
        dump_val = data.get("dump")
        if dump_val and not str(dump_val).isdigit():
            try:
                d = Dump.objects.get(index=dump_val)
                data["dump"] = str(d.pk)
            except Dump.DoesNotExist:
                pass
        form = EvidenceForm(request.user, data)
        if form.is_valid():
            try:
                _ = form.save()
                return HttpResponse(
                    "",
                    headers={
                        "HX-Trigger": json.dumps(
                            {
                                "showMessage": {
                                    "title": "Operation successful!",
                                    "content": "Evidence has been created",
                                    "type": "success",
                                },
                                "closeModal": True,
                                "refreshCaseDetail": True,
                            }
                        )
                    },
                )
            except IntegrityError:
                form.add_error("name", "Evidence already exists")
        return render(request, "website/partial_evidence.html", {"form": form})

    initial = {}
    if request.GET.get("dump"):
        dump_param = request.GET.get("dump")
        if dump_param and not str(dump_param).isdigit():
            try:
                d = Dump.objects.get(index=dump_param)
                initial["dump"] = d.pk
            except Dump.DoesNotExist:
                initial["dump"] = dump_param
        else:
            initial["dump"] = dump_param
    if request.GET.get("plugin"):
        initial["plugin"] = request.GET.get("plugin")
    if request.GET.get("result_row"):
        import base64

        try:
            raw_decoded = base64.b64decode(request.GET.get("result_row")).decode("utf-8")
            try:
                initial["result_row"] = json.loads(raw_decoded)
            except Exception:
                initial["result_row"] = raw_decoded
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
            {
                "form": form,
                "evidence": evidence,
                "mitre_techniques": get_all_technique_choices(),
            },
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
                "mitre_techniques": get_all_technique_choices(),
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
                    "mitre_techniques": get_all_technique_choices(),
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
                "mitre_techniques": get_all_technique_choices(),
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
                "mitre_techniques": get_all_technique_choices(),
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
                    "mitre_techniques": get_all_technique_choices(),
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


@user_passes_test(is_not_readonly)
@require_http_methods(["POST"])
def evidence_delete(request, pk):
    evidence = get_object_or_404(Evidence, pk=pk)

    case = evidence.case
    if case and case.user != request.user and request.user not in case.collaborators.all():
        raise Http404("Not authorized")

    evidence.delete()
    return HttpResponse(
        "",
        headers={
            "HX-Trigger": '{"showMessage": {"title": "Operation successful!", "content": "Evidence has been deleted", "type": "success"}, "refreshCaseDetail": true}'
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
        .order_by(*DUMP_ORDER_BY),
        "cases": Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user))
        .prefetch_related("evidences", "collaborators")
        .distinct(),
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
        .order_by(*DUMP_ORDER_BY),
        "main_page": True,
        "selected_indexes": [],
        "selected_plugin": None,
        "selected_query": None,
        "cases": Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user))
        .prefetch_related("evidences", "collaborators")
        .distinct(),
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
            response = HttpResponse(fh.read(), content_type="application/force-download")
            response["Content-Disposition"] = f"inline; filename={os.path.basename(filepath)}"
            return response
    return Http404("404")


@login_required
@user_passes_test(is_analyst_or_admin)
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
    fire_and_forget(dask_client.submit(manage_upload, dump_pk, user_pk, password, restart, move))


@login_required
@user_passes_test(is_analyst_or_admin)
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
@user_passes_test(is_admin)
@require_http_methods(["GET"])
def banner_symbols(request):
    """Return suggested banner and a button to download item"""
    dump = get_object_or_404(Dump, index=request.GET.get("index"))
    context = {"form": SymbolBannerForm(instance=dump, initial={"path": dump.suggested_symbols_path})}
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
@user_passes_test(is_admin)
def list_symbols(request):
    """Return list of symbols"""
    return TemplateResponse(request, "website/list_symbols.html")


@login_required
@user_passes_test(is_admin)
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
@user_passes_test(is_admin)
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
@user_passes_test(is_admin)
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


@login_required
def global_search(request):
    """Global vector search across Cases, Dumps, and Plugin Results."""
    q = request.GET.get("q", "").strip()
    scope = request.GET.get("scope", "all")
    if scope not in ("all", "cases", "dumps", "results"):
        scope = "all"
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.GET.get("ajax") == "1"

    limit = 10 if is_ajax else 50
    results = execute_vector_search(request.user, q, scope=scope, limit=limit)

    if is_ajax:
        return JsonResponse(results)

    context = {
        "query": q,
        "scope": scope,
        "results": results,
        "user_cases": Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct(),
        "user_folders": Folder.objects.filter(user=request.user),
    }
    return render(request, "website/global_search.html", context)


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["POST"])
def add_to_case_from_search(request):
    """Add selected search results (Value rows or Dumps) to a new or existing Case as Evidence."""
    case_mode = request.POST.get("case_mode", "existing")
    notes = request.POST.get("notes", "").strip()

    if case_mode == "new":
        case_name = request.POST.get("case_name", "").strip()
        if not case_name:
            return JsonResponse({"error": "Case name is required."}, status=400)

        case_description = request.POST.get("case_description", "").strip()
        folder_name = request.POST.get("folder_name", "").strip()
        is_ctf = request.POST.get("is_ctf") in ("true", "1", "on")

        folder = None
        if folder_name:
            folder, _ = Folder.objects.get_or_create(name=folder_name, user=request.user)

        case, _ = Case.objects.get_or_create(
            name=case_name,
            user=request.user,
            defaults={
                "description": case_description,
                "folder": folder,
                "is_ctf": is_ctf,
            },
        )
    elif case_id := request.POST.get("case_id"):
        case = get_object_or_404(
            Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)),
            pk=case_id,
        )

    else:
        return JsonResponse({"error": "Please select an existing case."}, status=400)
    # Values
    value_ids = request.POST.getlist("selected_values[]") or request.POST.getlist("selected_values")
    if not value_ids and request.POST.get("selected_values_str"):
        value_ids = [v.strip() for v in request.POST.get("selected_values_str").split(",") if v.strip()]

    allowed_dumps = get_objects_for_user(request.user, "website.can_see")
    created_evidences = []

    if value_ids:
        values = Value.objects.filter(
            pk__in=value_ids,
            result__dump__in=allowed_dumps,
        ).select_related("result__dump", "result__plugin")

        for val in values:
            dump = val.result.dump
            plugin_name = val.result.plugin.name
            val_data = val.value or {}

            title_identifier = ""
            for id_key in (
                "ImageFileName",
                "Name",
                "PID",
                "Process",
                "Path",
                "Offset",
            ):
                if id_key in val_data:
                    title_identifier = f" {id_key}:{val_data[id_key]}"
                    break
            evidence_name = f"[{plugin_name}]{title_identifier}"[:250]

            evidence = Evidence.objects.create(
                case=case,
                dump=dump,
                plugin=plugin_name,
                result_row=val_data,
                name=evidence_name,
                description=notes or f"Imported from Vector Global Search for dump '{dump.name}'",
            )
            created_evidences.append(evidence.pk)

    # Dumps
    dump_ids = request.POST.getlist("selected_dumps[]") or request.POST.getlist("selected_dumps")
    if not dump_ids and request.POST.get("selected_dumps_str"):
        dump_ids = [d.strip() for d in request.POST.get("selected_dumps_str").split(",") if d.strip()]

    if dump_ids:
        dumps = allowed_dumps.filter(pk__in=dump_ids)
        for dump in dumps:
            evidence = Evidence.objects.create(
                case=case,
                dump=dump,
                name=f"Dump: {dump.name}"[:250],
                description=notes or f"Imported dump '{dump.name}' from Vector Global Search",
            )
            created_evidences.append(evidence.pk)

    case_url = reverse("website:case_detail", kwargs={"pk": case.pk})

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.POST.get("ajax") == "1"
    if is_ajax:
        return JsonResponse(
            {
                "success": True,
                "case_id": case.pk,
                "case_name": case.name,
                "case_url": case_url,
                "evidences_count": len(created_evidences),
                "message": f"Successfully added {len(created_evidences)} evidence item(s) to case '{case.name}'.",
            }
        )

    messages.success(
        request,
        f"Successfully added {len(created_evidences)} evidence item(s) to case '{case.name}'.",
    )
    return redirect(case_url)


@login_required
@require_http_methods(["GET", "POST"])
def value_annotations(request, value_id):
    """View and add annotations/comments on an individual plugin result row (Value)."""
    val = get_object_or_404(
        Value.objects.select_related("result__dump", "result__plugin"),
        pk=value_id,
    )
    dump = val.result.dump
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot add annotations.")
        status = request.POST.get("status", "comment")
        comment = request.POST.get("comment", "").strip()
        if comment:
            ValueAnnotation.objects.create(
                value=val,
                user=request.user,
                status=status,
                comment=comment,
            )

    annotations = val.annotations.select_related("user").all()
    # Extract human-readable summary from JSON row
    val_json = val.value or {}
    summary_fields = []
    for key in [
        "ImageFileName",
        "Name",
        "Process",
        "COMM",
        "PID",
        "ForeignAddr",
        "Destination Addr",
        "Path",
    ]:
        if key in val_json:
            summary_fields.append(f"{key}: {val_json[key]}")
    row_summary = " | ".join(summary_fields) if summary_fields else f"Offset: {val_json.get('Offset', '-')}"

    return render(
        request,
        "website/partial_value_annotations.html",
        {
            "value": val,
            "dump": dump,
            "plugin": val.result.plugin,
            "row_summary": row_summary,
            "annotations": annotations,
            "status_choices": ValueAnnotation.STATUS_CHOICES,
            "readonly": not is_not_readonly(request.user),
        },
    )


@login_required
@user_passes_test(is_not_readonly)
@require_http_methods(["POST", "DELETE"])
def delete_value_annotation(request, pk):
    """Delete an individual annotation/comment on a plugin result row."""
    annotation = get_object_or_404(ValueAnnotation, pk=pk)
    if annotation.user != request.user and not request.user.is_superuser:
        return HttpResponseForbidden("Cannot delete another user's annotation.")
    value_id = annotation.value_id
    annotation.delete()
    return redirect("website:value_annotations", value_id=value_id)


@login_required
@require_http_methods(["GET", "POST"])
def dump_secrets(request, index):
    """View and scan secrets for a specific memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot run secrets scanner.")
        scan_dump_for_secrets(dump)

    secrets = dump.secrets.all()
    is_htmx = getattr(request, "htmx", False)
    template = "website/partial_dump_secrets.html" if is_htmx else "website/dump_secrets.html"
    return render(
        request,
        template,
        {
            "dump": dump,
            "secrets": secrets,
            "categories": DumpSecret.CATEGORY_CHOICES,
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def dump_triage(request, index):
    """View and evaluate behavioral triage rules and risk scoring for a memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot run triage evaluation.")
        evaluate_dump_triage(dump)
        dump.refresh_from_db()

    findings = dump.triage_findings.all()
    severity_kpis = {
        "critical": findings.filter(severity="Critical").count(),
        "high": findings.filter(severity="High").count(),
        "medium": findings.filter(severity="Medium").count(),
        "low": findings.filter(severity__in=["Low", "Info"]).count(),
    }
    if dump.risk_score >= 75:
        risk_level = "Critical"
    elif dump.risk_score >= 50:
        risk_level = "High"
    elif dump.risk_score >= 25:
        risk_level = "Medium"
    elif dump.risk_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Clean"

    mitre_techniques = sorted({f.mitre_technique for f in findings if f.mitre_technique})

    is_htmx = getattr(request, "htmx", False)
    template = "website/partial_dump_triage.html" if is_htmx else "website/dump_triage.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "findings": findings,
            "risk_level": risk_level,
            "severity_kpis": severity_kpis,
            "mitre_techniques": mitre_techniques,
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def dump_narrative(request, index):
    """Generate and display natural-language first-pass triage narrative with local Ollama."""
    import requests

    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    error = None
    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot generate AI narratives.")
        model_name = request.POST.get("model_name", "").strip() or None
        try:
            generate_dump_narrative(dump, author=request.user, model_name=model_name)
        except Exception as e:
            error = str(e)

    latest_narrative = dump.narratives.first()
    history = dump.narratives.all()[1:10]

    base_url, default_model, _ = get_local_ollama_config()
    available_models = [default_model]
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=3)
        if resp.status_code == 200:
            names = [m.get("name") for m in resp.json().get("models", []) if m.get("name")]
            if names:
                available_models = names
    except Exception:
        pass

    is_htmx = getattr(request, "htmx", False)
    template = "website/partial_dump_narrative.html" if is_htmx else "website/dump_narrative.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "narrative": latest_narrative,
            "history": history,
            "available_models": available_models,
            "current_model": (latest_narrative.model_name if latest_narrative else default_model),
            "error": error,
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET"])
def dump_narrative_export(request, index, narrative_id):
    """Export verified AI narrative as a standalone Markdown document."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to access this dump.")

    narrative = get_object_or_404(DumpNarrative, pk=narrative_id, dump=dump)

    header = (
        f"# AI FORENSIC FIRST-PASS TRIAGE REPORT\n"
        f"**Target Memory Dump:** {dump.name} ({dump.operating_system})\n"
        f"**Inference Engine:** Local Ollama ({narrative.model_name})\n"
        f"**Timestamp (UTC):** {narrative.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"**Evidence Integrity SHA-256:** `{narrative.evidence_hash}`\n"
        f"**Chain-of-Custody:** Certified 100% On-Premise Inference (Zero External Transmission)\n"
        f"**Forensic Guardrails Status:** {'✓ Clean (Zero Fabrications)' if narrative.hallucination_check.get('is_clean') else '⚠️ Guardrail Warnings Present'}\n"
        f"**Total Cited Artifacts:** {len(narrative.citations)}\n\n"
        f"---\n\n"
    )
    content = header + narrative.raw_narrative

    filename = f"{slugify(dump.name)}_triage_narrative.md"
    response = HttpResponse(content, content_type="text/markdown; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@login_required
@require_http_methods(["GET", "POST"])
def promote_to_finding(request):
    """Promote a DumpSecret or TriageFinding to an investigative Case Finding."""
    if request.method == "POST" and not is_not_readonly(request.user):
        return HttpResponseForbidden("Read-only users cannot promote findings.")

    if request.method == "GET":
        item_type = request.GET.get("type", "").strip()
        item_id = request.GET.get("id", "").strip()

        if item_type == "secret":
            secret = get_object_or_404(DumpSecret, pk=item_id)
            if secret.dump not in get_objects_for_user(request.user, "website.can_see"):
                return HttpResponseForbidden("Unauthorized to access this dump.")
            title = f"Exposed {secret.get_category_display()}: {secret.rule_name}"
            severity = "High"
            mitre_technique = "T1552 - Unsecured Credentials"
            tags = "credential,secret,memory"
            note = (
                f"Secret detected in memory dump '{secret.dump.name}'\n"
                f"Rule: {secret.rule_name}\n"
                f"Category: {secret.get_category_display()}\n"
                f"Process: {secret.process_name or 'N/A'} (PID: {secret.pid or 'N/A'})\n"
                f"Offset: {secret.offset or 'N/A'}\n"
                f"Masked Snippet: {secret.masked_data}"
            )
        elif item_type == "triage":
            tf = get_object_or_404(TriageFinding, pk=item_id)
            if tf.dump not in get_objects_for_user(request.user, "website.can_see"):
                return HttpResponseForbidden("Unauthorized to access this dump.")
            title = f"[{tf.severity}] {tf.rule_name}"
            severity = tf.severity if tf.severity in ["Low", "Medium", "High", "Critical"] else "Medium"
            mitre_technique = tf.mitre_technique or ""
            tags = "triage,behavioral,detection"
            note = (
                f"Detection Rule: {tf.rule_name} ({tf.rule_id})\n"
                f"Category: {tf.category}\n"
                f"Severity: {tf.severity} (Score Weight: +{tf.score})\n"
                f"Entity: {tf.entity or 'N/A'}\n"
                f"Description: {tf.description}\n"
                f"Evidence: {tf.evidence_snippet or 'N/A'}"
            )
        else:
            return HttpResponseForbidden("Invalid promotion item type.")

        cases = Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct()

        return render(
            request,
            "website/partial_promote_to_finding.html",
            {
                "cases": cases,
                "title": title,
                "severity": severity,
                "mitre_technique": mitre_technique,
                "tags": tags,
                "note": note,
                "item_type": item_type,
                "item_id": item_id,
            },
        )

    # POST
    item_type = request.POST.get("item_type", "").strip()
    item_id = request.POST.get("item_id", "").strip()
    case_id = request.POST.get("case_id", "").strip()
    new_case_name = request.POST.get("new_case_name", "").strip()
    severity = request.POST.get("severity", "Medium")
    mitre_technique = request.POST.get("mitre_technique", "").strip()
    tags_str = request.POST.get("tags", "").strip()
    tags = [t.strip() for t in tags_str.split(",") if t.strip()]
    note = request.POST.get("note", "").strip()

    if new_case_name:
        case, _ = Case.objects.get_or_create(
            name=new_case_name,
            user=request.user,
        )
    elif case_id:
        case = get_object_or_404(
            Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)),
            pk=case_id,
        )
    else:
        cases = Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user)).distinct()
        return render(
            request,
            "website/partial_promote_to_finding.html",
            {
                "error": "Please select an existing case or enter a new case name.",
                "cases": cases,
                "title": f"Item #{item_id}",
                "severity": severity,
                "mitre_technique": mitre_technique,
                "tags": tags_str,
                "note": note,
                "item_type": item_type,
                "item_id": item_id,
            },
        )

    evidence = None
    if item_type == "secret":
        secret = get_object_or_404(DumpSecret, pk=item_id)
        if secret.dump not in get_objects_for_user(request.user, "website.can_see"):
            return HttpResponseForbidden("Unauthorized to access this dump.")
        evidence = Evidence.objects.create(
            case=case,
            dump=secret.dump,
            plugin="secrets_scanner",
            name=f"Secret: {secret.rule_name}"[:250],
            description=secret.masked_data,
        )
    elif item_type == "triage":
        tf = get_object_or_404(TriageFinding, pk=item_id)
        if tf.dump not in get_objects_for_user(request.user, "website.can_see"):
            return HttpResponseForbidden("Unauthorized to access this dump.")
        evidence = Evidence.objects.create(
            case=case,
            dump=tf.dump,
            plugin=tf.category,
            result_row=tf.raw_data,
            name=f"Triage: {tf.rule_name}"[:250],
            description=tf.description,
        )

    Finding.objects.create(
        case=case,
        evidence=evidence,
        severity=severity,
        mitre_attack_technique=mitre_technique,
        note=note,
        tags=tags,
    )

    return render(
        request,
        "website/partial_promote_to_finding.html",
        {
            "success": True,
            "case": case,
        },
    )
