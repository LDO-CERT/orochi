import base64
import json
import logging
import mmap
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.db.models import F, Q
from django.http import Http404, HttpResponseForbidden, JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.utils.text import slugify
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user, get_perms
from pymisp import MISPEvent, MISPObject
from pymisp.tools import FileObject

from orochi.utils.timeliner import (
    build_timeline_feed,
    clean_bodywork,
    extract_timeline_entries,
)
from orochi.utils.volatility_dask_elk import get_parameters
from orochi.website.ai_narrative import generate_dump_narrative, get_local_ollama_config
from orochi.website.defaults import (
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_EMPTY,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
    SERVICE_CAPE,
    SERVICE_MISP,
)
from orochi.website.detection.engine import evaluate_dump_triage
from orochi.website.forms import (
    DumpForm,
    EditDumpForm,
    ParametersForm,
)
from orochi.website.models import (
    Case,
    Dump,
    DumpNarrative,
    DumpSecret,
    Plugin,
    Result,
    Service,
    TriageFinding,
    UserPlugin,
    Value,
    ValueAnnotation,
)
from orochi.website.roles import (
    ROLE_ANALYST,
    can_execute_plugin,
    has_role,
)
from orochi.website.secrets_scanner import scan_dump_for_secrets
from orochi.website.storage import ensure_local_dump_path, get_local_dump_size
from orochi.website.temporal import compute_temporal_diff
from orochi.website.views.common import (
    COLOR_TEMPLATE,
    DUMP_ORDER_BY,
    INDEX_VALUES_LIST,
    PLUGIN_WITH_CHILDREN,
    SYSTEM_COLUMNS,
    change_keys,
    get_hex_rec,
    is_analyst_or_admin,
    is_not_readonly,
    role_required,
)

logger = logging.getLogger(__name__)


def _views_pkg():
    return sys.modules["orochi.website.views"]


@login_required
@role_required(is_not_readonly)
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
    sandbox_configured = Service.objects.filter(name=SERVICE_CAPE).exists() and is_not_readonly(request.user)

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
                    "sandbox_configured": sandbox_configured,
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
                                    "dump_index": r.dump.index,
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
                                "dump_index": r.dump.index,
                                "color": colors.get(r.dump.index),
                            }
                        )

            is_pstree = any(p in plugin.name.lower() for p in ["pstree", "pslist"])
            pstree_dump_index = dumps[0].index if (is_pstree and len(dumps) == 1) else None

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
                    "is_pstree": is_pstree,
                    "pstree_dump_index": pstree_dump_index,
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
                    + ["orochi_name", "orochi_color", "actions"]
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
    indexes = request.GET.getlist("indexes[]") or request.GET.getlist("indexes")
    if not indexes and request.GET.get("indexes"):
        indexes = [request.GET.get("indexes")]

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
            orochi_index=F("result__dump__index"),
            orochi_os=F("result__dump__operating_system"),
            orochi_color=F("result__dump__color"),
            orochi_createdAt=F("result__updated_at"),
        )
        .values(
            "orochi_plugin",
            "orochi_name",
            "orochi_index",
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

    is_htmx = (
        getattr(request, "htmx", False)
        or request.headers.get("HX-Request") == "true"
        or request.GET.get("modal") == "1"
    )

    file_size = get_local_dump_size(dump)

    context = {
        "index": index,
        "name": dump.name,
        "dump": dump,
        "file_size": file_size,
        "initial_offset": initial_offset,
        "initial_search": initial_search,
        "back_to": back_to,
        "is_standalone": not is_htmx,
    }
    template = "website/hex_view.html" if is_htmx else "website/dump_hex.html"
    return TemplateResponse(request, template, context)


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

    local_dump_path = ensure_local_dump_path(dump)
    try:
        data, size = get_hex_rec(local_dump_path, length, start)
    except ValueError:
        data, size = get_hex_rec(local_dump_path, length, 0)
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

    local_dump_path = ensure_local_dump_path(dump)
    with open(local_dump_path, "r+b") as f:
        map_file = mmap.mmap(f.fileno(), length=0, prot=mmap.PROT_READ)
        if m := pattern.search(map_file[last:]):
            new_offset, _ = m.span()
            return JsonResponse({"found": 1, "pos": new_offset + last}, status=200)
        if m := pattern.search(map_file[:]):
            new_offset, _ = m.span()
            return JsonResponse({"found": 1, "pos": new_offset}, status=200)
        return JsonResponse({"found": -1, "pos": 0}, status=200)


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


@login_required
@role_required(is_not_readonly)
def restart(request):
    """Restart plugin on index"""
    if not getattr(request, "htmx", False) and request.META.get("HTTP_X_REQUESTED_WITH") != "XMLHttpRequest":
        return JsonResponse({"status_code": 405, "error": "Method Not Allowed"})

    index = request.GET.get("index") or request.POST.get("index")
    dump = get_object_or_404(get_objects_for_user(request.user, "website.can_see", klass=Dump), index=index)

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
                    lambda: _views_pkg().index_f_and_f(dump.pk, request.user.pk, password=None, restart=plugins_id)
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


@login_required
@require_http_methods(["GET", "POST"])
def export(request):
    """Export extracted dump file to misp"""
    try:
        filepath = request.GET.get("path") or request.POST.get("path")
        if not filepath:
            return JsonResponse(
                {
                    "detail": "File path parameter 'path' is required.",
                    "message": "File path parameter 'path' is required.",
                },
                status=400,
            )

        # Allow passing index and plugin directly, or resolve from path / Value
        index = (
            request.GET.get("dump") or request.GET.get("index") or request.POST.get("dump") or request.POST.get("index")
        )
        plugin_name = request.GET.get("plugin") or request.POST.get("plugin")

        val_obj = None
        if index and plugin_name:
            dump = get_object_or_404(Dump, index=index)
            plugin = get_object_or_404(Plugin, name=plugin_name)
        else:
            val_obj = (
                Value.objects.filter(value__down_path=filepath).select_related("result__dump", "result__plugin").first()
            )
            if val_obj:
                dump = val_obj.result.dump
                plugin = val_obj.result.plugin
            else:
                parts = [p for p in Path(filepath).parts if p and p != "/"]
                dump = None
                for part in parts:
                    if Dump.objects.filter(index=part).exists():
                        dump = Dump.objects.get(index=part)
                        break
                if not dump:
                    return JsonResponse(
                        {
                            "detail": f"Unable to determine memory dump from path '{filepath}'.",
                            "message": "Dump not found.",
                        },
                        status=400,
                    )
                plugin = None
                for part in parts:
                    if Plugin.objects.filter(name=part).exists():
                        plugin = Plugin.objects.get(name=part)
                        break
                if not plugin:
                    return JsonResponse(
                        {
                            "detail": f"Unable to determine Volatility plugin from path '{filepath}'.",
                            "message": "Plugin not found.",
                        },
                        status=400,
                    )

        if dump not in get_objects_for_user(request.user, "website.can_see"):
            return HttpResponseForbidden("Unauthorized to access this dump.")

        try:
            misp_info = Service.objects.get(name=SERVICE_MISP)
        except Service.DoesNotExist:
            return JsonResponse(
                {
                    "detail": "MISP service is not configured in Admin > Services.",
                    "message": "MISP service not configured.",
                },
                status=400,
            )

        # Validate file presence on disk
        p_file = Path(filepath)
        if not p_file.exists():
            cand = Path(settings.MEDIA_ROOT) / filepath.lstrip("/")
            if cand.exists():
                filepath = str(cand)
                p_file = cand
            else:
                return JsonResponse(
                    {
                        "detail": f"Extracted file not found on disk at '{filepath}'.",
                        "message": "File not found on disk.",
                    },
                    status=400,
                )

        proxy_dict = misp_info.proxy if (misp_info.proxy and isinstance(misp_info.proxy, dict)) else None
        misp = _views_pkg().PyMISP(misp_info.url, misp_info.decrypted_key, misp_info.verify_ssl, proxies=proxy_dict)
        event = MISPEvent()
        event.info = f"From orochi: {plugin.name}@{dump.name}"
        event.distribution = 0
        event.threat_level_id = 1 if dump.risk_score >= 75 else 2 if dump.risk_score >= 50 else 3
        event.analysis = 2
        event.add_tag("orochi")
        event.add_tag("memory-forensics")

        # Create file object
        file_obj = FileObject(filepath)
        event.add_object(file_obj)

        if not val_obj:
            val_obj = Value.objects.filter(result__plugin=plugin, result__dump=dump, value__down_path=filepath).first()

        if val_obj and isinstance(val_obj.value, dict):
            s = val_obj.value

            # ADD CLAMAV SIGNATURE
            if s.get("clamav") and s["clamav"] != "-":
                clamav_obj = MISPObject("av-signature")
                clamav_obj.add_attribute("signature", value=s["clamav"])
                clamav_obj.add_attribute("software", value="clamav")
                file_obj.add_reference(clamav_obj.uuid, "attributed-to")
                event.add_object(clamav_obj)

            # ADD VT SIGNATURE
            vt_path = Path(f"{filepath}.vt.json")
            if vt_path.exists():
                try:
                    with open(vt_path) as f:
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
                except Exception as ex:
                    logger.warning(f"Could not load VT json for MISP: {ex}")

        res = misp.add_event(event)
        event_id = res.get("Event", {}).get("id") if isinstance(res, dict) else getattr(event, "id", None)
        return JsonResponse(
            {
                "success": True,
                "message": f"MISP export successful (Event ID: {event_id})",
                "event_id": event_id,
            }
        )
    except Exception as e:
        logger.exception("MISP export failed")
        return JsonResponse({"detail": str(e), "message": str(e), "errors": str(e)}, status=400, safe=False)


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
        "readonly": not is_not_readonly(request.user),
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
        "readonly": not is_not_readonly(request.user),
    }
    return TemplateResponse(request, "website/index.html", context)


@login_required
def download(request):
    """Download dump data"""
    filepath = request.GET.get("path")
    if not filepath or ".." in filepath:
        raise Http404("404")

    dump = None
    media_root_str = str(settings.MEDIA_ROOT)
    if filepath.startswith(media_root_str):
        rel_parts = Path(os.path.relpath(filepath, media_root_str)).parts
        if rel_parts:
            dump = Dump.objects.filter(index=rel_parts[0]).first()
    if not dump:
        parts = Path(filepath).parts
        if len(parts) >= 3:
            dump = Dump.objects.filter(index=parts[2]).first()
    if not dump:
        raise Http404("404")

    if dump not in get_objects_for_user(request.user, "website.can_see"):
        raise Http404("404")
    if os.path.exists(filepath):
        media_root_str = str(settings.MEDIA_ROOT)
        if (
            request.headers.get("X-Accel-Support") == "yes" or getattr(settings, "USE_X_ACCEL_REDIRECT", False)
        ) and filepath.startswith(media_root_str):
            rel_path = os.path.relpath(filepath, media_root_str).lstrip("/")
            response = HttpResponse()
            response["X-Accel-Redirect"] = f"/protected_media/{rel_path}"
            response["Content-Type"] = "application/force-download"
            response["Content-Disposition"] = f'attachment; filename="{os.path.basename(filepath)}"'
            return response

        with open(filepath, "rb") as fh:
            response = HttpResponse(fh.read(), content_type="application/force-download")
            response["Content-Disposition"] = f"inline; filename={os.path.basename(filepath)}"
            return response
    return Http404("404")


@login_required
@role_required(is_analyst_or_admin)
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


@login_required
@role_required(is_analyst_or_admin)
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
@require_http_methods(["GET"])
def dump_process_tree(request, index):
    """View interactive visual process tree for a memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    from orochi.website.process_tree import build_process_tree

    tree_data = build_process_tree(dump)
    focus_pid = request.GET.get("focus") or request.GET.get("pid") or ""

    is_htmx = (
        getattr(request, "htmx", False)
        or request.headers.get("HX-Request") == "true"
        or request.GET.get("modal") == "1"
    )
    template = "website/partial_dump_process_tree.html" if is_htmx else "website/dump_process_tree.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "tree_data": tree_data,
            "tree_json": json.dumps(tree_data),
            "focus_pid": focus_pid,
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def dump_narrative(request, index):
    """Generate and display natural-language first-pass triage narrative with local Ollama."""

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
@require_http_methods(["GET"])
def dump_network(request, index):
    """View interactive network topology graph and geo-map for a memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    from orochi.website.network import extract_network_report

    network_data = extract_network_report(dump)
    is_htmx = (
        getattr(request, "htmx", False)
        or request.headers.get("HX-Request") == "true"
        or request.GET.get("modal") == "1"
    )
    template = "website/partial_dump_network.html" if is_htmx else "website/dump_network.html"

    return render(
        request,
        template,
        {
            "dump": dump,
            "network_data": network_data,
            "network_json": network_data,
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["GET"])
def partial_dump_network(request, index):
    """Render HTMX partial for network topology graph and geo-map."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    from orochi.website.network import extract_network_report

    network_data = extract_network_report(dump)
    return render(
        request,
        "website/partial_dump_network.html",
        {
            "dump": dump,
            "network_data": network_data,
            "network_json": network_data,
            "is_standalone": False,
        },
    )
