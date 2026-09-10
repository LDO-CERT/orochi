from django.urls import reverse

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Result, Value

PROCESS_PLUGINS = [
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.pstree.PsTree",
    "linux.pslist.PsList",
    "linux.pstree.PsTree",
    "linux.psscan.PsScan",
    "mac.pslist.PsList",
    "mac.pstree.PsTree",
]

MALFIND_PLUGINS = [
    "windows.malware.malfind.Malfind",
    "windows.malfind.Malfind",
    "linux.malware.malfind.Malfind",
    "linux.malfind.Malfind",
    "mac.malfind.Malfind",
]

NETWORK_PLUGINS = [
    "windows.netscan.NetScan",
    "windows.netstat.NetStat",
    "linux.sockstat.Sockstat",
    "mac.netstat.Netstat",
]


def format_duration(seconds):
    """Format duration in seconds to a human-readable string."""
    seconds = int(abs(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or (days == 0 and hours == 0 and minutes == 0):
        parts.append(f"{secs}s")
    return " ".join(parts)


def get_temporal_order(dump_a, dump_b, reverse=False):
    """
    Determine chronological order T1 (earlier) and T2 (later).
    If reverse is True, swaps the order.
    """
    time_a = dump_a.created_at
    time_b = dump_b.created_at

    t1, t2 = (dump_a, dump_b) if time_a <= time_b else (dump_b, dump_a)
    if reverse:
        t1, t2 = t2, t1

    delta_seconds = (t2.created_at - t1.created_at).total_seconds()
    time_delta_display = format_duration(delta_seconds)

    is_same_host = bool(t1.host_id and t2.host_id and t1.host_id == t2.host_id)
    host_name = None
    if is_same_host and t1.host:
        host_name = t1.host.name
    elif t1.host or t2.host:
        h1 = t1.host.name if t1.host else "Unassigned"
        h2 = t2.host.name if t2.host else "Unassigned"
        host_name = f"{h1} vs {h2}"

    return {
        "t1": t1,
        "t2": t2,
        "delta_seconds": delta_seconds,
        "time_delta_display": time_delta_display,
        "is_same_host": is_same_host,
        "host_name": host_name,
        "is_reversed": reverse,
    }


def _normalize_pid(val):
    if val is None:
        return ""
    try:
        return int(val)
    except (ValueError, TypeError):
        return str(val)


def _get_best_result(dump, preferred_plugin_names):
    """Find the best successful result for a given dump from preferred plugin list."""
    results = {
        r.plugin.name: r
        for r in Result.objects.filter(
            dump=dump,
            result=RESULT_STATUS_SUCCESS,
            plugin__name__in=preferred_plugin_names,
        ).select_related("plugin")
    }
    return next(
        (results[name] for name in preferred_plugin_names if name in results),
        None,
    )


def diff_processes(dump_t1, dump_t2):
    """
    Compute delta of processes between T1 and T2:
    - New in T2
    - Terminated in T2 (present in T1)
    - Persisted (present in both)
    """
    res_t1 = _get_best_result(dump_t1, PROCESS_PLUGINS)
    res_t2 = _get_best_result(dump_t2, PROCESS_PLUGINS)

    if not res_t1 and not res_t2:
        return {
            "available": False,
            "plugin_t1": None,
            "plugin_t2": None,
            "total_t1": 0,
            "total_t2": 0,
            "new_count": 0,
            "terminated_count": 0,
            "persisted_count": 0,
            "new": [],
            "terminated": [],
            "persisted": [],
            "all": [],
        }

    def _extract_procs(res, dump_label):
        if not res:
            return {}, []
        items_dict = {}
        items_list = []
        for val in Value.objects.filter(result=res):
            v = val.value or {}
            pid = _normalize_pid(v.get("PID") or v.get("pid"))
            name = str(
                v.get("ImageFileName")
                or v.get("COMM")
                or v.get("Process")
                or v.get("Name")
                or v.get("process_name")
                or "Unknown"
            )
            ppid = _normalize_pid(v.get("PPID") or v.get("ppid"))
            proc_item = {
                "pid": pid,
                "name": name,
                "ppid": ppid,
                "threads": v.get("Threads") or v.get("threads") or "-",
                "handles": v.get("Handles") or v.get("handles") or "-",
                "session": v.get("SessionId") or v.get("session") or "-",
                "create_time": str(v.get("CreateTime") or v.get("Created") or v.get("Start") or "-"),
                "exit_time": str(v.get("ExitTime") or v.get("Exited") or "-"),
                "cmdline": v.get("Cmdline") or v.get("CommandLine") or v.get("Path") or "",
                "offset": v.get("Offset(V)") or v.get("Offset(P)") or v.get("Offset") or v.get("OFFSET") or "-",
                "dump_source": dump_label,
            }
            key = (pid, name.lower())
            items_dict[key] = proc_item
            items_list.append((key, proc_item))
        return items_dict, items_list

    t1_dict, t1_list = _extract_procs(res_t1, "T1")
    t2_dict, t2_list = _extract_procs(res_t2, "T2")

    new_procs = []
    terminated_procs = []
    persisted_procs = []
    all_procs = []

    # New in T2
    for key, item in t2_list:
        if key not in t1_dict:
            entry = dict(item)
            entry["status"] = "new"
            new_procs.append(entry)
            all_procs.append(entry)
        else:
            entry = dict(item)
            entry["status"] = "persisted"
            persisted_procs.append(entry)
            all_procs.append(entry)

    # Terminated (in T1 but not in T2)
    for key, item in t1_list:
        if key not in t2_dict:
            entry = dict(item)
            entry["status"] = "terminated"
            terminated_procs.append(entry)
            all_procs.append(entry)

    # Sort all: new first, then terminated, then persisted, then by PID
    status_order = {"new": 0, "terminated": 1, "persisted": 2}
    all_procs.sort(
        key=lambda x: (
            status_order.get(x["status"], 3),
            x["pid"] if isinstance(x["pid"], int) else 999999,
            x["name"],
        )
    )

    return {
        "available": True,
        "plugin_t1": res_t1.plugin.name if res_t1 else None,
        "plugin_t2": res_t2.plugin.name if res_t2 else None,
        "total_t1": len(t1_dict),
        "total_t2": len(t2_dict),
        "new_count": len(new_procs),
        "terminated_count": len(terminated_procs),
        "persisted_count": len(persisted_procs),
        "new": new_procs,
        "terminated": terminated_procs,
        "persisted": persisted_procs,
        "all": all_procs,
    }


def diff_injected_regions(dump_t1, dump_t2):
    """
    Compute delta of injected memory regions (malfind) between T1 and T2.
    Detects new injected code in T2 (critical forensic finding).
    """
    res_t1 = _get_best_result(dump_t1, MALFIND_PLUGINS)
    res_t2 = _get_best_result(dump_t2, MALFIND_PLUGINS)

    if not res_t1 and not res_t2:
        return {
            "available": False,
            "plugin_t1": None,
            "plugin_t2": None,
            "total_t1": 0,
            "total_t2": 0,
            "new_count": 0,
            "terminated_count": 0,
            "persisted_count": 0,
            "new": [],
            "terminated": [],
            "persisted": [],
            "all": [],
        }

    def _extract_malfind(res, dump_label):
        if not res:
            return {}, []
        items_dict = {}
        items_list = []
        for val in Value.objects.filter(result=res):
            v = val.value or {}
            pid = _normalize_pid(v.get("PID") or v.get("pid"))
            process = str(v.get("Process") or v.get("ImageFileName") or v.get("COMM") or "Unknown")
            start = str(v.get("Start") or v.get("Start VPN") or v.get("Address") or "")
            end = str(v.get("End") or v.get("End VPN") or "")
            protection = str(v.get("Protection") or v.get("Flags") or "-")
            hexdump = str(v.get("HexDump") or v.get("HexBytes") or "")
            disassembly = str(v.get("Disasm") or v.get("Disassembly") or "")
            has_pe = "4d 5a" in hexdump.lower() or "MZ" in hexdump
            has_elf = "7f 45 4c 46" in hexdump.lower() or ".ELF" in hexdump

            item = {
                "pid": pid,
                "process": process,
                "start": start,
                "end": end,
                "protection": protection,
                "hexdump": hexdump,
                "disassembly": disassembly,
                "has_pe": has_pe,
                "has_elf": has_elf,
                "dump_source": dump_label,
            }
            key = (pid, process.lower(), start.lower())
            items_dict[key] = item
            items_list.append((key, item))
        return items_dict, items_list

    t1_dict, t1_list = _extract_malfind(res_t1, "T1")
    t2_dict, t2_list = _extract_malfind(res_t2, "T2")

    new_regions = []
    terminated_regions = []
    persisted_regions = []
    all_regions = []

    for key, item in t2_list:
        if key not in t1_dict:
            entry = dict(item)
            entry["status"] = "new"
            new_regions.append(entry)
            all_regions.append(entry)
        else:
            entry = dict(item)
            entry["status"] = "persisted"
            persisted_regions.append(entry)
            all_regions.append(entry)

    for key, item in t1_list:
        if key not in t2_dict:
            entry = dict(item)
            entry["status"] = "terminated"
            terminated_regions.append(entry)
            all_regions.append(entry)

    status_order = {"new": 0, "terminated": 1, "persisted": 2}
    all_regions.sort(
        key=lambda x: (
            status_order.get(x["status"], 3),
            x["pid"] if isinstance(x["pid"], int) else 999999,
            x["start"],
        )
    )

    return {
        "available": True,
        "plugin_t1": res_t1.plugin.name if res_t1 else None,
        "plugin_t2": res_t2.plugin.name if res_t2 else None,
        "total_t1": len(t1_dict),
        "total_t2": len(t2_dict),
        "new_count": len(new_regions),
        "terminated_count": len(terminated_regions),
        "persisted_count": len(persisted_regions),
        "new": new_regions,
        "terminated": terminated_regions,
        "persisted": persisted_regions,
        "all": all_regions,
    }


def diff_network(dump_t1, dump_t2):
    """
    Compute delta of network connections between T1 and T2:
    - New connections established in T2
    - Closed connections (present in T1, gone in T2)
    - Persisted connections
    """
    res_t1 = _get_best_result(dump_t1, NETWORK_PLUGINS)
    res_t2 = _get_best_result(dump_t2, NETWORK_PLUGINS)

    if not res_t1 and not res_t2:
        return {
            "available": False,
            "plugin_t1": None,
            "plugin_t2": None,
            "total_t1": 0,
            "total_t2": 0,
            "new_count": 0,
            "closed_count": 0,
            "persisted_count": 0,
            "new": [],
            "closed": [],
            "persisted": [],
            "all": [],
        }

    def _is_external_ip(ip_str):
        if not ip_str:
            return False
        clean = str(ip_str).replace('"', "").strip()
        if ":" in clean and not clean.startswith("::"):
            clean = clean.split(":")[0]
        if clean in ["0.0.0.0", "127.0.0.1", "::", "::1", "-", "None", "", "*"]:
            return False
        return not clean.startswith("127.") and not clean.startswith("groups:") and not clean.startswith("/")

    def _extract_net(res, dump_label):
        if not res:
            return {}, []
        items_dict = {}
        items_list = []
        for val in Value.objects.filter(result=res):
            v = val.value or {}
            proto = str(v.get("Proto") or v.get("Protocol") or v.get("Family") or "TCP").upper()
            local_addr = str(v.get("LocalAddr") or v.get("Local Addr") or v.get("Source Addr") or v.get("SrcIP") or "-")
            local_port = str(
                v.get("LocalPort") or v.get("Local Port") or v.get("Source Port") or v.get("SrcPort") or "-"
            )
            foreign_addr = str(
                v.get("ForeignAddr") or v.get("Destination Addr") or v.get("Foreign Addr") or v.get("DstIP") or "-"
            )
            foreign_port = str(
                v.get("ForeignPort") or v.get("Destination Port") or v.get("Foreign Port") or v.get("DstPort") or "-"
            )
            state = str(v.get("State") or "-").upper()
            pid = _normalize_pid(v.get("PID") or v.get("Owner PID") or v.get("pid"))
            owner = str(v.get("Owner") or v.get("Process") or v.get("COMM") or "-")
            created = str(v.get("Created") or v.get("Created Time") or v.get("Time") or "-")

            item = {
                "proto": proto,
                "local_addr": local_addr,
                "local_port": local_port,
                "foreign_addr": foreign_addr,
                "foreign_port": foreign_port,
                "state": state,
                "pid": pid,
                "owner": owner,
                "created": created,
                "is_external": _is_external_ip(foreign_addr),
                "dump_source": dump_label,
            }
            key = (proto, local_addr, local_port, foreign_addr, foreign_port)
            items_dict[key] = item
            items_list.append((key, item))
        return items_dict, items_list

    t1_dict, t1_list = _extract_net(res_t1, "T1")
    t2_dict, t2_list = _extract_net(res_t2, "T2")

    new_conns = []
    closed_conns = []
    persisted_conns = []
    all_conns = []

    for key, item in t2_list:
        if key not in t1_dict:
            entry = dict(item)
            entry["status"] = "new"
            new_conns.append(entry)
            all_conns.append(entry)
        else:
            entry = dict(item)
            entry["status"] = "persisted"
            persisted_conns.append(entry)
            all_conns.append(entry)

    for key, item in t1_list:
        if key not in t2_dict:
            entry = dict(item)
            entry["status"] = "closed"
            closed_conns.append(entry)
            all_conns.append(entry)

    status_order = {"new": 0, "closed": 1, "persisted": 2}
    all_conns.sort(
        key=lambda x: (
            status_order.get(x["status"], 3),
            x["proto"],
            x["local_addr"],
        )
    )

    return {
        "available": True,
        "plugin_t1": res_t1.plugin.name if res_t1 else None,
        "plugin_t2": res_t2.plugin.name if res_t2 else None,
        "total_t1": len(t1_dict),
        "total_t2": len(t2_dict),
        "new_count": len(new_conns),
        "closed_count": len(closed_conns),
        "persisted_count": len(persisted_conns),
        "new": new_conns,
        "closed": closed_conns,
        "persisted": persisted_conns,
        "all": all_conns,
    }


def diff_common_plugins(dump_t1, dump_t2):
    """
    Find all plugins that succeeded on both T1 and T2,
    compare their record counts, and provide links to diff_view.
    """
    results_t1 = {
        r.plugin.name: r
        for r in Result.objects.filter(dump=dump_t1, result=RESULT_STATUS_SUCCESS).select_related("plugin")
    }
    results_t2 = {
        r.plugin.name: r
        for r in Result.objects.filter(dump=dump_t2, result=RESULT_STATUS_SUCCESS).select_related("plugin")
    }

    common_names = sorted(set(results_t1.keys()) & set(results_t2.keys()))
    plugins_summary = []

    for name in common_names:
        r1 = results_t1[name]
        r2 = results_t2[name]
        count_1 = Value.objects.filter(result=r1).count()
        count_2 = Value.objects.filter(result=r2).count()
        has_diff = count_1 != count_2

        diff_url = reverse(
            "website:diff_view",
            kwargs={
                "index_a": dump_t1.index,
                "index_b": dump_t2.index,
                "plugin": name,
            },
        )

        plugins_summary.append(
            {
                "name": name,
                "count_t1": count_1,
                "count_t2": count_2,
                "has_diff": has_diff,
                "diff_url": diff_url,
            }
        )

    return plugins_summary


def compute_temporal_diff(dump_a, dump_b, reverse=False):
    """
    Main entry point for computing the complete temporal delta between two memory dumps.
    """
    temporal_meta = get_temporal_order(dump_a, dump_b, reverse=reverse)
    t1 = temporal_meta["t1"]
    t2 = temporal_meta["t2"]

    procs_diff = diff_processes(t1, t2)
    injected_diff = diff_injected_regions(t1, t2)
    network_diff = diff_network(t1, t2)
    common_plugins = diff_common_plugins(t1, t2)

    return {
        "meta": temporal_meta,
        "t1": t1,
        "t2": t2,
        "processes": procs_diff,
        "injected": injected_diff,
        "network": network_diff,
        "common_plugins": common_plugins,
        "summary": {
            "new_processes": procs_diff["new_count"],
            "terminated_processes": procs_diff["terminated_count"],
            "persisted_processes": procs_diff["persisted_count"],
            "new_injected": injected_diff["new_count"],
            "terminated_injected": injected_diff["terminated_count"],
            "new_connections": network_diff["new_count"],
            "closed_connections": network_diff["closed_count"],
            "common_plugins_count": len(common_plugins),
        },
    }
