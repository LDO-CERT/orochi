import re
from typing import Any

from orochi.website.defaults import (
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_EMPTY,
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
    RESULT_STATUS_UNSATISFIED,
)
from orochi.website.models import Dump, Result, Value
from orochi.website.process_tree import _extract_pid, _format_offset, build_process_tree

CREDENTIAL_KEY_RE = re.compile(r"(KEY|TOKEN|SECRET|PASS|AUTH|CRED|API|AWS_|PRIVATE)", re.IGNORECASE)

DOSSIER_PLUGINS_BY_OS: dict[str, list[tuple[str, str, str]]] = {
    "Windows": [
        ("windows.pslist.PsList", "Process List", "process"),
        ("windows.cmdline.CmdLine", "Command Line", "cmdline"),
        ("windows.envars.Envars", "Environment Variables", "envars"),
        ("windows.netscan.NetScan", "Network Sockets", "network"),
        ("windows.malfind.Malfind", "Code Injection (Malfind)", "malfind"),
        ("windows.ldrmodules.LdrModules", "Loaded DLLs (LdrModules)", "modules"),
        ("windows.privileges.Privs", "Process Privileges", "privileges"),
        ("windows.getsids.GetSIDs", "Security Identifiers (SIDs)", "sids"),
        ("windows.handles.Handles", "Open Handles", "handles"),
        ("windows.consoles.Consoles", "Console Buffers", "console"),
    ],
    "Linux": [
        ("linux.pslist.PsList", "Process List", "process"),
        ("linux.psaux.PsAux", "Command Line (psaux)", "cmdline"),
        ("linux.envars.Envars", "Environment Variables", "envars"),
        ("linux.sockstat.Sockstat", "Network Sockets", "network"),
        ("linux.malfind.Malfind", "Code Injection (Malfind)", "malfind"),
        ("linux.proc.Maps", "Memory Maps (proc.Maps)", "modules"),
        ("linux.capabilities.Capabilities", "Process Capabilities", "privileges"),
        ("linux.lsof.Lsof", "Open Files (lsof)", "handles"),
        ("linux.bash.Bash", "Bash History", "console"),
    ],
    "Mac": [
        ("mac.pslist.PsList", "Process List", "process"),
        ("mac.psaux.Psaux", "Command Line (psaux)", "cmdline"),
        ("mac.netstat.Netstat", "Network Sockets", "network"),
        ("mac.malfind.Malfind", "Code Injection (Malfind)", "malfind"),
        ("mac.proc_maps.Maps", "Memory Maps (proc_maps)", "modules"),
        ("mac.lsof.Lsof", "Open Files (lsof)", "handles"),
        ("mac.bash.Bash", "Bash History", "console"),
    ],
}

STATUS_LABELS: dict[int, tuple[str, str]] = {
    RESULT_STATUS_NOT_STARTED: ("not_executed", "Not Executed"),
    RESULT_STATUS_RUNNING: ("running", "Running on Dask"),
    RESULT_STATUS_EMPTY: ("empty", "Executed (0 rows)"),
    RESULT_STATUS_SUCCESS: ("success", "Executed"),
    RESULT_STATUS_UNSATISFIED: ("failed", "Unsatisfied"),
    RESULT_STATUS_DISABLED: ("not_executed", "Disabled / Not Run"),
}


def _row_matches_pid(row: dict[str, Any], target_pid: int) -> bool:
    for key in ("PID", "Pid", "pid", "Process ID"):
        if key in row:
            parsed = _extract_pid(row.get(key))
            if parsed == target_pid:
                return True
    return False


def _fetch_pid_rows(result_obj: Result | None, target_pid: int) -> list[dict[str, Any]]:
    if not result_obj or result_obj.result != RESULT_STATUS_SUCCESS:
        return []
    matched: list[dict[str, Any]] = []
    for val in Value.objects.filter(result=result_obj).values_list("value", flat=True):
        if isinstance(val, dict) and _row_matches_pid(val, target_pid):
            matched.append(val)
    return matched


def build_process_dossier(dump: Dump, target_pid: int) -> dict[str, Any]:
    """
    Aggregates a 360-degree cross-plugin forensic dossier for a single process (PID)
    in a memory dump, including plugin execution coverage and missing-plugin tracking.
    """
    os_name = dump.operating_system or "Windows"
    matrix = DOSSIER_PLUGINS_BY_OS.get(os_name, DOSSIER_PLUGINS_BY_OS["Windows"])

    results_by_lower: dict[str, Result] = {}
    for res in Result.objects.filter(dump=dump).select_related("plugin"):
        results_by_lower[res.plugin.name.lower()] = res

    coverage_items: list[dict[str, Any]] = []
    section_status: dict[str, dict[str, Any]] = {}
    missing_plugins: list[str] = []
    executed_count = 0
    running_count = 0

    for plugin_name, label, section in matrix:
        res = results_by_lower.get(plugin_name.lower())
        raw_status = res.result if res is not None else RESULT_STATUS_DISABLED
        state_key, state_label = STATUS_LABELS.get(raw_status, ("failed", "Failed"))
        actual_name = res.plugin.name if res is not None else plugin_name

        if state_key in {"success", "empty"}:
            executed_count += 1
        elif state_key == "running":
            running_count += 1
        elif state_key == "not_executed":
            missing_plugins.append(actual_name)

        item = {
            "name": actual_name,
            "short_name": actual_name.split(".")[-1],
            "label": label,
            "section": section,
            "status": state_key,
            "status_label": state_label,
            "can_run": state_key in {"not_executed", "failed"},
            "result_obj": res,
        }
        coverage_items.append(item)
        if section not in section_status or state_key in {"success", "empty", "running"}:
            section_status[section] = {
                "status": state_key,
                "status_label": state_label,
                "plugin_name": actual_name,
                "label": label,
                "can_run": item["can_run"],
            }

    total_matrix = len(matrix)
    coverage_pct = int(round(100 * executed_count / max(1, total_matrix)))

    # 1. Process Hierarchy & Node Metadata from build_process_tree
    tree_data = build_process_tree(dump)
    nodes_by_pid: dict[int, dict[str, Any]] = {}
    for n in tree_data.get("nodes", []):
        p = _extract_pid(n.get("pid"))
        if p is not None:
            nodes_by_pid[p] = n

    target_node = nodes_by_pid.get(target_pid)
    if not target_node:
        target_node = {
            "id": str(target_pid),
            "pid": target_pid,
            "ppid": 0,
            "name": f"PID {target_pid}",
            "offset": "",
            "cmdline": "",
            "create_time": "",
            "exit_time": "",
            "threads": "",
            "handles": "",
            "session_id": "",
            "wow64": False,
            "risk_score": 0,
            "risk_level": "Clean",
            "is_flagged": False,
            "findings": [],
            "secrets": [],
        }

    # Parent, ancestors, and direct children
    parent_pid = _extract_pid(target_node.get("ppid"))
    parent_node = nodes_by_pid.get(parent_pid) if parent_pid and parent_pid != target_pid else None

    ancestors: list[dict[str, Any]] = []
    visited_anc: set[int] = {target_pid}
    curr_p = parent_pid
    while curr_p is not None and curr_p not in visited_anc and curr_p in nodes_by_pid:
        visited_anc.add(curr_p)
        anc_n = nodes_by_pid[curr_p]
        ancestors.append(
            {
                "pid": anc_n["pid"],
                "name": anc_n["name"],
                "risk_level": anc_n.get("risk_level", "Clean"),
            }
        )
        curr_p = _extract_pid(anc_n.get("ppid"))
    ancestors.reverse()

    children: list[dict[str, Any]] = []
    for p, n in nodes_by_pid.items():
        if p != target_pid and _extract_pid(n.get("ppid")) == target_pid:
            children.append(
                {
                    "pid": n["pid"],
                    "name": n["name"],
                    "cmdline": n.get("cmdline", ""),
                    "risk_level": n.get("risk_level", "Clean"),
                    "is_flagged": n.get("is_flagged", False),
                }
            )

    # Helper to look up Result by section or plugin prefix
    def _res_for(names: list[str]) -> Result | None:
        for nm in names:
            r = results_by_lower.get(nm.lower())
            if r and r.result == RESULT_STATUS_SUCCESS:
                return r
        return None

    # 2. Command Line fallback (if not already populated)
    cmdline_str = target_node.get("cmdline") or ""
    if not cmdline_str:
        for row in _fetch_pid_rows(
            _res_for(["windows.cmdline.CmdLine", "linux.psaux.PsAux", "mac.psaux.Psaux"]),
            target_pid,
        ):
            c = row.get("Args") or row.get("Command") or row.get("CommandLine") or ""
            if c:
                cmdline_str = str(c)
                break

    # 3. Environment Variables
    envars_list: list[dict[str, Any]] = []
    credential_envars_count = 0
    for row in _fetch_pid_rows(_res_for(["windows.envars.Envars", "linux.envars.Envars"]), target_pid):
        var_name = str(row.get("Variable") or row.get("Key") or "")
        var_val = str(row.get("Value") or "")
        if not var_name and not var_val:
            continue
        is_cred = bool(CREDENTIAL_KEY_RE.search(var_name))
        if is_cred:
            credential_envars_count += 1
        envars_list.append(
            {
                "variable": var_name,
                "value": var_val,
                "block": _format_offset(row.get("Block")),
                "is_credential": is_cred,
            }
        )
    envars_list.sort(key=lambda x: (not x["is_credential"], x["variable"].lower()))

    # 4. Network Sockets for PID
    network_list: list[dict[str, Any]] = []
    for net_plugin in (
        "windows.netscan.NetScan",
        "windows.netstat.NetStat",
        "linux.sockstat.Sockstat",
        "mac.netstat.Netstat",
    ):
        for row in _fetch_pid_rows(results_by_lower.get(net_plugin.lower()), target_pid):
            proto = str(row.get("Proto") or row.get("Net Protocol") or row.get("Family") or "TCP/IP")
            laddr = str(row.get("LocalAddr") or row.get("Source Addr") or row.get("Local IP") or "*")
            lport = str(row.get("LocalPort") or row.get("Source Port") or row.get("Local Port") or "")
            faddr = str(row.get("ForeignAddr") or row.get("Destination Addr") or row.get("Remote IP") or "*")
            fport = str(row.get("ForeignPort") or row.get("Destination Port") or row.get("Remote Port") or "")
            state = str(row.get("State") or "-")
            network_list.append(
                {
                    "proto": proto,
                    "local": f"{laddr}:{lport}" if lport and lport != "None" else laddr,
                    "remote": f"{faddr}:{fport}" if fport and fport != "None" else faddr,
                    "state": state,
                    "created": str(row.get("Created") or ""),
                }
            )

    # 5. Code Injection (Malfind) for PID
    malfind_list: list[dict[str, Any]] = []
    for row in _fetch_pid_rows(
        _res_for(["windows.malfind.Malfind", "linux.malfind.Malfind", "mac.malfind.Malfind"]),
        target_pid,
    ):
        hexdump = str(row.get("HexDump") or row.get("HexBytes") or "")
        malfind_list.append(
            {
                "start": _format_offset(row.get("Start") or row.get("Start VPN")),
                "end": _format_offset(row.get("End") or row.get("End VPN")),
                "protection": str(row.get("Protection") or row.get("Flags") or ""),
                "has_pe": "4d 5a" in hexdump.lower() or "MZ" in hexdump,
                "has_elf": "7f 45 4c 46" in hexdump.lower() or ".ELF" in hexdump,
                "hexdump": hexdump,
                "disassembly": str(row.get("Disasm") or row.get("Disassembly") or ""),
            }
        )

    # 6. Loaded Modules / Memory Maps
    modules_list: list[dict[str, Any]] = []
    unlinked_or_rwx_count = 0
    ldr_res = results_by_lower.get("windows.ldrmodules.ldrmodules")
    if ldr_res and ldr_res.result == RESULT_STATUS_SUCCESS:
        for row in _fetch_pid_rows(ldr_res, target_pid):
            in_load = bool(row.get("InLoad"))
            in_init = bool(row.get("InInit"))
            in_mem = bool(row.get("InMem"))
            path = str(row.get("MappedPath") or "")
            is_exe = path.lower().endswith(".exe")
            is_unlinked = (not in_load) or (not in_mem) or (not in_init and not is_exe)
            if is_unlinked:
                unlinked_or_rwx_count += 1
            modules_list.append(
                {
                    "kind": "ldrmodules",
                    "base": _format_offset(row.get("Base")),
                    "path": path or "(Unmapped / Anonymous)",
                    "in_load": in_load,
                    "in_init": in_init,
                    "in_mem": in_mem,
                    "is_flagged": is_unlinked,
                }
            )
        modules_list.sort(key=lambda x: (not x["is_flagged"], x["path"].lower()))
    else:
        maps_res = _res_for(["linux.proc.Maps", "mac.proc_maps.Maps", "windows.vadinfo.VadInfo"])
        for row in _fetch_pid_rows(maps_res, target_pid):
            flags = str(row.get("Flags") or row.get("Protection") or "")
            fpath = str(row.get("File Path") or row.get("File") or row.get("MappedPath") or "")
            is_rwx = "rwx" in flags.lower() or "PAGE_EXECUTE_READWRITE" in flags.upper()
            is_exec = "x" in flags.lower() or "EXECUTE" in flags.upper()
            is_anon_exec = is_exec and (
                not fpath
                or fpath in {"Anonymous Mapping", "[heap]", "[stack]"}
                or any(k in fpath.lower() for k in ("/memfd:", "(deleted)", "/dev/shm", "/tmp/"))
            )
            is_flagged = is_rwx or is_anon_exec
            if is_flagged:
                unlinked_or_rwx_count += 1
            modules_list.append(
                {
                    "kind": "maps",
                    "base": f"{_format_offset(row.get('Start'))} - {_format_offset(row.get('End'))}",
                    "path": fpath or "(Anonymous Mapping)",
                    "flags": flags,
                    "is_flagged": is_flagged,
                }
            )
        modules_list.sort(key=lambda x: (not x["is_flagged"], x["base"]))

    modules_total = len(modules_list)
    modules_list = modules_list[:100]

    # 7. Privileges / Capabilities / SIDs
    privileges_list: list[dict[str, Any]] = []
    high_risk_privs_count = 0
    for row in _fetch_pid_rows(
        _res_for(["windows.privileges.Privs", "linux.capabilities.Capabilities"]),
        target_pid,
    ):
        priv_name = str(row.get("Privilege") or row.get("cap_effective") or "")
        attrs = str(row.get("Attributes") or row.get("cap_permitted") or "")
        desc = str(row.get("Description") or "")
        if not priv_name:
            continue
        is_risk = priv_name.lower() == "all" or any(
            k in priv_name.lower()
            for k in (
                "sys_admin",
                "net_admin",
                "sys_ptrace",
                "sys_module",
                "sedebugprivilege",
                "seimpersonateprivilege",
                "setcbprivilege",
                "seloaddriverprivilege",
            )
        )
        if is_risk:
            high_risk_privs_count += 1
        privileges_list.append(
            {
                "name": priv_name,
                "attributes": attrs,
                "description": desc,
                "is_high_risk": is_risk,
            }
        )
    for row in _fetch_pid_rows(results_by_lower.get("windows.getsids.getsids"), target_pid):
        sid = str(row.get("SID") or "")
        sid_name = str(row.get("Name") or "")
        if sid or sid_name:
            is_admin_sid = sid.endswith("-500") or sid in {"S-1-5-18", "S-1-5-32-544"} or "admin" in sid_name.lower()
            privileges_list.append(
                {
                    "name": f"{sid_name} ({sid})" if sid_name else sid,
                    "attributes": "SID",
                    "description": "Security Identifier",
                    "is_high_risk": is_admin_sid,
                }
            )
    privileges_list.sort(key=lambda x: (not x["is_high_risk"], x["name"]))

    # 8. Open Handles / Files
    handles_list: list[dict[str, Any]] = []
    for row in _fetch_pid_rows(
        _res_for(["windows.handles.Handles", "linux.lsof.Lsof", "mac.lsof.Lsof"]),
        target_pid,
    ):
        h_name = str(row.get("Name") or row.get("File Path") or row.get("Path") or "")
        h_type = str(row.get("Type") or row.get("File Type") or "File/FD")
        h_val = str(row.get("HandleValue") or row.get("FD") or "")
        if not h_name and h_type not in {"Process", "Thread", "Mutant", "Key", "File"}:
            continue
        handles_list.append(
            {
                "handle": _format_offset(h_val) if h_val else "-",
                "type": h_type,
                "name": h_name or "(Unnamed Handle)",
                "access": _format_offset(row.get("GrantedAccess")) if row.get("GrantedAccess") else "",
            }
        )
    handles_total = len(handles_list)
    handles_list = handles_list[:100]

    # 9. Console / Bash Commands
    console_list: list[dict[str, Any]] = []
    for c_plugin in (
        "linux.bash.Bash",
        "mac.bash.Bash",
        "windows.consoles.Consoles",
        "windows.cmdscan.CmdScan",
    ):
        for row in _fetch_pid_rows(results_by_lower.get(c_plugin.lower()), target_pid):
            cmd = (
                row.get("Command")
                or row.get("CommandHistory")
                or row.get("ScreenBuffer")
                or (
                    f"[{row.get('Property')}] {row.get('Data')}"
                    if row.get("Property") and row.get("Data") and not str(row.get("Data")).strip().isdigit()
                    else None
                )
            )
            if cmd:
                console_list.append(
                    {
                        "command": str(cmd),
                        "time": str(row.get("CommandTime") or ""),
                        "plugin": c_plugin,
                    }
                )

    for item in coverage_items:
        item.pop("result_obj", None)

    return {
        "dump": {
            "index": dump.index,
            "name": dump.name,
            "operating_system": os_name,
        },
        "process": {
            "pid": target_pid,
            "ppid": parent_pid or 0,
            "name": target_node.get("name") or f"PID {target_pid}",
            "offset": _format_offset(target_node.get("offset")),
            "cmdline": cmdline_str,
            "create_time": target_node.get("create_time") or "",
            "exit_time": target_node.get("exit_time") or "",
            "threads": target_node.get("threads") or "",
            "handles": target_node.get("handles") or "",
            "session_id": target_node.get("session_id") or "",
            "wow64": target_node.get("wow64", False),
            "risk_score": target_node.get("risk_score", 0),
            "risk_level": target_node.get("risk_level", "Clean"),
            "is_flagged": target_node.get("is_flagged", False),
        },
        "parent": parent_node,
        "ancestors": ancestors,
        "children": children,
        "findings": target_node.get("findings", []),
        "secrets": target_node.get("secrets", []),
        "coverage": {
            "total": total_matrix,
            "executed": executed_count,
            "running": running_count,
            "missing_plugins": missing_plugins,
            "missing_count": len(missing_plugins),
            "pct": coverage_pct,
            "items": coverage_items,
        },
        "section_status": section_status,
        "envars": envars_list,
        "credential_envars_count": credential_envars_count,
        "network": network_list,
        "malfind": malfind_list,
        "modules": modules_list,
        "modules_total": modules_total,
        "unlinked_or_rwx_count": unlinked_or_rwx_count,
        "privileges": privileges_list,
        "high_risk_privs_count": high_risk_privs_count,
        "handles": handles_list,
        "handles_total": handles_total,
        "console": console_list,
    }
