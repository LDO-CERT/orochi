from typing import Any

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Value


def _iter_result_values(result_obj, chunk_size: int = 2000):
    """Stream raw JSON value dicts from a Result without instantiating Value model objects."""
    qs = Value.objects.filter(result=result_obj).values_list("value", flat=True)
    for val in qs.iterator(chunk_size=chunk_size):
        if isinstance(val, dict):
            yield val


def build_plugin_analysis_summaries(
    plugin_name: str,
    results,
    colors: dict[str, Any],
) -> dict[str, Any]:
    """
    Compute single-plugin forensic triage summary ribbons and cards for analysis()
    using lightweight value-dict streaming.
    """
    plugin_lower = plugin_name.lower()
    success_results = list(results.filter(result=RESULT_STATUS_SUCCESS))

    terminal_data = None
    if plugin_lower in {
        "linux.bash.bash",
        "mac.bash.bash",
        "windows.consoles.consoles",
        "windows.cmdscan.cmdscan",
        "windows.cmdline.cmdline",
        "linux.psaux.psaux",
        "mac.psaux.psaux",
    }:
        terminal_data = []
        for r in success_results:
            for v in _iter_result_values(r):
                if len(terminal_data) >= 200:
                    break
                cmd = (
                    v.get("Command")
                    or v.get("Args")
                    or v.get("CommandHistory")
                    or v.get("ScreenBuffer")
                    or (
                        f"[{v.get('Property')}] {v.get('Data')}"
                        if v.get("Property") and v.get("Data") and not str(v.get("Data")).strip().isdigit()
                        else None
                    )
                )
                if cmd:
                    terminal_data.append(
                        {
                            "pid": v.get("PID"),
                            "process": v.get("Process") or v.get("COMM"),
                            "command": cmd,
                            "time": v.get("CommandTime"),
                            "dump": r.dump.name,
                            "dump_index": r.dump.index,
                            "color": colors.get(r.dump.index),
                        }
                    )

    integrity_summary = None
    if plugin_lower.endswith(".check_syscall.check_syscall") or plugin_lower in {
        "windows.ssdt.ssdt",
        "windows.callbacks.callbacks",
        "windows.driverirp.driverirp",
    }:
        is_callbacks = plugin_lower == "windows.callbacks.callbacks"
        total = 0
        hooked = []
        for r in success_results:
            for v in _iter_result_values(r):
                total += 1
                symbol = str(v.get("Handler Symbol") or v.get("Symbol") or "").strip().upper()
                module = str(v.get("Module") or "").strip().upper()
                if is_callbacks:
                    is_hooked = "UNKNOWN" in symbol or "HOOK" in symbol or not module or "UNKNOWN" in module
                else:
                    is_hooked = not symbol or "UNKNOWN" in symbol or "HOOK" in symbol or "UNKNOWN" in module
                if is_hooked:
                    hooked.append(v)
        integrity_summary = {
            "total": total,
            "hooked_count": len(hooked),
            "clean": len(hooked) == 0,
            "hooked": hooked[:10],
        }

    network_summary = None
    if plugin_lower in {
        "linux.sockstat.sockstat",
        "linux.sockscan.sockscan",
        "windows.netscan.netscan",
        "windows.netstat.netstat",
        "mac.netstat.netstat",
    }:
        total = 0
        listening = 0
        established = 0
        external_ips = set()
        for r in success_results:
            for v in _iter_result_values(r):
                total += 1
                state = str(v.get("State") or "").upper()
                if state == "LISTEN":
                    listening += 1
                elif state in {"ESTABLISHED", "CONNECTED"}:
                    established += 1
                remote = v.get("ForeignAddr") or v.get("Destination Addr") or v.get("Remote IP")
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
                        "*",
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
    if plugin_lower in {
        "linux.capabilities.capabilities",
        "windows.privileges.privs",
    }:
        high_risk_count = 0
        total_procs = 0
        for r in success_results:
            for v in _iter_result_values(r):
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
    malfind_total = 0
    malfind_limit = 50
    if plugin_lower.endswith(".malfind.malfind"):
        malfind_data = []
        for r in success_results:
            qs = Value.objects.filter(result=r)
            malfind_total += qs.count()
            remaining = max(0, malfind_limit - len(malfind_data))
            if remaining <= 0:
                continue
            for v in qs.values_list("value", flat=True)[:remaining]:
                if not isinstance(v, dict):
                    continue
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

    service_summary = None
    if plugin_lower == "windows.svcscan.svcscan":
        svc_total = 0
        svc_running = 0
        svc_stopped = 0
        svc_drivers = 0
        svc_suspicious = 0
        for r in success_results:
            for v in _iter_result_values(r):
                svc_total += 1
                st = str(v.get("State") or "").upper()
                tp = str(v.get("Type") or "").upper()
                bin_path = str(v.get("Binary") or "").lower().strip()
                if "RUNNING" in st:
                    svc_running += 1
                elif "STOPPED" in st:
                    svc_stopped += 1
                if "DRIVER" in tp:
                    svc_drivers += 1
                if bin_path and bin_path not in {"-", "none", "n/a"}:
                    if any(
                        k in bin_path
                        for k in ("appdata", "\\temp\\", "programdata", "\\users\\", "\\public\\", "perflogs")
                    ):
                        svc_suspicious += 1
        service_summary = {
            "total": svc_total,
            "running": svc_running,
            "stopped": svc_stopped,
            "drivers": svc_drivers,
            "suspicious": svc_suspicious,
        }

    ldrmodules_summary = None
    if plugin_lower == "windows.ldrmodules.ldrmodules":
        ldr_total = 0
        ldr_unlinked = 0
        ldr_unusual_path = 0
        for r in success_results:
            for v in _iter_result_values(r):
                ldr_total += 1
                in_load = bool(v.get("InLoad"))
                in_init = bool(v.get("InInit"))
                in_mem = bool(v.get("InMem"))
                mpath = str(v.get("MappedPath") or "").lower().strip()
                is_exe = mpath.endswith(".exe")
                if (not in_load) or (not in_mem) or (not in_init and not is_exe):
                    ldr_unlinked += 1
                if mpath and not any(
                    k in mpath for k in ("\\windows\\", "\\program files", "\\programdata\\microsoft")
                ):
                    ldr_unusual_path += 1
        ldrmodules_summary = {
            "total": ldr_total,
            "unlinked": ldr_unlinked,
            "unusual_path": ldr_unusual_path,
        }

    memmap_summary = None
    if plugin_lower in {"windows.vadinfo.vadinfo", "linux.proc.maps", "mac.proc_maps.maps"}:
        mm_total = 0
        mm_rwx = 0
        mm_anon_exec = 0
        for r in success_results:
            for v in _iter_result_values(r):
                mm_total += 1
                prot = str(v.get("Protection") or v.get("Flags") or "")
                fpath = str(v.get("File Path") or v.get("File") or v.get("MappedPath") or "").strip()
                is_rwx = "PAGE_EXECUTE_READWRITE" in prot.upper() or "rwx" in prot.lower()
                is_exec = "EXECUTE" in prot.upper() or "x" in prot.lower()
                if is_rwx:
                    mm_rwx += 1
                if is_exec and (
                    not fpath
                    or fpath in {"Anonymous Mapping", "[heap]", "[stack]", "-"}
                    or any(k in fpath.lower() for k in ("/memfd:", "(deleted)", "/dev/shm", "/tmp/"))
                ):
                    mm_anon_exec += 1
        memmap_summary = {
            "total": mm_total,
            "rwx": mm_rwx,
            "anon_exec": mm_anon_exec,
        }

    session_summary = None
    if plugin_lower == "windows.sessions.sessions":
        sess_total = 0
        sess_ids: set[str] = set()
        user_counts: dict[str, int] = {}
        for r in success_results:
            for v in _iter_result_values(r):
                sess_total += 1
                sid = str(v.get("Session ID") or "").strip()
                if sid and sid != "None":
                    sess_ids.add(sid)
                uname = str(v.get("User Name") or "").strip()
                if uname and uname not in {"-", "None", ""}:
                    user_counts[uname] = user_counts.get(uname, 0) + 1
        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:12]
        session_summary = {
            "total": sess_total,
            "unique_sessions": len(sess_ids),
            "users": sorted_users,
        }

    yara_summary = None
    if "yarascan" in plugin_lower:
        from orochi.ya.forensics import lookup_rule_metadata_by_name

        yara_total = 0
        rule_counts: dict[str, int] = {}
        pids_hit: set[str] = set()
        for r in success_results:
            for v in _iter_result_values(r):
                yara_total += 1
                r_name = str(v.get("Rule") or v.get("Rule Name") or "").strip()
                if r_name:
                    rule_counts[r_name] = rule_counts.get(r_name, 0) + 1
                pid_val = v.get("PID") or v.get("Pid")
                if pid_val is not None and str(pid_val).strip():
                    pids_hit.add(str(pid_val).strip())

        enriched_rules = []
        mitre_techniques: set[str] = set()
        for r_name, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
            meta_info = lookup_rule_metadata_by_name(r_name) or {}
            mitre_list = meta_info.get("mitre_techniques", [])
            mitre_techniques.update(mitre_list)
            enriched_rules.append(
                {
                    "name": r_name,
                    "count": count,
                    "rule_id": meta_info.get("rule_id"),
                    "ruleset": meta_info.get("ruleset"),
                    "description": meta_info.get("description"),
                    "author": meta_info.get("author"),
                    "severity": meta_info.get("severity"),
                    "mitre_techniques": mitre_list,
                }
            )
        yara_summary = {
            "total_hits": yara_total,
            "unique_rules": len(rule_counts),
            "unique_pids": len(pids_hit),
            "mitre_techniques": sorted(mitre_techniques),
            "rules": enriched_rules,
        }

    return {
        "terminal_data": terminal_data,
        "integrity_summary": integrity_summary,
        "network_summary": network_summary,
        "privilege_summary": privilege_summary,
        "malfind_data": malfind_data,
        "malfind_total": malfind_total,
        "malfind_limit": malfind_limit,
        "service_summary": service_summary,
        "ldrmodules_summary": ldrmodules_summary,
        "memmap_summary": memmap_summary,
        "session_summary": session_summary,
        "yara_summary": yara_summary,
    }
