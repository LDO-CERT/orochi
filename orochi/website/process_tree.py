import logging
import re
from collections import defaultdict
from typing import Any

from orochi.website.detection.engine import get_plugin_rows, get_risk_level
from orochi.website.models import Dump

logger = logging.getLogger(__name__)


def _extract_pid(value: Any) -> int | None:
    """Helper to cleanly parse PID into an integer."""
    if value is None:
        return None
    try:
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("0x") or value.startswith("0X"):
                return int(value, 16)
        return int(value)
    except (ValueError, TypeError):
        return None


def _format_offset(offset_val: Any) -> str:
    """Helper to format memory offsets as clean hex strings."""
    if offset_val is None or offset_val == "":
        return ""
    try:
        if isinstance(offset_val, int):
            return hex(offset_val)
        offset_str = str(offset_val).strip()
        if offset_str.startswith("0x") or offset_str.startswith("0X"):
            return offset_str
        return hex(int(offset_str))
    except (ValueError, TypeError):
        return str(offset_val)


def build_process_tree(dump: Dump) -> dict[str, Any]:
    """
    Constructs a complete, enriched hierarchical process tree for a given memory dump.
    Aggregates:
      - Process hierarchy from pstree or pslist Volatility plugins
      - Command line arguments from cmdline or consoles
      - Forensic triage findings and risk scores
      - Extracted secrets (tokens, credentials, API keys)
      - Lineage tracing with flagged descendant indicators
    """
    # 1. Fetch process rows (prefer pstree, fallback to pslist, then psscan)
    process_rows = get_plugin_rows(
        dump,
        [
            "windows.pstree.PsTree",
            "linux.pstree.PsTree",
            "mac.pstree.PsTree",
            "pstree.PsTree",
            "pstree.pstree",
        ],
    )
    source_plugin = "pstree"

    if not process_rows:
        process_rows = get_plugin_rows(
            dump,
            [
                "windows.pslist.PsList",
                "linux.pslist.PsList",
                "mac.pslist.PsList",
                "pslist.PsList",
                "pslist.pslist",
            ],
        )
        source_plugin = "pslist"

    if not process_rows:
        process_rows = get_plugin_rows(
            dump,
            [
                "windows.psscan.PsScan",
                "linux.psscan.PsScan",
                "mac.psscan.PsScan",
                "psscan.PsScan",
                "psscan.psscan",
            ],
        )
        source_plugin = "psscan"

    # 2. Extract command lines by PID
    cmdline_rows = get_plugin_rows(
        dump,
        [
            "windows.cmdline.CmdLine",
            "linux.cmdline.CmdLine",
            "mac.cmdline.CmdLine",
            "cmdline.CmdLine",
            "consoles.Consoles",
        ],
    )
    cmdlines_by_pid: dict[int, str] = {}
    for r in cmdline_rows:
        pid = _extract_pid(r.get("PID"))
        if pid is not None:
            args = r.get("Args") or r.get("CommandLine") or r.get("Command") or r.get("arguments") or ""
            if args:
                cmdlines_by_pid[pid] = str(args)

    # 3. Fetch Triage Findings by PID
    findings_by_pid: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for finding in dump.triage_findings.all():
        matched_pids: set[int] = set()

        # Check raw_data dict
        if finding.raw_data and isinstance(finding.raw_data, dict):
            raw_pid = _extract_pid(finding.raw_data.get("PID"))
            if raw_pid is not None:
                matched_pids.add(raw_pid)

        # Check entity string e.g. "PID: 1234 (malicious.exe)" or "PID 1234"
        if finding.entity:
            for match in re.finditer(r"\bPID[:\s]+(\d+)\b", finding.entity, re.IGNORECASE):
                try:
                    matched_pids.add(int(match.group(1)))
                except ValueError:
                    pass

        finding_dict = {
            "id": finding.id,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "category": finding.category,
            "severity": finding.severity,
            "score": finding.score,
            "mitre_technique": finding.mitre_technique or "",
            "description": finding.description,
            "evidence_snippet": finding.evidence_snippet or "",
        }
        for p in matched_pids:
            findings_by_pid[p].append(finding_dict)

    # 4. Fetch Secrets by PID
    secrets_by_pid: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for secret in dump.secrets.all():
        if secret.pid is not None:
            secrets_by_pid[secret.pid].append(
                {
                    "id": secret.id,
                    "rule_name": secret.rule_name,
                    "category": secret.category,
                    "masked_data": secret.masked_data,
                    "offset": secret.offset or "",
                }
            )

    # 5. Build raw node objects
    nodes_by_pid: dict[int, dict[str, Any]] = {}
    children_by_ppid: dict[int, list[int]] = defaultdict(list)

    for row in process_rows:
        pid = _extract_pid(row.get("PID"))
        if pid is None:
            continue

        # Skip duplicates if plugin returned duplicate rows (e.g. psscan carved multiple)
        if pid in nodes_by_pid:
            continue

        ppid = _extract_pid(row.get("PPID"))
        if ppid is None or ppid == pid:
            ppid = 0

        name = row.get("ImageFileName") or row.get("COMM") or row.get("Process") or row.get("Name") or f"Process-{pid}"
        offset = _format_offset(row.get("Offset(V)") or row.get("Offset") or row.get("offset"))
        threads = row.get("Threads")
        handles = row.get("Handles")
        session_id = row.get("SessionId") or row.get("Session")
        wow64 = row.get("Wow64")
        create_time = str(row.get("CreateTime") or row.get("Created") or "")
        exit_time = str(row.get("ExitTime") or row.get("Exited") or "")

        cmdline = cmdlines_by_pid.get(pid) or str(row.get("Args") or "")

        p_findings = findings_by_pid.get(pid, [])
        p_secrets = secrets_by_pid.get(pid, [])

        risk_score = max([f["score"] for f in p_findings], default=0)
        risk_level = get_risk_level(risk_score)

        # ClamAV / VirusTotal detections in row
        clamav = row.get("clamav")
        vt = row.get("virustotal")

        is_flagged = bool(
            risk_score > 0 or p_findings or p_secrets or clamav or (isinstance(vt, dict) and vt.get("positives", 0) > 0)
        )

        node_data = {
            "id": str(pid),
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "cmdline": cmdline,
            "offset": offset,
            "threads": threads,
            "handles": handles,
            "session_id": session_id,
            "wow64": wow64,
            "create_time": create_time,
            "exit_time": exit_time,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "is_flagged": is_flagged,
            "findings": p_findings,
            "findings_count": len(p_findings),
            "secrets": p_secrets,
            "secrets_count": len(p_secrets),
            "clamav": clamav,
            "has_flagged_descendant": False,
            "children_count": 0,
        }
        nodes_by_pid[pid] = node_data
        children_by_ppid[ppid].append(pid)

    # 6. Record children counts
    for ppid, kids in children_by_ppid.items():
        if ppid in nodes_by_pid:
            nodes_by_pid[ppid]["children_count"] = len(kids)

    # 7. Identify roots & compute lineage flags (has_flagged_descendant)
    # A root is any process whose parent PID is 0 or whose parent is not present in nodes_by_pid
    roots: list[str] = []
    for pid, node in nodes_by_pid.items():
        ppid = node["ppid"]
        if ppid == 0 or ppid not in nodes_by_pid:
            roots.append(str(pid))

    # Propagate has_flagged_descendant up the tree
    for node in nodes_by_pid.values():
        if node["is_flagged"]:
            curr_ppid = node["ppid"]
            visited = set()
            while curr_ppid in nodes_by_pid and curr_ppid not in visited:
                nodes_by_pid[curr_ppid]["has_flagged_descendant"] = True
                visited.add(curr_ppid)
                curr_ppid = nodes_by_pid[curr_ppid]["ppid"]

    # 8. Construct edges list
    edges = []
    for pid, node in nodes_by_pid.items():
        ppid = node["ppid"]
        if ppid in nodes_by_pid and ppid != pid:
            edges.append(
                {
                    "source": str(ppid),
                    "target": str(pid),
                    "is_compromised_path": node["is_flagged"] or node["has_flagged_descendant"],
                }
            )

    nodes_list = list(nodes_by_pid.values())

    # Sort nodes so roots come first, then by PID
    nodes_list.sort(key=lambda n: (0 if n["id"] in roots else 1, n["pid"]))

    return {
        "dump": {
            "index": str(dump.index),
            "name": dump.name,
            "os": dump.operating_system,
            "risk_score": dump.risk_score,
            "source_plugin": source_plugin,
            "total_processes": len(nodes_list),
            "flagged_processes": sum(1 for n in nodes_list if n["is_flagged"]),
            "critical_processes": sum(1 for n in nodes_list if n["risk_level"] == "Critical"),
            "high_processes": sum(1 for n in nodes_list if n["risk_level"] == "High"),
            "medium_processes": sum(1 for n in nodes_list if n["risk_level"] == "Medium"),
            "low_processes": sum(1 for n in nodes_list if n["risk_level"] == "Low"),
            "clean_processes": sum(1 for n in nodes_list if n["risk_level"] == "Clean"),
        },
        "nodes": nodes_list,
        "edges": edges,
        "roots": roots,
    }
