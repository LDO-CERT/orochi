"""Canonical forensic entity normalizer and multi-tier matcher for Orochi CTF Discovery mode."""

from __future__ import annotations

import fnmatch
import json
import re
from typing import Any


def _ci_get(row: dict[str, Any], *keys: str) -> Any:
    """Case-insensitive / whitespace-tolerant dictionary lookup."""
    if not isinstance(row, dict):
        return None
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for key in keys:
        val = lowered.get(key.strip().lower())
        if val is not None and val != "":
            return val
    return None


def _to_int(val: Any) -> int | None:
    if val is None or val == "":
        return None
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val
    text = str(val).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (ValueError, TypeError):
        return None


def _to_hex(val: Any) -> str | None:
    if val is None or val == "":
        return None
    if isinstance(val, int):
        return hex(val).lower()
    text = str(val).strip().lower()
    if text.startswith("0x"):
        try:
            return hex(int(text, 16)).lower()
        except ValueError:
            return text
    try:
        return hex(int(text)).lower()
    except ValueError:
        return text


def _clean_str(val: Any) -> str | None:
    if val is None:
        return None
    text = str(val).strip()
    return text if text else None


def extract_canonical_entity(
    plugin_name: str,
    row: dict[str, Any] | None,
    extracted_file: str = "",
) -> dict[str, Any]:
    """Normalize a Volatility 3 plugin row into a canonical forensic entity dictionary."""
    row = row if isinstance(row, dict) else {}
    plugin = (plugin_name or "").lower()

    pid = _to_int(_ci_get(row, "PID", "Process ID", "ProcessId", "OwningPID", "pid"))
    ppid = _to_int(_ci_get(row, "PPID", "ParentPID", "ppid"))
    proc_name = _clean_str(
        _ci_get(row, "ImageFileName", "Process", "ProcessName", "COMM", "Name", "Owner", "process_name")
    )

    # 1. Memory Injection family
    if any(k in plugin for k in ("malfind", "hollowprocesses", "processghosting", "ldrmodules")):
        base_addr = _to_hex(
            _ci_get(row, "Start VPN", "StartVPN", "Start", "Base", "BaseAddress", "Offset", "base_address")
        )
        protection = _clean_str(_ci_get(row, "Protection", "Perms", "protection"))
        entity: dict[str, Any] = {"entity_type": "injection"}
        if pid is not None:
            entity["pid"] = pid
        if proc_name:
            entity["name"] = proc_name.lower()
        if base_addr:
            entity["base_address"] = base_addr
        if protection:
            entity["protection"] = protection.upper()
        return entity

    # 2. Network family
    if any(k in plugin for k in ("netscan", "netstat", "sockstat")):
        foreign_ip = _clean_str(
            _ci_get(row, "ForeignAddr", "ForeignAddress", "RemoteAddress", "RemoteAddr", "DstAddr", "foreign_ip")
        )
        foreign_port = _to_int(_ci_get(row, "ForeignPort", "RemotePort", "DstPort", "foreign_port"))
        local_ip = _clean_str(_ci_get(row, "LocalAddr", "LocalAddress", "SrcAddr", "local_ip"))
        local_port = _to_int(_ci_get(row, "LocalPort", "SrcPort", "local_port"))
        proto = _clean_str(_ci_get(row, "Proto", "Protocol", "proto"))
        entity = {"entity_type": "network"}
        if foreign_ip:
            entity["foreign_ip"] = foreign_ip.lower()
        if foreign_port is not None:
            entity["foreign_port"] = foreign_port
        if local_ip:
            entity["local_ip"] = local_ip.lower()
        if local_port is not None:
            entity["local_port"] = local_port
        if proto:
            entity["proto"] = proto.upper()
        if pid is not None:
            entity["pid"] = pid
        if proc_name:
            entity["name"] = proc_name.lower()
        return entity

    # 3. Registry / Persistence family
    if any(k in plugin for k in ("printkey", "userassist", "hivelist", "registry", "regipy")):
        key_path = _clean_str(_ci_get(row, "Key", "KeyPath", "Hive", "Path", "key_path"))
        value_name = _clean_str(_ci_get(row, "Name", "ValueName", "value_name"))
        value_data = _clean_str(_ci_get(row, "Data", "Value", "ValueData", "value_data"))
        entity = {"entity_type": "registry"}
        if key_path:
            entity["key_path"] = key_path.lower()
        if value_name:
            entity["value_name"] = value_name.lower()
        if value_data:
            entity["value_data"] = value_data.lower()
        return entity

    # 4. YARA family
    if "yara" in plugin:
        rule = _clean_str(_ci_get(row, "Rule", "RuleName", "rule"))
        offset = _to_hex(_ci_get(row, "Offset", "offset"))
        entity = {"entity_type": "yara"}
        if rule:
            entity["rule"] = rule.lower()
        if pid is not None:
            entity["pid"] = pid
        if offset:
            entity["offset"] = offset
        return entity

    # 5. Process family (pslist, pstree, psscan, cmdline, dlllist, handles, envars, privileges, bash)
    if any(
        k in plugin
        for k in (
            "pslist",
            "pstree",
            "psscan",
            "psaux",
            "cmdline",
            "dlllist",
            "handles",
            "envars",
            "privileges",
            "bash",
        )
    ):
        cmdline = _clean_str(_ci_get(row, "Args", "Command", "Cmdline", "CommandLine", "cmdline"))
        entity = {"entity_type": "process"}
        if pid is not None:
            entity["pid"] = pid
        if ppid is not None:
            entity["ppid"] = ppid
        if proc_name:
            entity["name"] = proc_name.lower()
        if cmdline:
            entity["cmdline"] = cmdline.lower()
        return entity

    # 6. File / Artifact family
    if any(k in plugin for k in ("filescan", "dumpfiles", "mftscan", "elfs")) or extracted_file:
        file_name = _clean_str(_ci_get(row, "Name", "FileName", "Filename", "name")) or _clean_str(extracted_file)
        file_path = _clean_str(_ci_get(row, "FilePath", "Path", "Name", "path")) or _clean_str(extracted_file)
        file_hash = _clean_str(_ci_get(row, "SHA256", "MD5", "Hash", "hash"))
        entity = {"entity_type": "file"}
        if file_name:
            entity["name"] = file_name.lower()
        if file_path:
            entity["path"] = file_path.lower()
        if file_hash:
            entity["hash"] = file_hash.lower()
        if pid is not None:
            entity["pid"] = pid
        return entity

    # 7. Generic fallback
    entity = {"entity_type": "generic"}
    if pid is not None:
        entity["pid"] = pid
    if proc_name:
        entity["name"] = proc_name.lower()
    return entity


def build_criteria_from_evidence(
    plugin_name: str,
    row: dict[str, Any] | None,
    extracted_file: str = "",
) -> tuple[str, dict[str, Any]]:
    """Distill an instructor Evidence row into (entity_type, criteria) for a Golden Case CTFObjective."""
    canonical = extract_canonical_entity(plugin_name, row, extracted_file=extracted_file)
    entity_type = canonical.get("entity_type", "generic")

    if entity_type == "process":
        criteria = {k: v for k, v in canonical.items() if k in ("pid", "name") and v is not None}
    elif entity_type == "network":
        criteria = {
            k: v for k, v in canonical.items() if k in ("foreign_ip", "foreign_port", "proto") and v is not None
        }
    elif entity_type == "injection":
        criteria = {k: v for k, v in canonical.items() if k in ("pid", "base_address") and v is not None}
    elif entity_type == "registry":
        criteria = {k: v for k, v in canonical.items() if k in ("key_path", "value_name") and v is not None}
    elif entity_type == "yara":
        criteria = {k: v for k, v in canonical.items() if k in ("rule", "pid") and v is not None}
    elif entity_type == "file":
        criteria = {k: v for k, v in canonical.items() if k in ("hash", "name", "path") and v is not None}
    else:
        criteria = {k: v for k, v in canonical.items() if k != "entity_type" and v is not None}

    if not criteria and isinstance(row, dict):
        # Fall back to first 3 non-empty scalar fields from raw row
        for k, v in row.items():
            if not str(k).startswith("__") and v not in (None, "", [], {}):
                criteria[str(k)] = v
                if len(criteria) >= 3:
                    break

    return entity_type, criteria


def _values_match(expected: Any, actual: Any) -> bool:
    """Compare expected criteria value against actual value with type/hex/wildcard normalization."""
    if actual is None:
        return False
    if isinstance(expected, bool):
        return bool(actual) is expected
    if isinstance(expected, int):
        actual_int = _to_int(actual)
        return actual_int is not None and actual_int == expected

    exp_str = str(expected).strip().lower()
    act_str = str(actual).strip().lower()

    # Hex address normalization
    if exp_str.startswith("0x"):
        exp_hex = _to_hex(exp_str)
        act_hex = _to_hex(act_str)
        if exp_hex and act_hex and exp_hex == act_hex:
            return True

    # Wildcard / glob matching (e.g. "*\\CurrentVersion\\Run" or "*mimikatz*")
    if "*" in exp_str or "?" in exp_str:
        return fnmatch.fnmatch(act_str, exp_str)

    # Numeric string equivalence (e.g. "4820" == 4820)
    exp_int = _to_int(exp_str)
    act_int = _to_int(act_str)
    if exp_int is not None and act_int is not None and exp_str.isdigit():
        return exp_int == act_int

    return exp_str == act_str


def matches_objective(
    objective_entity_type: str,
    criteria: dict[str, Any] | None,
    plugin_name: str,
    row: dict[str, Any] | None,
    extracted_file: str = "",
    canonical_entity: dict[str, Any] | None = None,
) -> bool:
    """Evaluate a submitted artifact against a CTFObjective using 3-tier matching.

    Tier 1: Cross-plugin canonical entity matching (e.g. PID in pstree matches pslist objective).
    Tier 2: Raw JSON row predicate matching (case-insensitive keys, wildcard values).
    Tier 3: Regex / pattern matching across serialized row and extracted file name.
    """
    if not criteria or not isinstance(criteria, dict):
        return False

    row = row if isinstance(row, dict) else {}
    canonical = canonical_entity or extract_canonical_entity(plugin_name, row, extracted_file=extracted_file)
    plugin_lower = (plugin_name or "").lower()

    # Optional plugin constraint
    if plugin_contains := criteria.get("plugin_contains"):
        if str(plugin_contains).lower() not in plugin_lower:
            return False

    # Tier 3: Regex / pattern match
    regex_pattern = criteria.get("regex") or criteria.get("pattern")
    if regex_pattern:
        haystack = json.dumps(row, default=str) + " " + (extracted_file or "")
        try:
            if not re.search(str(regex_pattern), haystack, re.IGNORECASE):
                return False
        except re.error:
            return False

    # Tier 1 & Tier 2: Canonical + raw row field matching
    field_criteria = {
        k: v
        for k, v in criteria.items()
        if k not in ("regex", "pattern", "plugin_contains") and v is not None and v != ""
    }

    if not field_criteria:
        return bool(regex_pattern)

    # Alias map so e.g. criteria {"process_name": "svchost.exe"} matches canonical {"name": "svchost.exe"}
    aliases = {
        "process_name": "name",
        "imagefilename": "name",
        "remote_ip": "foreign_ip",
        "remote_port": "foreign_port",
        "vad_base": "base_address",
        "start_vpn": "base_address",
        "rule_name": "rule",
        "file_name": "name",
        "file_path": "path",
        "sha256": "hash",
    }

    # Build a lookup combining canonical entity fields and raw row fields
    lowered_row = {str(k).strip().lower(): v for k, v in row.items()}
    if extracted_file:
        lowered_row.setdefault("extracted_file", extracted_file)

    for key, expected in field_criteria.items():
        norm_key = str(key).strip().lower()
        canonical_key = aliases.get(norm_key, norm_key)

        matched = False
        # Tier 1: check canonical entity first
        if canonical_key in canonical and _values_match(expected, canonical[canonical_key]):
            matched = True
        elif norm_key in canonical and _values_match(expected, canonical[norm_key]):
            matched = True
        # Tier 2: fallback to raw row field lookup
        elif norm_key in lowered_row and _values_match(expected, lowered_row[norm_key]):
            matched = True
        elif canonical_key in lowered_row and _values_match(expected, lowered_row[canonical_key]):
            matched = True

        if not matched:
            return False

    return True
