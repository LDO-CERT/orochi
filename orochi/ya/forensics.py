"""
YARA Forensic Toolkit:
1. Extract YARA rule `meta:` fields & MITRE ATT&CK technique IDs (Txxxx[.xxx]) from Rule DB or source text.
2. Live YARA-X scanning / hunting against:
   - extracted dump files (`/media/<dump_index>/**`),
   - indexed DB forensic text artifacts (cmdlines, bash/console, envars, malfind strings),
   - raw text or uploaded sample bytes.
3. Auto-generate valid YARA rules from `malfind` hexdump / artifact bytes.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yara_x
from django.conf import settings
from django.db.models import Q
from extra_settings.models import Setting

from orochi.website.models import CustomRule, Dump, Value
from orochi.ya.models import Rule

logger = logging.getLogger(__name__)

MITRE_TECHNIQUE_RE = re.compile(r"\b(T1\d{3}(?:\.\d{3})?)\b", re.IGNORECASE)
RULE_HEADER_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
META_KV_RE = re.compile(
    r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(\d+)|(true|false))\s*$',
    re.MULTILINE,
)

# Skip internal sidecar/metadata JSON files when scanning dumped artifacts
IGNORED_SUFFIXES = (".vt.json", ".regipy.json", ".yara.json", ".clamav.json")


def parse_yara_rule_metadata(source: str) -> dict[str, Any]:
    """Extract meta key-values, rule names, and MITRE ATT&CK technique IDs from YARA source text."""
    if not source:
        return {"rule_names": [], "meta": {}, "mitre_techniques": []}

    rule_names = RULE_HEADER_RE.findall(source)
    meta: dict[str, Any] = {}
    for match in META_KV_RE.finditer(source):
        key = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else (match.group(3) or match.group(4))
        if key not in meta:
            meta[key] = val

    mitre_hits = sorted({t.upper() for t in MITRE_TECHNIQUE_RE.findall(source)})
    return {
        "rule_names": rule_names,
        "meta": meta,
        "mitre_techniques": mitre_hits,
    }


def lookup_rule_metadata_by_name(rule_name: str) -> dict[str, Any] | None:
    """Look up a YARA rule in the DB by rule identifier and return its parsed metadata + DB id."""
    if not rule_name:
        return None
    clean_name = rule_name.strip()
    candidate = (
        Rule.objects.select_related("ruleset")
        .filter(Q(rule__icontains=f"rule {clean_name}") | Q(path__icontains=clean_name))
        .first()
    )
    if not candidate:
        return None
    source = candidate.rule or ""
    if not source and candidate.path and Path(candidate.path).exists():
        source = Path(candidate.path).read_text(errors="ignore")
    parsed = parse_yara_rule_metadata(source)
    return {
        "rule_id": candidate.pk,
        "ruleset": candidate.ruleset.name if candidate.ruleset else None,
        "path": Path(candidate.path).name if candidate.path else clean_name,
        "meta": parsed["meta"],
        "mitre_techniques": parsed["mitre_techniques"],
        "description": parsed["meta"].get("description") or parsed["meta"].get("desc"),
        "author": parsed["meta"].get("author"),
        "severity": parsed["meta"].get("severity") or parsed["meta"].get("score"),
        "reference": parsed["meta"].get("reference") or parsed["meta"].get("ref"),
    }


def _compile_scanner(
    *,
    rule_source: str | None = None,
    custom_rule_id: int | None = None,
    rule_ids: list[int] | None = None,
    user=None,
) -> yara_x.Rules:
    """Build or load a `yara_x.Rules` object from raw source, CustomRule, Rule IDs, or default.yara."""
    if rule_source and rule_source.strip():
        return yara_x.compile(rule_source)

    if custom_rule_id:
        cr_qs = CustomRule.objects.filter(pk=custom_rule_id)
        if user is not None:
            cr_qs = cr_qs.filter(Q(user=user) | Q(public=True))
        cr = cr_qs.first()
        if not cr or not Path(cr.path).exists():
            raise ValueError("Selected compiled CustomRule not found or inaccessible.")
        with open(cr.path, "rb") as fp:
            return yara_x.Rules.deserialize_from(fp)

    if rule_ids:
        from orochi.ya.rules_sync import compile_yara_rules_queryset

        qs = Rule.objects.filter(pk__in=rule_ids)
        if user is not None:
            qs = qs.filter(Q(ruleset__user__isnull=True) | Q(ruleset__user=user))
        if not qs.exists():
            raise ValueError("No accessible YARA rules found for the provided rule_ids.")
        built, _, _ = compile_yara_rules_queryset(qs, ignore_errors=False)
        return built

    # Fallback: user's default CustomRule or system DEFAULT_YARA_RULE_PATH
    if user is not None:
        user_default = CustomRule.objects.filter(user=user, default=True).first()
        if user_default and Path(user_default.path).exists():
            with open(user_default.path, "rb") as fp:
                return yara_x.Rules.deserialize_from(fp)

    default_path = Setting.get("DEFAULT_YARA_RULE_PATH") or "/yara/default.yara"
    if Path(default_path).exists():
        with open(default_path, "rb") as fp:
            return yara_x.Rules.deserialize_from(fp)

    raise ValueError("Provide YARA rule source, rule_ids, custom_rule_id, or compile a default YARA ruleset first.")


def _serialize_yara_matches(scan_results) -> list[dict[str, Any]]:
    """Convert yara_x.ScanResults into JSON-serializable match dictionaries."""
    matches_out: list[dict[str, Any]] = []
    for matching_rule in scan_results.matching_rules:
        strings_out = []
        for pattern in matching_rule.patterns:
            for m in list(pattern.matches)[:10]:
                strings_out.append(
                    {
                        "identifier": pattern.identifier,
                        "offset": hex(m.offset),
                        "length": m.length,
                    }
                )
        meta_dict = {}
        try:
            for k, v in matching_rule.metadata:
                meta_dict[str(k)] = v
        except Exception:
            pass
        mitre_ids = sorted({t.upper() for val in meta_dict.values() for t in MITRE_TECHNIQUE_RE.findall(str(val))})
        matches_out.append(
            {
                "rule": matching_rule.identifier,
                "namespace": matching_rule.namespace,
                "tags": list(matching_rule.tags) if hasattr(matching_rule, "tags") else [],
                "metadata": meta_dict,
                "mitre_techniques": mitre_ids,
                "strings": strings_out[:20],
            }
        )
    return matches_out


def scan_bytes_with_yara(
    data: bytes,
    *,
    rule_source: str | None = None,
    custom_rule_id: int | None = None,
    rule_ids: list[int] | None = None,
    user=None,
) -> list[dict[str, Any]]:
    """Scan an in-memory bytes buffer with yara-x."""
    compiled = _compile_scanner(
        rule_source=rule_source,
        custom_rule_id=custom_rule_id,
        rule_ids=rule_ids,
        user=user,
    )
    scanner = yara_x.Scanner(compiled)
    scanner.set_timeout(15)
    results = scanner.scan(data)
    return _serialize_yara_matches(results)


def scan_dump_extracted_files(
    dump: Dump,
    *,
    rule_source: str | None = None,
    custom_rule_id: int | None = None,
    rule_ids: list[int] | None = None,
    user=None,
    max_file_bytes: int = 50 * 1024 * 1024,
    save_sidecars: bool = False,
) -> dict[str, Any]:
    """
    Scan all files extracted by plugins for a given Dump under `<MEDIA_ROOT>/<dump.index>/`.
    Excludes the raw memory image itself and sidecar metadata JSONs.
    """
    import json

    compiled = _compile_scanner(
        rule_source=rule_source,
        custom_rule_id=custom_rule_id,
        rule_ids=rule_ids,
        user=user,
    )
    scanner = yara_x.Scanner(compiled)
    scanner.set_timeout(15)

    dump_dir = Path(settings.MEDIA_ROOT) / str(dump.index)
    raw_dump_path = None
    try:
        if dump.upload and dump.upload.name:
            raw_dump_path = Path(dump.upload.path).resolve()
    except Exception:
        raw_dump_path = None

    scanned_files = 0
    hits: list[dict[str, Any]] = []

    if dump_dir.exists() and dump_dir.is_dir():
        for file_path in sorted(dump_dir.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.name.endswith(IGNORED_SUFFIXES):
                continue
            try:
                resolved = file_path.resolve()
                if raw_dump_path and resolved == raw_dump_path:
                    continue
                size = file_path.stat().st_size
                if size == 0 or size > max_file_bytes:
                    continue
                scanned_files += 1
                scan_res = scanner.scan(file_path.read_bytes())
                matched = _serialize_yara_matches(scan_res)
                if matched:
                    rel_path = str(file_path.relative_to(dump_dir))
                    if save_sidecars:
                        sidecar = Path(f"{file_path}.yara.json")
                        sidecar.write_text(json.dumps(matched, indent=2), encoding="utf-8")
                    hits.append(
                        {
                            "dump_index": str(dump.index),
                            "dump_name": dump.name,
                            "file": file_path.name,
                            "relative_path": rel_path,
                            "size": size,
                            "matches": matched,
                        }
                    )
            except Exception as exc:
                logger.debug("Error scanning extracted file %s: %s", file_path, exc)

    return {
        "dump_index": str(dump.index),
        "dump_name": dump.name,
        "scanned_files": scanned_files,
        "matched_files": len(hits),
        "hits": hits,
    }


def hunt_db_artifacts_with_yara(
    dumps,
    *,
    rule_source: str | None = None,
    custom_rule_id: int | None = None,
    rule_ids: list[int] | None = None,
    user=None,
    limit_per_dump: int = 5000,
) -> dict[str, Any]:
    """
    Fast retro-hunt: scan indexed forensic text rows (cmdline, bash, consoles, envars, malfind, svcscan)
    in PostgreSQL `Value` rows using yara-x without touching raw multi-GB memory images.
    """
    import json

    compiled = _compile_scanner(
        rule_source=rule_source,
        custom_rule_id=custom_rule_id,
        rule_ids=rule_ids,
        user=user,
    )
    scanner = yara_x.Scanner(compiled)
    scanner.set_timeout(15)

    scanned_rows = 0
    hits: list[dict[str, Any]] = []

    for dump in dumps:
        qs = (
            Value.objects.filter(result__dump=dump)
            .select_related("result__plugin")
            .only("id", "value", "result__plugin__name")[:limit_per_dump]
        )
        for val_obj in qs.iterator(chunk_size=1000):
            scanned_rows += 1
            raw_text = json.dumps(val_obj.value, ensure_ascii=False).encode("utf-8", errors="ignore")
            scan_res = scanner.scan(raw_text)
            matched = _serialize_yara_matches(scan_res)
            if matched:
                hits.append(
                    {
                        "dump_index": str(dump.index),
                        "dump_name": dump.name,
                        "plugin": val_obj.result.plugin.name,
                        "value_id": val_obj.pk,
                        "preview": raw_text.decode("utf-8", errors="ignore")[:240],
                        "matches": matched,
                    }
                )
                if len(hits) >= 200:
                    break

    return {
        "scanned_rows": scanned_rows,
        "matched_rows": len(hits),
        "hits": hits,
    }


def generate_yara_rule_from_artifact(
    *,
    rule_name: str = "Orochi_Generated_Rule",
    hex_dump: str | None = None,
    strings: list[str] | None = None,
    author: str = "Orochi Analyst",
    description: str = "Auto-generated YARA rule from memory forensic artifact",
    dump_name: str | None = None,
    process_name: str | None = None,
    pid: int | str | None = None,
    mitre_technique: str | None = None,
) -> str:
    """
    Generate a syntactically valid YARA rule from a `malfind` Hexdump and/or extracted strings.
    Validates the generated rule with `yara_x.compile()` before returning.
    """
    safe_rule_name = re.sub(r"[^A-Za-z0-9_]", "_", rule_name or "Orochi_Generated_Rule")
    if not safe_rule_name or safe_rule_name[0].isdigit():
        safe_rule_name = f"Rule_{safe_rule_name}"

    hex_bytes: list[str] = []
    if hex_dump:
        # Extract 2-hex-digit tokens from Volatility hexdump lines (e.g. "4d 5a 90 00 ...")
        # Strip ASCII column if present after double spaces or pipes
        for line in hex_dump.splitlines():
            # Strip leading offset like "0x00000000:" if present
            cleaned = re.sub(r"^\s*(?:0x)?[0-9a-fA-F]{4,16}\s*[:|]\s*", "", line)
            tokens = re.findall(r"\b([0-9a-fA-F]{2})\b", cleaned)
            hex_bytes.extend(t.upper() for t in tokens)
            if len(hex_bytes) >= 48:
                break
        hex_bytes = hex_bytes[:48]

    clean_strings: list[str] = []
    for s in strings or []:
        s_clean = str(s).strip()
        if len(s_clean) >= 4:
            escaped = s_clean.replace("\\", "\\\\").replace('"', '\\"')
            clean_strings.append(escaped)

    meta_lines = [
        f'        author = "{author.replace(chr(34), chr(39))}"',
        f'        description = "{description.replace(chr(34), chr(39))}"',
    ]
    if dump_name:
        meta_lines.append(f'        source_dump = "{str(dump_name).replace(chr(34), chr(39))}"')
    if process_name:
        meta_lines.append(f'        process = "{str(process_name).replace(chr(34), chr(39))}"')
    if pid is not None and str(pid) != "":
        meta_lines.append(f'        pid = "{pid}"')
    if mitre_technique:
        meta_lines.append(f'        mitre_att = "{mitre_technique}"')

    string_lines = []
    if hex_bytes:
        hex_pattern = " ".join(hex_bytes)
        string_lines.append(f"        $hex_payload = {{ {hex_pattern} }}")
    for idx, s_val in enumerate(clean_strings[:10], start=1):
        string_lines.append(f'        $s{idx} = "{s_val}" ascii wide nocase')

    if not string_lines:
        string_lines.append('        $placeholder = "REPLACE_WITH_INDICATOR" ascii wide')

    condition = "any of them" if len(string_lines) > 1 else "all of them"
    rule_text = (
        f"rule {safe_rule_name} {{\n"
        f"    meta:\n" + "\n".join(meta_lines) + "\n"
        "    strings:\n" + "\n".join(string_lines) + "\n"
        f"    condition:\n"
        f"        {condition}\n"
        f"}}\n"
    )
    # Guarantee syntax validity with yara-x
    yara_x.compile(rule_text)
    return rule_text
