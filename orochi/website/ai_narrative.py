import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from orochi.website.defaults import SERVICE_OLLAMA
from orochi.website.models import Dump, DumpNarrative, Service, Value


def extract_dump_forensic_context(
    dump: Dump,
) -> Tuple[str, Set[int], Set[str], Dict[str, Dict[str, Any]]]:
    """
    Extract high-signal forensic artifacts across all executed plugins for a memory dump.
    Returns:
        - evidence_text: Compact structured text formatted for LLM consumption with unique citation keys.
        - valid_pids: Set of genuine PIDs extracted from evidence.
        - valid_offsets: Set of genuine memory offsets extracted from evidence.
        - citation_registry: Map of citation keys to metadata dictionaries.
    """
    valid_pids: Set[int] = set()
    valid_offsets: Set[str] = set()
    valid_ips: Set[str] = set()
    valid_hashes: Set[str] = set()
    citation_registry: Dict[str, Dict[str, Any]] = {}
    lines: List[str] = []

    if dump.sha256:
        valid_hashes.add(dump.sha256.lower())

    lines.append(f"# FORENSIC EVIDENCE DUMP: {dump.name} ({dump.operating_system})\n")

    # 1. Behavioral Triage Findings
    triage_findings = list(dump.triage_findings.all()[:25])
    if triage_findings:
        lines.append("## BEHAVIORAL TRIAGE FINDINGS")
        for tf in triage_findings:
            cite_key = f"TriageFinding:{tf.pk}"
            citation_registry[cite_key] = {
                "type": "triage",
                "id": tf.pk,
                "rule_name": tf.rule_name,
                "severity": tf.severity,
                "category": tf.category,
                "entity": tf.entity or "N/A",
                "score": tf.score,
                "description": tf.description,
                "evidence": tf.evidence_snippet or "",
                "label": f"[{tf.severity}] {tf.rule_name}",
            }
            if tf.raw_data and isinstance(tf.raw_data, dict):
                pid_val = (
                    tf.raw_data.get("PID")
                    or tf.raw_data.get("pid")
                    or tf.raw_data.get("Pid")
                )
                if pid_val is not None:
                    try:
                        valid_pids.add(int(pid_val))
                    except (ValueError, TypeError):
                        pass
                offset_val = tf.raw_data.get("Offset") or tf.raw_data.get("Start")
                if offset_val:
                    valid_offsets.add(str(offset_val).lower())
                    valid_offsets.add(str(offset_val).upper())

            lines.append(
                f"- [{cite_key}] Severity: {tf.severity} | Rule: {tf.rule_name} | "
                f"Entity: {tf.entity or 'N/A'} | MITRE: {tf.mitre_technique or 'N/A'} | "
                f"Summary: {tf.description}"
            )
        lines.append("")

    # 2. Exposed Memory Secrets & Hardcoded Credentials
    secrets = list(dump.secrets.all()[:20])
    if secrets:
        lines.append("## DETECTED MEMORY SECRETS & CREDENTIALS")
        for sec in secrets:
            cite_key = f"DumpSecret:{sec.pk}"
            if sec.pid:
                valid_pids.add(sec.pid)
            if sec.offset:
                valid_offsets.add(str(sec.offset).lower())
                valid_offsets.add(str(sec.offset).upper())

            citation_registry[cite_key] = {
                "type": "secret",
                "id": sec.pk,
                "rule_name": sec.rule_name,
                "category": sec.category,
                "process": sec.process_name or "N/A",
                "pid": sec.pid,
                "offset": sec.offset or "N/A",
                "masked_data": sec.masked_data,
                "label": f"Secret: {sec.rule_name} ({sec.get_category_display()})",
            }
            lines.append(
                f"- [{cite_key}] Category: {sec.get_category_display()} | Rule: {sec.rule_name} | "
                f"Process: {sec.process_name or 'N/A'} (PID: {sec.pid or 'N/A'}) | "
                f"Offset: {sec.offset or 'N/A'} | Snippet: {sec.masked_data}"
            )
        lines.append("")

    # 3. Process Execution Artifacts (PsList, PsScan, CmdLine, Bash)
    process_values = list(
        Value.objects.filter(
            result__dump=dump,
            result__plugin__name__in=[
                "windows.pslist.PsList",
                "linux.pslist.PsList",
                "mac.pslist.PsList",
                "windows.psscan.PsScan",
                "windows.cmdline.CmdLine",
                "linux.bash.Bash",
                "mac.bash.Bash",
            ],
        ).select_related("result__plugin")[:30]
    )
    if process_values:
        lines.append("## PROCESS EXECUTION ARTIFACTS")
        for val in process_values:
            cite_key = f"Value:{val.pk}"
            v = val.value or {}
            proc_name = (
                v.get("ImageFileName")
                or v.get("Name")
                or v.get("Process")
                or v.get("COMM")
                or "Unknown"
            )
            pid = v.get("PID") or v.get("Pid")
            ppid = v.get("PPID") or v.get("Ppid")
            args = (
                v.get("Args")
                or v.get("CommandLine")
                or v.get("Command")
                or v.get("CommandHistory")
            )
            offset = v.get("Offset") or v.get("Offset(V)") or v.get("Offset(P)")

            if pid is not None:
                try:
                    valid_pids.add(int(pid))
                except (ValueError, TypeError):
                    pass
            if ppid is not None:
                try:
                    valid_pids.add(int(ppid))
                except (ValueError, TypeError):
                    pass
            if offset:
                valid_offsets.add(str(offset).lower())
                valid_offsets.add(str(offset).upper())

            citation_registry[cite_key] = {
                "type": "value",
                "id": val.pk,
                "plugin": val.result.plugin.name,
                "process": proc_name,
                "pid": pid,
                "ppid": ppid,
                "args": args,
                "offset": offset,
                "label": f"{proc_name} (PID: {pid}) via {val.result.plugin.name.split('.')[-1]}",
            }

            detail = f"{proc_name} (PID: {pid}, PPID: {ppid})"
            if args:
                detail += f" Args: {str(args)[:80]}"
            lines.append(f"- [{cite_key}] {detail}")
        lines.append("")

    # 4. Network Connections (NetScan, NetStat, Sockstat)
    network_values = list(
        Value.objects.filter(
            result__dump=dump,
            result__plugin__name__in=[
                "windows.netscan.NetScan",
                "windows.netstat.NetStat",
                "linux.sockstat.Sockstat",
                "mac.netstat.Netstat",
            ],
        ).select_related("result__plugin")[:20]
    )
    if network_values:
        lines.append("## NETWORK COMMUNICATIONS")
        for val in network_values:
            cite_key = f"Value:{val.pk}"
            v = val.value or {}
            proto = v.get("Proto") or v.get("Protocol") or "TCP"
            local_addr = v.get("LocalAddr") or v.get("Source Addr") or ""
            local_port = v.get("LocalPort") or v.get("Source Port") or ""
            foreign_addr = v.get("ForeignAddr") or v.get("Destination Addr") or ""
            foreign_port = v.get("ForeignPort") or v.get("Destination Port") or ""
            state = v.get("State") or ""
            pid = v.get("PID") or v.get("Owner")
            proc_name = v.get("Owner") or v.get("Process") or ""

            if pid is not None:
                try:
                    valid_pids.add(int(pid))
                except (ValueError, TypeError):
                    pass

            if local_addr and str(local_addr).strip():
                clean_ip = str(local_addr).strip().split(":")[0]
                valid_ips.add(clean_ip)
            if foreign_addr and str(foreign_addr).strip():
                clean_ip = str(foreign_addr).strip().split(":")[0]
                valid_ips.add(clean_ip)

            citation_registry[cite_key] = {
                "type": "value",
                "id": val.pk,
                "plugin": val.result.plugin.name,
                "local": f"{local_addr}:{local_port}",
                "foreign": f"{foreign_addr}:{foreign_port}",
                "proto": proto,
                "state": state,
                "pid": pid,
                "label": f"{proto} {foreign_addr}:{foreign_port} ({state})",
            }
            lines.append(
                f"- [{cite_key}] {proto} {local_addr}:{local_port} -> {foreign_addr}:{foreign_port} "
                f"State: {state} (PID: {pid}, Owner: {proc_name})"
            )
        lines.append("")

    # 5. Injected Memory Regions & Malfind
    malfind_values = list(
        Value.objects.filter(
            result__dump=dump,
            result__plugin__name__in=[
                "windows.malfind.Malfind",
                "linux.malfind.Malfind",
                "mac.malfind.Malfind",
            ],
        ).select_related("result__plugin")[:15]
    )
    if malfind_values:
        lines.append("## SUSPICIOUS MEMORY INJECTIONS (MALFIND)")
        for val in malfind_values:
            cite_key = f"Value:{val.pk}"
            v = val.value or {}
            proc_name = v.get("Process") or "Unknown"
            pid = v.get("PID")
            start = v.get("Start") or v.get("Start VPN")
            protection = v.get("Protection") or v.get("Flags")
            hexdump = v.get("HexDump") or v.get("HexBytes") or ""
            has_pe = "4d 5a" in str(hexdump).lower() or "MZ" in str(hexdump)

            if pid is not None:
                try:
                    valid_pids.add(int(pid))
                except (ValueError, TypeError):
                    pass
            if start:
                valid_offsets.add(str(start).lower())
                valid_offsets.add(str(start).upper())

            citation_registry[cite_key] = {
                "type": "value",
                "id": val.pk,
                "plugin": val.result.plugin.name,
                "process": proc_name,
                "pid": pid,
                "start": start,
                "protection": protection,
                "has_pe": has_pe,
                "label": f"Injection in {proc_name} (PID: {pid}) at {start}",
            }
            lines.append(
                f"- [{cite_key}] Injected memory in {proc_name} (PID: {pid}) at {start} "
                f"Protection: {protection} | Embedded PE Header: {has_pe}"
            )
        lines.append("")

    # 6. Incident Chronology & Timeline Telemetry (Timeliner)
    try:
        from orochi.website.defaults import RESULT_STATUS_SUCCESS
        from orochi.website.models import Result

        timeliner_res = Result.objects.filter(
            dump=dump,
            plugin__name__in=["windows.timeliner.Timeliner", "timeliner.Timeliner"],
            result=RESULT_STATUS_SUCCESS,
        ).first()
        if timeliner_res:
            timeline_values = list(
                Value.objects.filter(result=timeliner_res).values_list(
                    "value", flat=True
                )[:1000]
            )
            if timeline_values:
                from orochi.utils.timeliner import (
                    build_timeline_feed,
                    extract_timeline_entries,
                )

                entries = extract_timeline_entries(
                    values=timeline_values,
                    dump_name=dump.name,
                    dump_index=str(dump.index),
                )
                feed = build_timeline_feed(entries)
                stats = feed.get("stats", {})
                if stats.get("total_events", 0) > 0:
                    lines.append("## INCIDENT TIMELINE TELEMETRY (TIMELINER)")
                    lines.append(
                        f"- Incident Timespan: {stats.get('timespan_display', 'N/A')} "
                        f"(Earliest: {stats.get('earliest_date', 'N/A')} | Latest: {stats.get('latest_date', 'N/A')})"
                    )
                    lines.append(
                        f"- Total Chronological Events: {stats.get('total_events')}"
                    )
                    if stats.get("max_density", 0) > 0:
                        lines.append(
                            f"- Peak Activity Velocity: {stats.get('max_density')} events/bucket"
                        )
                    lines.append("")
    except Exception:
        pass

    citation_registry["__meta__"] = {
        "valid_ips": valid_ips,
        "valid_hashes": valid_hashes,
    }

    evidence_text = "\n".join(lines)
    return evidence_text, valid_pids, valid_offsets, citation_registry


def get_local_ollama_config() -> Tuple[str, str, Optional[Dict[str, str]]]:
    """
    Retrieve local Ollama connection settings:
    - Base URL (strictly local)
    - Default Model Name
    - Proxies (if configured)
    """
    service = Service.objects.filter(name=SERVICE_OLLAMA).first()
    base_url = (
        service.url if service and service.url else "http://ollama:11434"
    ).rstrip("/")
    proxies = service.proxy if service and service.proxy else None

    model_name = service.key if service and service.key else None
    if not model_name:
        try:
            resp = requests.get(f"{base_url}/api/tags", proxies=proxies, timeout=5)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                if models:
                    model_name = models[0].get("name")
        except Exception:
            pass

    model_name = model_name or "llama3.2:1b"
    return base_url, model_name, proxies


def generate_narrative_with_ollama(
    dump: Dump,
    evidence_text: str,
    model_name: Optional[str] = None,
    timeout: int = 240,
) -> Tuple[str, str]:
    """
    Send structured evidence to local Ollama instance with hard chain-of-custody prompt.
    Returns:
        - model_used: Name of model executed
        - response_text: Raw LLM markdown output
    """
    base_url, default_model, proxies = get_local_ollama_config()
    chosen_model = model_name or default_model

    prompt = (
        "You are an expert digital forensics assistant delivering an executive first-pass triage narrative "
        f"for memory dump '{dump.name}' ({dump.operating_system}).\n\n"
        "STRICT FORENSIC CONSTRAINTS:\n"
        "1. Triage narrative and forensic orientation only. Do not speculate or invent details.\n"
        "2. CRITICAL CONSTRAINT: NEVER invent, hallucinate, fabricate, or guess any PID, process name, memory offset, IP address, or cryptographic hash.\n"
        "3. You MUST ONLY reference PIDs, offsets, and processes that explicitly appear in the EVIDENCE section below.\n"
        "4. MANDATORY CITATIONS: Every factual finding, anomaly, or suspicious activity MUST cite the exact bracketed citation tag "
        "from the evidence (e.g. [TriageFinding:1], [DumpSecret:3], [Value:12]).\n"
        "5. Structure your output in professional Markdown with these distinct sections:\n"
        "   - ## Executive Triage Summary\n"
        "   - ## Process Execution & Suspicious Anomalies\n"
        "   - ## Network Communications & External Infrastructure\n"
        "   - ## Memory Injections & Exposed Credentials\n"
        "   - ## Recommended Investigative Actions (with citations)\n\n"
        f"EVIDENCE SECTION:\n{evidence_text}\n"
    )

    try:
        resp = requests.post(
            f"{base_url}/api/generate",
            json={
                "model": chosen_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "num_predict": 512,
                },
            },
            proxies=proxies,
            timeout=timeout,
        )
        if resp.status_code == 200:
            return chosen_model, resp.json().get("response", "")
        else:
            raise RuntimeError(f"Ollama returned HTTP {resp.status_code}: {resp.text}")
    except requests.RequestException as e:
        raise ConnectionError(
            f"Unable to communicate with local Ollama at {base_url}: {str(e)}"
        ) from e


def verify_and_sanitize_narrative(
    raw_text: str,
    valid_pids: Set[int],
    valid_offsets: Set[str],
    citation_registry: Dict[str, Dict[str, Any]],
    valid_ips: Optional[Set[str]] = None,
    valid_hashes: Optional[Set[str]] = None,
    evidence_hash: Optional[str] = None,
) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Forensic verification and sanitization layer:
    1. Extracts all asserted PIDs and verifies against genuine evidence set.
    2. Flags any unverified / hallucinated PID with a prominent warning badge.
    3. Extracts and verifies memory offsets with word boundaries.
    4. Extracts and flags unverified external IPv4 addresses and cryptographic hashes.
    5. Transforms citation tags into clickable interactive HTML pills.
    6. Computes comprehensive hallucination and integrity telemetry.
    """
    if valid_ips is None:
        valid_ips = citation_registry.get("__meta__", {}).get("valid_ips", set())
    if valid_hashes is None:
        valid_hashes = citation_registry.get("__meta__", {}).get("valid_hashes", set())

    verified_pids: Set[int] = set()
    unverified_pids: Set[int] = set()
    verified_offsets: Set[str] = set()
    unverified_offsets: Set[str] = set()
    verified_ips: Set[str] = set()
    unverified_ips: Set[str] = set()
    verified_hashes: Set[str] = set()
    unverified_hashes: Set[str] = set()
    cited_items: List[Dict[str, Any]] = []

    text = raw_text

    # 1. Check for PIDs: look for patterns like PID 1234, PID: 1234, pid=1234, PID #1234
    pid_matches = re.finditer(r"\b(?:PIDs?|pids?|Pid)\s*[:=#]?\s*(\d+)\b", text)
    for m in pid_matches:
        pid_num = int(m.group(1))
        if pid_num in valid_pids:
            verified_pids.add(pid_num)
        else:
            unverified_pids.add(pid_num)

    # Flag unverified PIDs in text
    for bad_pid in unverified_pids:
        flag_markup = (
            f'<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-bold '
            f'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border border-rose-300 dark:border-rose-800" '
            f'title="FORENSIC WARNING: This PID was not present in the structured plugin evidence and may be an LLM fabrication">'
            f"⚠️ Unverified PID: {bad_pid}</span>"
        )
        pattern = rf"\b(?:PIDs?|pids?|Pid)\s*[:=#]?\s*{bad_pid}\b"
        text = re.sub(pattern, flag_markup, text)

    # 2. Check for Hex Offsets: 0x12345678
    offset_matches = re.finditer(r"\b(0x[0-9a-fA-F]{4,16})\b", text)
    for m in offset_matches:
        offset_str = m.group(1)
        if offset_str.lower() in valid_offsets or offset_str.upper() in valid_offsets:
            verified_offsets.add(offset_str)
        else:
            unverified_offsets.add(offset_str)

    # Flag unverified offsets in text with word boundaries
    for bad_offset in unverified_offsets:
        flag_markup = (
            f'<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-bold '
            f'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300 dark:border-amber-800" '
            f'title="FORENSIC WARNING: This memory offset was not verified in source plugin data">'
            f"⚠️ Unverified Offset: {bad_offset}</span>"
        )
        text = re.sub(rf"\b{re.escape(bad_offset)}\b", flag_markup, text)

    # 3. Check for IPv4 addresses
    if valid_ips:
        ip_matches = re.finditer(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b", text)
        for m in ip_matches:
            ip_str = m.group(1)
            if ip_str in ["127.0.0.1", "0.0.0.0", "255.255.255.0", "255.255.255.255"]:
                continue
            octets = [int(o) for o in ip_str.split(".") if o.isdigit()]
            if len(octets) != 4 or any(o > 255 for o in octets):
                continue
            if ip_str in valid_ips:
                verified_ips.add(ip_str)
            else:
                unverified_ips.add(ip_str)

        for bad_ip in unverified_ips:
            flag_markup = (
                f'<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-bold '
                f'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border border-rose-300 dark:border-rose-800" '
                f'title="FORENSIC WARNING: This IP address was not present in structured network evidence">'
                f"⚠️ Unverified IP: {bad_ip}</span>"
            )
            text = re.sub(rf"\b{re.escape(bad_ip)}\b", flag_markup, text)

    # 4. Check for Hashes (MD5: 32 hex, SHA256: 64 hex)
    if valid_hashes or evidence_hash:
        hash_matches = re.finditer(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{32})\b", text)
        for m in hash_matches:
            h_str = m.group(1).lower()
            if (
                evidence_hash and h_str in evidence_hash.lower()
            ) or h_str in valid_hashes:
                verified_hashes.add(h_str)
            else:
                unverified_hashes.add(h_str)

        for bad_hash in unverified_hashes:
            short_h = f"{bad_hash[:8]}..."
            flag_markup = (
                f'<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-bold '
                f'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300 dark:border-amber-800" '
                f'title="FORENSIC WARNING: This cryptographic hash was not verified in source records">'
                f"⚠️ Unverified Hash: {short_h}</span>"
            )
            text = re.sub(rf"\b{re.escape(bad_hash)}\b", flag_markup, text)

    # 5. Transform citation tags into interactive pills: [TriageFinding:1], [DumpSecret:2], [Value:3]
    def replace_citation(match):
        key = match.group(1)
        if key in citation_registry:
            meta = citation_registry[key]
            cited_items.append(meta)
            tooltip = f"Click to inspect: {meta.get('label', key)}"
            return (
                f'<span class="citation-pill inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold '
                f"bg-blue-100 text-blue-800 dark:bg-blue-950/70 dark:text-blue-300 border border-blue-200 dark:border-blue-800 "
                f'hover:bg-blue-200 dark:hover:bg-blue-900/80 cursor-pointer transition-colors" '
                f'data-cite-key="{key}" data-cite-type="{meta.get("type")}" data-cite-id="{meta.get("id")}" '
                f'title="{tooltip}" onclick="showCitationDetails(\'{key}\')">'
                f'<i class="fa-solid fa-bookmark text-[9px]"></i> {key}</span>'
            )
        return match.group(0)

    formatted_text = re.sub(
        r"\[((?:TriageFinding|DumpSecret|Value):\d+)\]", replace_citation, text
    )

    # Convert Markdown to HTML
    try:
        import marko

        formatted_html = marko.convert(formatted_text)
    except Exception:
        formatted_html = formatted_text.replace("\n", "<br>")

    hallucination_check = {
        "verified_pids": sorted(list(verified_pids)),
        "unverified_pids": sorted(list(unverified_pids)),
        "verified_offsets": sorted(list(verified_offsets)),
        "unverified_offsets": sorted(list(unverified_offsets)),
        "verified_ips": sorted(list(verified_ips)),
        "unverified_ips": sorted(list(unverified_ips)),
        "verified_hashes": sorted(list(verified_hashes)),
        "unverified_hashes": sorted(list(unverified_hashes)),
        "total_citations": len(cited_items),
        "is_clean": (
            len(unverified_pids) == 0
            and len(unverified_offsets) == 0
            and len(unverified_ips) == 0
            and len(unverified_hashes) == 0
        ),
    }

    return formatted_html, hallucination_check, cited_items


def generate_dump_narrative(
    dump: Dump,
    author=None,
    model_name: Optional[str] = None,
) -> DumpNarrative:
    """
    High-level coordinator to extract evidence, invoke local Ollama, verify claims,
    and persist the resulting DumpNarrative record.
    """
    evidence_text, valid_pids, valid_offsets, citation_registry = (
        extract_dump_forensic_context(dump)
    )
    evidence_hash = hashlib.sha256(evidence_text.encode("utf-8")).hexdigest()

    model_used, raw_text = generate_narrative_with_ollama(
        dump, evidence_text, model_name=model_name
    )

    formatted_html, hallucination_check, cited_items = verify_and_sanitize_narrative(
        raw_text,
        valid_pids,
        valid_offsets,
        citation_registry,
        evidence_hash=evidence_hash,
    )

    narrative = DumpNarrative.objects.create(
        dump=dump,
        author=author,
        model_name=model_used,
        raw_narrative=raw_text,
        formatted_narrative=formatted_html,
        evidence_hash=evidence_hash,
        citations=cited_items,
        hallucination_check=hallucination_check,
    )
    return narrative
