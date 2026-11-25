# orochi/website/case_reporting.py
import contextlib
import html
import logging
from datetime import UTC

import markdown
import stix2

from orochi.website.models import Case

logger = logging.getLogger(__name__)


def _collect_case_dumps(case: Case) -> list:
    """Return unique Dump objects linked to a case via evidences or forensic nodes."""
    dumps_by_pk = {}
    for ev in case.evidences.select_related("dump").all():
        if ev.dump:
            dumps_by_pk[ev.dump.pk] = ev.dump
    for node in case.graph_nodes.select_related("dump").all():
        if node.dump:
            dumps_by_pk[node.dump.pk] = node.dump
    return list(dumps_by_pk.values())


def _collect_artefact_timeline(case: Case, dumps: list) -> list[tuple]:
    """Collect forensic artefact timestamps (nodes, edges, process/network rows, manual entries) for a case."""
    from datetime import datetime

    from orochi.website.defaults import RESULT_STATUS_SUCCESS
    from orochi.website.models import Value

    entries: list[tuple[datetime, str, str]] = []

    # 1. Manual analyst-authored timeline events (non-activity)
    from orochi.website.defaults import ACTIVITY_EVENT_TYPES as activity_types

    for event in case.timeline_events.all().order_by("timestamp"):
        if event.event_type not in activity_types:
            entries.append((event.timestamp, event.event_type, event.description))

    # 2. ForensicNode first_seen timestamps
    for node in case.graph_nodes.filter(first_seen__isnull=False).select_related("dump"):
        dump_label = node.dump.name if node.dump else "unknown"
        entries.append((node.first_seen, f"Artifact ({node.node_type})", f"{node.label} observed in dump {dump_label}"))

    # 3. ForensicEdge timestamps
    for edge in (
        case.graph_nodes.model._meta.apps.get_model("website", "ForensicEdge")
        .objects.filter(case=case, timestamp__isnull=False)
        .select_related("source", "target")
    ):
        entries.append((edge.timestamp, f"Relation ({edge.edge_type})", f"{edge.source.label} -> {edge.target.label}"))

    # 4. Direct process/network artefact timestamps from dump plugin results (if not already populated via nodes)
    if dumps and not any(e[1].startswith("Artifact (") for e in entries):
        ts_keys = ("CreateTime", "Created", "StartTime", "Timestamp", "CREATION TIME", "Creation Time")
        for dump in dumps:
            rows = Value.objects.filter(
                result__dump=dump,
                result__result=RESULT_STATUS_SUCCESS,
                result__plugin__name__in=[
                    "windows.pslist.PsList",
                    "linux.pslist.PsList",
                    "windows.netscan.NetScan",
                ],
            ).values_list("result__plugin__name", "value")[:100]
            for plugin_name, row in rows:
                if not isinstance(row, dict):
                    continue
                for k in ts_keys:
                    raw_ts = row.get(k)
                    if not raw_ts or not isinstance(raw_ts, str):
                        continue
                    try:
                        parsed = datetime.fromisoformat(raw_ts.strip().replace("Z", "+00:00").replace(" UTC", ""))
                        if parsed.tzinfo is None:
                            parsed = parsed.replace(tzinfo=UTC)
                        proc = (
                            row.get("ImageFileName")
                            or row.get("COMM")
                            or row.get("Owner")
                            or row.get("Process")
                            or "artifact"
                        )
                        pid = row.get("PID") or row.get("Pid") or ""
                        label = f"{proc} (PID {pid})" if pid else str(proc)
                        entries.append((parsed, f"Artifact ({plugin_name})", f"{label} in {dump.name}"))
                        break
                    except ValueError:
                        continue

    entries.sort(key=lambda item: item[0])
    return entries


def export_case_to_markdown(case: Case) -> str:
    """Generate a structured Markdown incident response and technical report for a Case (Issue #1540)."""
    import volatility3

    from orochi.website.models import DumpIOC, Result

    dumps = _collect_case_dumps(case)
    vol_version = getattr(volatility3, "__version__", "unknown")

    lines = [
        f"# Incident Report: {case.name}",
        "",
        f"**Case ID**: {case.pk}  ",
        f"**Status**: {case.status}  ",
        f"**Created At**: {case.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Lead Investigator**: {case.user.username}  ",
        f"**Collaborators**: {', '.join(c.username for c in case.collaborators.all()) or 'None'}  ",
        f"**CTF Mode**: {'Yes' if case.is_ctf else 'No'}  ",
        "",
        "## Executive Summary",
        "",
        case.description or "No overall description provided.",
        "",
        "## Scope",
        "",
    ]

    if dumps:
        lines.append("| Dump Name | OS | MD5 | SHA-256 | Banner |")
        lines.append("|-----------|----|-----|---------|--------|")
        for d in dumps:
            lines.append(
                f"| {d.name} | {d.operating_system or 'N/A'} | `{d.md5 or 'N/A'}` | `{d.sha256 or 'N/A'}` | {d.banner or 'N/A'} |"
            )
    else:
        lines.append("_No memory dumps linked to this case._")
    lines.append("")

    lines.append("## Evidences & Memory Dumps")
    lines.append("")
    evidences = case.evidences.all()
    if evidences.exists():
        lines.append("| Evidence ID | Dump Name | OS | Plugin | Extracted File |")
        lines.append("|-------------|-----------|----|--------|----------------|")
        for ev in evidences:
            dump_name = ev.dump.name if ev.dump else "N/A"
            os_name = ev.dump.operating_system if ev.dump else "N/A"
            plugin_name = ev.plugin or "N/A"
            extracted = ev.extracted_file or "N/A"
            lines.append(f"| {ev.pk} | {dump_name} | {os_name} | {plugin_name} | {extracted} |")
    else:
        lines.append("_No evidence attached to this case._")
    lines.append("")

    lines.append("## Findings & Threat Indicators")
    lines.append("")
    findings = case.findings.all()
    if findings.exists():
        lines.append("| ID | Severity | MITRE ATT&CK | Tags | Description / Note |")
        lines.append("|----|----------|--------------|------|--------------------|")
        for f in findings:
            tags = ", ".join(f.tags or [])
            lines.append(f"| {f.pk} | {f.severity} | {f.mitre_attack_technique or 'N/A'} | {tags} | {f.note or ''} |")
    else:
        lines.append("_No findings recorded for this case._")
    lines.append("")

    lines.append("## Indicators of Compromise (IOCs)")
    lines.append("")
    iocs = (
        list(DumpIOC.objects.filter(dump__in=dumps).select_related("dump").order_by("-threat_score", "ioc_type"))
        if dumps
        else []
    )
    if iocs:
        lines.append("| Dump | Type | Value | Source Plugin | Score | Malicious |")
        lines.append("|------|------|-------|---------------|-------|-----------|")
        for ioc in iocs:
            lines.append(
                f"| {ioc.dump.name} | `{ioc.ioc_type}` | `{ioc.value}` | {ioc.source_plugin or 'N/A'} | {ioc.threat_score} | {'Yes' if ioc.is_malicious else 'No'} |"
            )
    else:
        lines.append("_No IOCs extracted for the case's memory dumps._")
    lines.append("")

    lines.append("## Forensic Timeline")
    lines.append("")
    artefact_events = _collect_artefact_timeline(case, dumps)
    if artefact_events:
        for ts_val, ev_type, desc in artefact_events:
            ts = ts_val.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"- **{ts}** `[{ev_type}]`: {desc}")
    else:
        lines.append("_No forensic artefact timeline events recorded._")
    lines.append("")

    lines.append("## Investigator Notes")
    lines.append("")
    notes = case.notes.all().order_by("created_at")
    if notes.exists():
        for note in notes:
            created = note.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"### {note.title}")
            lines.append(f"_Author: {note.author.username} | Timestamp: {created}_")
            lines.append("")
            lines.append(note.content)
            lines.append("")
    else:
        lines.append("_No notes recorded._")
    lines.append("")

    lines.append("## Technical Appendix")
    lines.append("")
    lines.append(f"- **Volatility 3 Version**: `{vol_version}`")
    lines.append("")
    results = (
        list(
            Result.objects.filter(dump__in=dumps)
            .select_related("dump", "plugin")
            .order_by("dump__name", "plugin__name")
        )
        if dumps
        else []
    )
    if results:
        lines.append("| Dump | Plugin | Status | Parameters |")
        lines.append("|------|--------|--------|------------|")
        for r in results:
            params_str = str(r.parameter) if r.parameter else "-"
            lines.append(f"| {r.dump.name} | `{r.plugin.name}` | {r.get_result_display()} | `{params_str}` |")
    else:
        lines.append("_No plugin executions recorded for the case's memory dumps._")
    lines.append("")

    return "\n".join(lines)


def export_case_to_html(case: Case) -> str:
    """Generate a styled HTML document for a Case."""
    md_content = export_case_to_markdown(case)
    html_body = markdown.markdown(md_content, extensions=["tables", "fenced_code"])

    case_name_escaped = html.escape(case.name)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Incident Report: {case_name_escaped}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #24292e;
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
        }}
        h1, h2, h3 {{
            color: #1a202c;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 8px;
        }}
        h1 {{ font-size: 2.2rem; }}
        h2 {{ font-size: 1.5rem; margin-top: 30px; }}
        h3 {{ font-size: 1.2rem; margin-top: 20px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #cbd5e0;
            padding: 10px 12px;
            text-align: left;
        }}
        th {{
            background-color: #f7fafc;
            font-weight: 600;
        }}
        tr:nth-child(even) {{
            background-color: #f8fafc;
        }}
        code {{
            background-color: #edf2f7;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.9em;
        }}
        @page {{
            margin: 2cm;
            @bottom-right {{
                content: counter(page);
            }}
        }}
    </style>
</head>
<body>
    {html_body}
</body>
</html>"""


def export_case_to_pdf(case: Case) -> bytes:
    """Compile Case HTML report into a professional PDF via WeasyPrint."""
    try:
        import weasyprint
    except (ImportError, OSError) as exc:
        logger.error("WeasyPrint or system C libraries (libpango/libgobject) not available: %s", exc)
        raise RuntimeError(
            "PDF generation requires WeasyPrint and system libraries (libpango-1.0-0, libglib2.0-0). "
            "Please ensure system dependencies are installed or export as HTML / Markdown."
        ) from exc
    html_content = export_case_to_html(case)
    return weasyprint.HTML(string=html_content).write_pdf()


def export_case_to_stix(case: Case) -> str:
    """Generate an OASIS STIX 2.1 JSON bundle from Case findings, evidences, and observables."""
    objects = []

    identity = stix2.Identity(
        name="Orochi Forensics Platform",
        identity_class="system",
        description="Automated Volatility Memory Forensics Suite",
    )
    objects.append(identity)

    report_refs = [identity.id]

    # Map Evidence and IOCs
    for evidence in case.evidences.all():
        if not evidence.dump:
            continue
        dump = evidence.dump

        # Check hashes
        if dump.sha256:
            file_obj = stix2.File(
                hashes={"SHA-256": dump.sha256},
                custom_properties={"x_orochi_dump_name": dump.name, "x_orochi_case_id": case.pk},
            )
            objects.append(file_obj)
            report_refs.append(file_obj.id)
        elif dump.md5:
            file_obj = stix2.File(
                hashes={"MD5": dump.md5},
                custom_properties={"x_orochi_dump_name": dump.name, "x_orochi_case_id": case.pk},
            )
            objects.append(file_obj)
            report_refs.append(file_obj.id)

    # Map Findings to STIX Indicators / Attack Patterns
    for finding in case.findings.all():
        indicator = stix2.Indicator(
            name=f"Finding #{finding.pk}: {finding.severity} Severity",
            description=finding.note or f"Forensic finding in case {case.name}",
            pattern="[file:hashes.'SHA-256' = '0000000000000000000000000000000000000000000000000000000000000000']"
            if not finding.mitre_attack_technique
            else f"[process:name = '{finding.mitre_attack_technique}']",
            pattern_type="stix",
            created_by_ref=identity.id,
        )
        objects.append(indicator)
        report_refs.append(indicator.id)

        if finding.mitre_attack_technique:
            attack_pattern = stix2.AttackPattern(
                name=finding.mitre_attack_technique,
                external_references=[
                    {
                        "source_name": "mitre-attack",
                        "external_id": finding.mitre_attack_technique,
                    }
                ],
                created_by_ref=identity.id,
            )
            objects.append(attack_pattern)
            report_refs.append(attack_pattern.id)

            relationship = stix2.Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=attack_pattern.id,
            )
            objects.append(relationship)
            report_refs.append(relationship.id)

    # Map Forensic Nodes (from Feature 2)
    for node in case.graph_nodes.filter(is_malicious=True)[:100]:
        if node.node_type == "socket":
            parts = node.label.split(":")
            if len(parts) >= 2:
                with contextlib.suppress(Exception):
                    ip_obj = stix2.IPv4Address(value=parts[0])
                    objects.append(ip_obj)
                    report_refs.append(ip_obj.id)

    pub_date = case.created_at
    if pub_date.tzinfo is None or pub_date.tzinfo.utcoffset(pub_date) is None:
        pub_date = pub_date.replace(tzinfo=UTC)

    report = stix2.Report(
        name=f"Forensic Investigation: {case.name}",
        description=case.description or "Memory forensics incident report.",
        published=pub_date,
        created_by_ref=identity.id,
        object_refs=report_refs,
    )
    objects.append(report)

    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    return bundle.serialize(pretty=True)
