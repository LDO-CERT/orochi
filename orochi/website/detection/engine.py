import logging
from collections import Counter
from typing import Any, Dict, List

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.detection.rules import (
    DetectionResult,
    evaluate_code_injection,
    evaluate_dkom_unlinked,
    evaluate_linux_threats,
    evaluate_parent_child_incoherence,
    evaluate_process_masquerading,
    evaluate_suspicious_cmdlines,
    evaluate_suspicious_network,
)
from orochi.website.models import Dump, Result, TriageFinding, Value

logger = logging.getLogger(__name__)


def get_risk_level(score: int) -> str:
    """Classifies risk score into severity level."""
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    elif score > 0:
        return "Low"
    return "Clean"


def get_plugin_rows(dump: Dump, plugin_suffixes: List[str]) -> List[Dict[str, Any]]:
    """
    Fetches structured Value dictionaries for a dump matching any of the given plugin suffixes.
    e.g. ['pslist.PsList', 'pstree.PsTree']
    """
    results = Result.objects.filter(
        dump=dump,
        result=RESULT_STATUS_SUCCESS,
    ).select_related("plugin")
    if matching_result_ids := [
        r.id
        for r in results
        if any(r.plugin.name.endswith(suffix) for suffix in plugin_suffixes)
    ]:
        return list(
            Value.objects.filter(result_id__in=matching_result_ids).values_list(
                "value", flat=True
            )
        )
    else:
        return []


def evaluate_dump_triage(dump: Dump) -> Dict[str, Any]:
    """
    Executes the full forensic behavioral detection engine across dump Volatility plugin outputs,
    persists TriageFinding records, updates dump.risk_score, and returns a detailed report.
    """
    # 1. Fetch relevant plugin outputs
    pslist_rows = get_plugin_rows(
        dump, ["pslist.PsList", "pstree.PsTree", "linux.pslist.PsList"]
    )
    psscan_rows = get_plugin_rows(dump, ["psscan.PsScan", "linux.psscan.PsScan"])
    cmdline_rows = get_plugin_rows(dump, ["cmdline.CmdLine", "consoles.Consoles"])
    netscan_rows = get_plugin_rows(
        dump,
        [
            "netscan.NetScan",
            "netstat.NetStat",
            "linux.netscan.NetScan",
            "linux.sockstat.Sockstat",
        ],
    )
    malfind_rows = get_plugin_rows(dump, ["malfind.Malfind", "linux.malfind.Malfind"])
    check_syscall_rows = get_plugin_rows(dump, ["check_syscall.Check_syscall"])
    bash_rows = get_plugin_rows(dump, ["bash.Bash"])

    all_detections: List[DetectionResult] = []

    # 2. Run rule evaluations
    if pslist_rows:
        all_detections.extend(evaluate_parent_child_incoherence(pslist_rows))
        all_detections.extend(evaluate_process_masquerading(pslist_rows, cmdline_rows))

    if psscan_rows:
        all_detections.extend(evaluate_dkom_unlinked(pslist_rows, psscan_rows))

    if cmdline_rows:
        all_detections.extend(evaluate_suspicious_cmdlines(cmdline_rows))

    if netscan_rows:
        all_detections.extend(evaluate_suspicious_network(netscan_rows))

    if malfind_rows:
        all_detections.extend(evaluate_code_injection(malfind_rows))

    if check_syscall_rows or bash_rows:
        all_detections.extend(evaluate_linux_threats(check_syscall_rows, bash_rows))

    # 3. Calculate Risk Score
    raw_score = sum(d.score for d in all_detections)
    final_score = min(100, raw_score)
    risk_level = get_risk_level(final_score)

    # 4. Atomically persist TriageFinding records
    TriageFinding.objects.filter(dump=dump).delete()
    if db_findings := [
        TriageFinding(
            dump=dump,
            rule_id=d.rule_id,
            rule_name=d.rule_name,
            category=d.category,
            severity=d.severity,
            score=d.score,
            mitre_technique=d.mitre_technique,
            description=d.description,
            evidence_snippet=d.evidence_snippet,
            entity=d.entity,
            raw_data=d.raw_data,
        )
        for d in all_detections
    ]:
        TriageFinding.objects.bulk_create(db_findings)

    # 5. Update Dump risk score
    dump.risk_score = final_score
    dump.save(update_fields=["risk_score"])

    # 6. Aggregate KPIs
    severity_counts = Counter(d.severity for d in all_detections)
    category_counts = Counter(d.category for d in all_detections)
    mitre_set = sorted({d.mitre_technique for d in all_detections if d.mitre_technique})

    persisted_findings = list(TriageFinding.objects.filter(dump=dump))

    return {
        "dump_index": str(dump.index),
        "dump_name": dump.name,
        "risk_score": final_score,
        "risk_level": risk_level,
        "total_findings": len(persisted_findings),
        "findings": persisted_findings,
        "severity_kpis": {
            "critical": severity_counts.get("Critical", 0),
            "high": severity_counts.get("High", 0),
            "medium": severity_counts.get("Medium", 0),
            "low": severity_counts.get("Low", 0),
        },
        "category_kpis": dict(category_counts),
        "mitre_techniques": mitre_set,
    }
