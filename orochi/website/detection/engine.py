import logging
from collections import Counter
from typing import Any

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.detection.rules import (
    DetectionResult,
    evaluate_code_injection,
    evaluate_dkom_unlinked,
    evaluate_linux_threats,
    evaluate_parent_child_incoherence,
    evaluate_process_masquerading,
    evaluate_suspicious_cmdlines,
    evaluate_suspicious_dlls,
    evaluate_suspicious_network,
    evaluate_unbacked_exec_images,
    evaluate_unexpected_drivers,
    evaluate_yara_and_extracted_files,
)
from orochi.website.models import Dump, DumpIOC, Result, TriageFinding, Value

logger = logging.getLogger(__name__)


SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
# Highest risk score reachable for each worst-finding severity (keeps get_risk_level consistent)
SEVERITY_SCORE_CAP = {0: 0, 1: 24, 2: 49, 3: 74, 4: 100}


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


def get_plugin_rows(dump: Dump, plugin_suffixes: list[str]) -> list[dict[str, Any]]:
    """
    Fetches structured Value dictionaries for a dump matching any of the given plugin suffixes.
    e.g. ['pslist.PsList', 'pstree.PsTree']
    """
    results = Result.objects.filter(
        dump=dump,
        result=RESULT_STATUS_SUCCESS,
    ).select_related("plugin")
    if matching_result_ids := [
        r.id for r in results if any(r.plugin.name.endswith(suffix) for suffix in plugin_suffixes)
    ]:
        return list(Value.objects.filter(result_id__in=matching_result_ids).values_list("value", flat=True))
    else:
        return []


NOTIFY_SEVERITIES = ("Critical", "High")


def notify_new_serious_findings(dump: Dump, detections: list) -> None:
    """Tell the users who can see the dump about new High/Critical triage findings (#1566), once per evaluation.

    One summary message per evaluation, not one per finding; re-evaluating triage does not repeat findings
    already reported. External channels follow each user's preferences (``finding`` events).
    """
    try:
        from django.utils.html import escape
        from guardian.shortcuts import get_users_with_perms

        from orochi.website.notifier import bold, notify_user
        from orochi.website.signals import _safe_async_external_notifications

        counts = Counter(d.severity for d in detections)
        summary = ", ".join(f"{counts[s]} {s}" for s in NOTIFY_SEVERITIES if counts.get(s))
        top = sorted(detections, key=lambda d: (d.severity != "Critical", -d.score))[:3]
        lines = "".join(f"<br>• {escape(d.rule_name)}: {escape(d.entity or '')}" for d in top)
        message = f"Triage of {bold(dump.name)}: {escape(summary)} new finding(s).{lines}"
        for user in get_users_with_perms(dump, only_with_perms_in=["can_see"]):
            notify_user(user, message, html=True, kind="finding")
            _safe_async_external_notifications(user, f"Triage: {summary} finding(s)", message, "finding")
    except Exception as exc:
        logger.warning("Triage finding notification for dump %s not sent: %s", dump.pk, exc)


def evaluate_dump_triage(dump: Dump) -> dict[str, Any]:
    """
    Executes the full forensic behavioral detection engine across dump Volatility plugin outputs,
    persists TriageFinding records, updates dump.risk_score, and returns a detailed report.
    """
    # 1. Fetch relevant plugin outputs
    pslist_rows = get_plugin_rows(dump, ["pslist.PsList", "pstree.PsTree", "linux.pslist.PsList"])
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
    dll_rows = get_plugin_rows(dump, ["dlllist.DllList", "ldrmodules.LdrModules"])
    yara_rows = get_plugin_rows(
        dump,
        ["yarascan.YaraScan", "vadyarascan.VadYaraScan", "vmayarascan.VmaYaraScan"],
    )
    dumpfiles_rows = get_plugin_rows(dump, ["dumpfiles.DumpFiles"])
    module_rows = get_plugin_rows(dump, ["windows.modules.Modules"])
    driverscan_rows = get_plugin_rows(dump, ["windows.driverscan.DriverScan"])
    vad_rows = get_plugin_rows(dump, ["windows.vadinfo.VadInfo"])
    malicious_hash_iocs = list(
        DumpIOC.objects.filter(dump=dump, ioc_type__in=["hash_sha256", "hash_md5"], is_malicious=True)
    )

    all_detections: list[DetectionResult] = []

    # 2. Run rule evaluations
    if pslist_rows:
        all_detections.extend(evaluate_parent_child_incoherence(pslist_rows))
        all_detections.extend(evaluate_process_masquerading(pslist_rows, cmdline_rows))

    # Without the active process list (not run yet, or being re-run) every scanned process would look unlinked
    if psscan_rows and pslist_rows:
        all_detections.extend(evaluate_dkom_unlinked(pslist_rows, psscan_rows))

    if cmdline_rows:
        all_detections.extend(evaluate_suspicious_cmdlines(cmdline_rows))

    if netscan_rows:
        all_detections.extend(evaluate_suspicious_network(netscan_rows))

    if malfind_rows:
        unbacked = evaluate_unbacked_exec_images(malfind_rows, vad_rows)
        # One finding per region: the unbacked-image finding replaces the generic malfind one
        unbacked_regions = {
            (d.raw_data["malfind"].get("PID"), d.raw_data["malfind"].get("Start VPN")) for d in unbacked
        }
        all_detections.extend(
            d
            for d in evaluate_code_injection(malfind_rows)
            if (d.raw_data.get("PID"), d.raw_data.get("Start VPN")) not in unbacked_regions
        )
        all_detections.extend(unbacked)

    # Driver checks need the module list: without it every scanned driver would look unlinked
    if module_rows:
        all_detections.extend(evaluate_unexpected_drivers(driverscan_rows, module_rows))

    if check_syscall_rows or bash_rows:
        all_detections.extend(evaluate_linux_threats(check_syscall_rows, bash_rows))

    if dll_rows:
        all_detections.extend(evaluate_suspicious_dlls(dll_rows))

    if yara_rows or dumpfiles_rows or malicious_hash_iocs:
        all_detections.extend(evaluate_yara_and_extracted_files(yara_rows, dumpfiles_rows, malicious_hash_iocs))

    # Declarative Sigma-style hunting rules (#1545)
    from orochi.website.detection.sigma_engine import evaluate_hunting_rules

    all_detections.extend(evaluate_hunting_rules(dump))

    # 3. Calculate Risk Score
    # Many weak signals must not add up to a level above the worst finding: cap by highest severity
    raw_score = sum(d.score for d in all_detections)
    worst = max((SEVERITY_RANK.get(d.severity, 0) for d in all_detections), default=0)
    final_score = min(100, raw_score, SEVERITY_SCORE_CAP[worst])
    risk_level = get_risk_level(final_score)

    # 4. Atomically persist TriageFinding records
    previous_serious = set(
        TriageFinding.objects.filter(dump=dump, severity__in=NOTIFY_SEVERITIES).values_list("rule_id", "entity")
    )
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

    new_serious = [
        d for d in all_detections if d.severity in NOTIFY_SEVERITIES and (d.rule_id, d.entity) not in previous_serious
    ]
    if new_serious:
        notify_new_serious_findings(dump, new_serious)

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
