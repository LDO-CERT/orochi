import logging
import os
import time
from pathlib import Path
from typing import Any

import requests
from django.conf import settings
from django.utils import timezone

from orochi.website.defaults import SERVICE_CAPE, SERVICE_SIEM, SERVICE_THEHIVE
from orochi.website.models import Case, Dump, DumpIOC, Service

logger = logging.getLogger(__name__)


# =============================================================================
# 1. SIEM Forwarding (Splunk HEC / Elastic ECS / Microsoft Sentinel) - #1568
# =============================================================================
def format_siem_payload(event_data: dict[str, Any], provider: str = "splunk") -> dict[str, Any]:
    """
    Format an Orochi forensic event or Case summary into a SIEM-native payload:
    - 'splunk': Splunk HTTP Event Collector (HEC) envelope
    - 'elastic': Elastic Common Schema (ECS) JSON document
    - 'sentinel': Microsoft Sentinel Log Analytics custom table record
    """
    prov = (provider or "splunk").strip().lower()
    now_ts = time.time()
    iso_ts = timezone.now().isoformat()

    if prov in ("elastic", "elk"):
        return {
            "@timestamp": iso_ts,
            "event": {
                "kind": "alert" if event_data.get("severity") in ("High", "Critical") else "event",
                "category": ["intrusion_detection", "malware"],
                "dataset": "orochi.forensics",
                "module": "orochi",
            },
            "orochi": event_data,
        }

    if prov in ("sentinel", "azure"):
        return {
            "TimeGenerated": iso_ts,
            "SourceSystem": "Orochi",
            "EventType": event_data.get("event", "forensic_event"),
            "Title": event_data.get("title", ""),
            "Severity": event_data.get("severity", "Medium"),
            "Payload": event_data,
        }

    # Default: Splunk HEC format
    return {
        "time": now_ts,
        "host": "orochi",
        "source": "orochi:dfir",
        "sourcetype": "orochi:forensics:json",
        "event": event_data,
    }


def _proxies(svc: Service) -> dict[str, str] | None:
    """requests proxies from the Service proxy JSON (other keys, e.g. "provider", are ignored)."""
    conf = svc.proxy if isinstance(svc.proxy, dict) else {}
    return {k: v for k, v in conf.items() if k in ("http", "https") and v} or None


def _guess_siem_provider(url: str) -> str:
    """Best effort provider detection from the endpoint URL, used when none is configured."""
    url_lower = url.lower()
    if "ingest.monitor.azure.com" in url_lower or "sentinel" in url_lower:
        return "sentinel"
    if "9200" in url_lower or "_doc" in url_lower or "elastic" in url_lower:
        return "elastic"
    return "splunk"


def forward_to_siem(
    event_data: dict[str, Any],
    provider: str | None = None,
    service: Service | None = None,
) -> dict[str, Any]:
    """
    Dispatch formatted forensic event data to the configured SIEM service (#1568).
    """
    svc = service or Service.objects.filter(name=SERVICE_SIEM).first()
    if not svc or not svc.url:
        raise ValueError("SIEM service is not configured in Admin > Services.")

    proxy_conf = svc.proxy if isinstance(svc.proxy, dict) else {}
    detected_provider = provider or proxy_conf.get("provider") or _guess_siem_provider(svc.url)

    payload = format_siem_payload(event_data, provider=detected_provider)
    headers = {"Content-Type": "application/json"}
    token = svc.decrypted_key
    if token:
        if token.lower().startswith(("apikey ", "bearer ", "splunk ")):
            # Full header value already provided by the administrator
            headers["Authorization"] = token
        elif detected_provider == "splunk":
            headers["Authorization"] = f"Splunk {token}"
        elif detected_provider == "elastic":
            headers["Authorization"] = f"ApiKey {token}"
        else:
            headers["Authorization"] = f"Bearer {token}"

    # The Azure Monitor Logs Ingestion API (Sentinel) expects an array of records
    body = [payload] if detected_provider == "sentinel" else payload
    resp = requests.post(svc.url, json=body, headers=headers, proxies=_proxies(svc), timeout=10, verify=svc.verify_ssl)
    return {
        "success": 200 <= resp.status_code < 300,
        "status_code": resp.status_code,
        "provider": detected_provider,
        "payload": payload,
    }


def forward_case_to_siem(case: Case, provider: str | None = None) -> dict[str, Any]:
    """Package a Case's findings, timeline events, and IOCs and forward them to the SIEM."""
    dump_ids = set(case.evidences.filter(dump__isnull=False).values_list("dump_id", flat=True))
    if case.folder:
        dump_ids.update(Dump.objects.filter(folder=case.folder).values_list("pk", flat=True))

    iocs = list(
        DumpIOC.objects.filter(dump_id__in=dump_ids).values(
            "ioc_type", "value", "threat_score", "is_malicious", "source_plugin"
        )[:200]
    )
    findings = [
        {
            "id": f.pk,
            "severity": f.severity,
            "mitre_attack_technique": f.mitre_attack_technique,
            "note": f.note,
            "tags": f.tags or [],
        }
        for f in case.findings.all()
    ]
    event_data = {
        "event": "case_siem_export",
        "case_id": case.pk,
        "title": case.name,
        "status": case.status,
        "description": case.description or "",
        "severity": "Critical"
        if any(f["severity"] == "Critical" for f in findings)
        else "High"
        if findings
        else "Medium",
        "findings_count": len(findings),
        "findings": findings,
        "iocs_count": len(iocs),
        "iocs": iocs,
    }
    return forward_to_siem(event_data, provider=provider)


# =============================================================================
# 2. TheHive / Cortex Integration - #1550
# =============================================================================
SEVERITY_TO_THEHIVE = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

IOC_TYPE_TO_THEHIVE = {
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "hash_sha256": "hash",
    "hash_md5": "hash",
    "yara": "other",
}


def build_thehive_case_payload(case: Case) -> dict[str, Any]:
    """
    Build a TheHive v4/v5 compatible Case & Observables payload from an Orochi Case (#1550).
    """
    findings = list(case.findings.all())
    max_sev = 2
    tags = {"orochi", "memory-forensics"}
    tasks = []

    for f in findings:
        max_sev = max(max_sev, SEVERITY_TO_THEHIVE.get(f.severity, 2))
        if f.mitre_attack_technique:
            tags.add(f"mitre:{f.mitre_attack_technique}")
        for t in f.tags or []:
            tags.add(t)
        tasks.append(
            {
                "title": f"[{f.severity}] Finding #{f.pk} ({f.mitre_attack_technique or 'General'})",
                "description": f.note or "",
                "status": "InProgress",
            }
        )

    dump_ids = set(case.evidences.filter(dump__isnull=False).values_list("dump_id", flat=True))
    if case.folder:
        dump_ids.update(Dump.objects.filter(folder=case.folder).values_list("pk", flat=True))

    observables = []
    for ioc in DumpIOC.objects.filter(dump_id__in=dump_ids)[:200]:
        observables.append(
            {
                "dataType": IOC_TYPE_TO_THEHIVE.get(ioc.ioc_type, "other"),
                "data": ioc.value,
                "message": f"Extracted from {ioc.source_plugin} (threat_score={ioc.threat_score})",
                "tlp": 2,
                "ioc": bool(ioc.is_malicious),
                "sighted": True,
                "tags": [f"plugin:{ioc.source_plugin}", f"score:{ioc.threat_score}"],
            }
        )

    return {
        "title": f"[Orochi] {case.name}",
        "description": case.description or f"Forensic investigation exported from Orochi Case #{case.pk}",
        "severity": max_sev,
        "tlp": 2,
        "pap": 2,
        "tags": sorted(tags),
        "tasks": tasks,
        "observables": observables,
    }


def export_case_to_thehive(case: Case, push: bool = True) -> dict[str, Any]:
    """
    Export an Orochi Case to a configured TheHive instance (#1550).
    If `push=False`, returns the constructed TheHive payload without making network requests.
    """
    payload = build_thehive_case_payload(case)
    if not push:
        return {"success": True, "pushed": False, "thehive_payload": payload}

    svc = Service.objects.filter(name=SERVICE_THEHIVE).first()
    if not svc or not svc.url:
        raise ValueError("TheHive service is not configured in Admin > Services.")

    if not svc.decrypted_key:
        raise ValueError("TheHive service has no API key configured.")

    # Accept both the instance root and a full ".../api/v1/case" URL
    base_url = svc.url.rstrip("/")
    for suffix in ("/api/v1/case", "/api/case"):
        if base_url.endswith(suffix):
            base_url = base_url[: -len(suffix)]
    endpoint = f"{base_url}/api/v1/case"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {svc.decrypted_key}",
    }
    proxies = _proxies(svc)

    case_body = {k: v for k, v in payload.items() if k != "observables"}
    resp = requests.post(endpoint, json=case_body, headers=headers, proxies=proxies, timeout=10, verify=svc.verify_ssl)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"TheHive returned HTTP {resp.status_code}: {resp.text}")

    remote_case = resp.json() if resp.content else {}
    remote_id = remote_case.get("_id") or remote_case.get("id")

    exported_obs = 0
    if remote_id and payload["observables"]:
        obs_endpoint = f"{base_url}/api/v1/case/{remote_id}/observable"
        for obs in payload["observables"]:
            try:
                r_obs = requests.post(
                    obs_endpoint, json=obs, headers=headers, proxies=proxies, timeout=8, verify=svc.verify_ssl
                )
                if r_obs.status_code in (200, 201):
                    exported_obs += 1
            except Exception as exc:
                logger.warning("Failed to push observable %s to TheHive: %s", obs.get("data"), exc)

    return {
        "success": True,
        "pushed": True,
        "thehive_case_id": remote_id,
        "exported_observables": exported_obs,
        "thehive_payload": payload,
    }


# =============================================================================
# 3. CAPE / Cuckoo Sandbox Integration for Extracted PEs - #1551
# =============================================================================
def cape_base_url(url: str) -> str:
    """CAPE root URL, accepting also ".../apiv2" or the full ".../apiv2/tasks/create/file" endpoint."""
    base = url.rstrip("/")
    for suffix in ("/apiv2/tasks/create/file", "/apiv2"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


def submit_file_to_sandbox(
    dump: Dump,
    filepath: str,
    machine: str | None = None,
    tags: str | None = None,
) -> dict[str, Any]:
    """
    Submit an extracted artifact/PE from a memory dump to CAPE or Cuckoo Sandbox (#1551).
    """
    svc = Service.objects.filter(name=SERVICE_CAPE).first()
    if not svc or not svc.url:
        raise ValueError("CAPE / Cuckoo Sandbox service is not configured in Admin > Services.")

    # Only artifacts extracted from this dump (MEDIA_ROOT/<index>/...) may leave the server.
    dump_root = (Path(settings.MEDIA_ROOT) / str(dump.index)).resolve()
    candidate = Path(filepath)
    if not candidate.is_absolute():
        candidate = Path(settings.MEDIA_ROOT) / filepath
    p_file = candidate.resolve()
    if not p_file.is_relative_to(dump_root) or p_file == dump_root:
        raise ValueError("Invalid file path: only files extracted from this dump can be submitted.")
    if not p_file.is_file():
        raise FileNotFoundError(f"Extracted file not found at '{filepath}'.")

    submit_url = f"{cape_base_url(svc.url)}/apiv2/tasks/create/file/"

    headers = {}
    token = svc.decrypted_key
    if token:
        headers["Authorization"] = token if token.lower().startswith(("token ", "bearer ")) else f"Token {token}"

    data = {"custom": f"orochi_dump:{dump.index}"}
    if machine:
        data["machine"] = machine
    if tags:
        data["tags"] = tags

    proxies = _proxies(svc)
    with open(p_file, "rb") as fh:
        files = {"file": (os.path.basename(p_file), fh)}
        resp = requests.post(
            submit_url, headers=headers, data=data, files=files, proxies=proxies, timeout=30, verify=svc.verify_ssl
        )

    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Sandbox submission failed with HTTP {resp.status_code}: {resp.text}")

    body = resp.json() if resp.content else {}
    task_id = (
        body.get("task_id")
        or (body.get("data", {}).get("task_ids", [None])[0] if isinstance(body.get("data"), dict) else None)
        or (body.get("task_ids", [None])[0] if isinstance(body.get("task_ids"), list) else None)
    )
    return {
        "success": True,
        "task_id": task_id,
        "filename": os.path.basename(p_file),
        "dump_index": dump.index,
        "sandbox_response": body,
    }
