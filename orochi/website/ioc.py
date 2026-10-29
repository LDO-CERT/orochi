import ipaddress
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import requests
from pymisp import MISPEvent, PyMISP

from orochi.website.defaults import (
    SERVICE_ABUSEIPDB,
    SERVICE_GREYNOISE,
    SERVICE_MISP,
    SERVICE_OTX,
    SERVICE_VIRUSTOTAL,
)
from orochi.website.models import Dump, DumpIOC, DumpSecret, Service, Value

logger = logging.getLogger(__name__)

# Private and reserved networks to exclude from network IOCs
EXCLUDED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

URL_REGEX = re.compile(r"https?://[a-zA-Z0-9\.\-_~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|ru|cn|cc|top|me|info|biz|co|live|club|online|site|pro|cloud|ai)\b",
    re.IGNORECASE,
)


def is_public_ip(ip_str: str) -> bool:
    """Verify whether a string is a valid public, routable IP address."""
    if not ip_str or ip_str in {"-", "*", "None", "0.0.0.0", "::"}:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_link_local
            or ip.is_unspecified
        ):
            return False
        for net in EXCLUDED_NETWORKS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False


def clean_address(raw_addr: Any) -> tuple[str | None, int | None]:
    """Parse raw address string into (ip, port)."""
    if not raw_addr or not isinstance(raw_addr, str):
        return None, None
    raw_addr = raw_addr.strip()
    if ":" in raw_addr:
        # IPv4 with port or IPv6
        if raw_addr.startswith("[") and "]" in raw_addr:
            ip = raw_addr[1 : raw_addr.index("]")]
            port_str = raw_addr.split("]:")[-1] if "]:" in raw_addr else None
            try:
                port = int(port_str) if port_str else None
            except ValueError:
                port = None
            return ip, port
        parts = raw_addr.split(":")
        if len(parts) == 2:
            ip = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = None
            return ip, port
    return raw_addr, None


def extract_dump_iocs(dump: Dump) -> list[DumpIOC]:
    """Extract IOCs across network, dumped files, YARA hits, and command lines for a dump."""
    created_or_updated: list[DumpIOC] = []
    values_qs = Value.objects.filter(result__dump=dump).select_related("result__plugin")

    # Group values by plugin name
    for val in values_qs.iterator(chunk_size=1000):
        row = val.value
        plugin = val.result.plugin.name.lower()
        if not isinstance(row, dict):
            continue

        # 1. Network IOCs
        if "netscan" in plugin or "sockstat" in plugin or "netstat" in plugin:
            foreign_addr_raw = (
                row.get("ForeignAddr")
                or row.get("Foreign Address")
                or row.get("Destination Addr")
                or row.get("Remote Address")
                or row.get("foreign_ip")
            )
            foreign_ip, parsed_port = clean_address(foreign_addr_raw)
            foreign_port = row.get("ForeignPort") or row.get("Foreign Port") or parsed_port
            local_addr = row.get("LocalAddr") or row.get("Local Address") or row.get("Source Addr")
            local_port = row.get("LocalPort") or row.get("Local Port")
            proto = row.get("Proto") or row.get("Protocol") or "TCP"
            pid = row.get("Pid") or row.get("PID")
            process = row.get("Owner") or row.get("Process") or row.get("ImageFileName")

            if foreign_ip and is_public_ip(foreign_ip):
                context = {
                    "pid": pid,
                    "process": process,
                    "foreign_port": foreign_port,
                    "local_addr": local_addr,
                    "local_port": local_port,
                    "proto": str(proto),
                }
                ioc, _ = DumpIOC.objects.update_or_create(
                    dump=dump,
                    ioc_type="ip",
                    value=foreign_ip,
                    defaults={
                        "source_plugin": val.result.plugin.name,
                        "context": context,
                    },
                )
                created_or_updated.append(ioc)

        # 2. Dumped File Hashes & ClamAV
        down_path = row.get("down_path")
        sha256 = row.get("sha256") or row.get("File SHA256") or row.get("SHA256")
        md5 = row.get("md5") or row.get("File MD5") or row.get("MD5")
        clamav = row.get("clamav") or row.get("ClamAV")
        filename = (
            row.get("File output")
            or row.get("Filename")
            or row.get("FileName")
            or row.get("file_name")
            or row.get("Name")
        )
        pid = row.get("Pid") or row.get("PID")
        process = row.get("Owner") or row.get("Process") or row.get("ImageFileName")

        if sha256 and isinstance(sha256, str) and len(sha256) == 64 and sha256 != "-" and not sha256.startswith("0000"):
            context = {
                "pid": pid,
                "process": process,
                "filename": filename,
                "down_path": down_path if down_path != "-" else None,
                "clamav": clamav if clamav != "-" else None,
            }
            is_mal = bool(clamav and clamav != "-")
            threat_score = 90 if is_mal else 0
            ioc, _ = DumpIOC.objects.update_or_create(
                dump=dump,
                ioc_type="hash_sha256",
                value=sha256.lower(),
                defaults={
                    "source_plugin": val.result.plugin.name,
                    "context": context,
                    "is_malicious": is_mal,
                    "threat_score": threat_score,
                },
            )
            created_or_updated.append(ioc)

        if md5 and isinstance(md5, str) and len(md5) == 32 and md5 != "-" and not md5.startswith("0000"):
            context = {
                "pid": pid,
                "process": process,
                "filename": filename,
                "down_path": down_path if down_path != "-" else None,
                "clamav": clamav if clamav != "-" else None,
            }
            is_mal = bool(clamav and clamav != "-")
            threat_score = 90 if is_mal else 0
            ioc, _ = DumpIOC.objects.update_or_create(
                dump=dump,
                ioc_type="hash_md5",
                value=md5.lower(),
                defaults={
                    "source_plugin": val.result.plugin.name,
                    "context": context,
                    "is_malicious": is_mal,
                    "threat_score": threat_score,
                },
            )
            created_or_updated.append(ioc)

        # 3. YARA Rules
        if "yara" in plugin:
            rule_name = row.get("Rule") or row.get("rule")
            offset = row.get("Offset") or row.get("offset")
            hexdump = row.get("Hexdump") or row.get("Value") or ""
            pid = row.get("Pid") or row.get("PID")
            process = row.get("Process") or row.get("ImageFileName")

            if rule_name and isinstance(rule_name, str) and len(rule_name) > 1:
                context = {
                    "pid": pid,
                    "process": process,
                    "offset": hex(offset) if isinstance(offset, int) else str(offset),
                    "hexdump": str(hexdump)[:120],
                }
                ioc, _ = DumpIOC.objects.update_or_create(
                    dump=dump,
                    ioc_type="yara",
                    value=rule_name,
                    defaults={
                        "source_plugin": val.result.plugin.name,
                        "context": context,
                        "is_malicious": True,
                        "threat_score": 80,
                    },
                )
                created_or_updated.append(ioc)

        # 4. Command line URLs & Domains
        if "cmdline" in plugin or "consoles" in plugin:
            args = row.get("Args") or row.get("args") or row.get("CommandLine") or ""
            if isinstance(args, str) and len(args) > 5:
                pid = row.get("Pid") or row.get("PID")
                process = row.get("Process") or row.get("ImageFileName")

                for url in URL_REGEX.findall(args):
                    if len(url) < 500:
                        ioc, _ = DumpIOC.objects.update_or_create(
                            dump=dump,
                            ioc_type="url",
                            value=url,
                            defaults={
                                "source_plugin": val.result.plugin.name,
                                "context": {"pid": pid, "process": process},
                            },
                        )
                        created_or_updated.append(ioc)

                for dom in DOMAIN_REGEX.findall(args):
                    dom_clean = dom.lower()
                    if not dom_clean.endswith(".exe") and not dom_clean.endswith(".dll") and len(dom_clean) < 250:
                        ioc, _ = DumpIOC.objects.update_or_create(
                            dump=dump,
                            ioc_type="domain",
                            value=dom_clean,
                            defaults={
                                "source_plugin": val.result.plugin.name,
                                "context": {"pid": pid, "process": process},
                            },
                        )
                        created_or_updated.append(ioc)

    # 5. Extract URLs/Domains from DumpSecret records
    for secret in DumpSecret.objects.filter(dump=dump):
        if secret.matched_data:
            for url in URL_REGEX.findall(secret.matched_data):
                if len(url) < 500:
                    ioc, _ = DumpIOC.objects.update_or_create(
                        dump=dump,
                        ioc_type="url",
                        value=url,
                        defaults={
                            "source_plugin": f"Secrets Scanner ({secret.rule_name})",
                            "context": {"pid": secret.pid, "process": secret.process_name, "category": secret.category},
                        },
                    )
                    created_or_updated.append(ioc)

    return list(DumpIOC.objects.filter(dump=dump))


def enrich_ioc(ioc: DumpIOC, service_type: int | None = None) -> dict[str, Any]:
    """Enrich an IOC using configured Threat Intelligence services."""
    results: dict[str, Any] = {}
    services = Service.objects.all()
    if service_type:
        services = services.filter(name=service_type)

    for s in services:
        proxy_dict = s.proxy if (s.proxy and isinstance(s.proxy, dict)) else None

        # ABUSEIPDB
        if s.name == SERVICE_ABUSEIPDB and ioc.ioc_type == "ip":
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {"Key": s.key, "Accept": "application/json"}
                params = {"ipAddress": ioc.value, "maxAgeInDays": "90"}
                resp = requests.get(url, headers=headers, params=params, proxies=proxy_dict, timeout=8)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = int(data.get("abuseConfidenceScore", 0))
                    ioc.enrichment["abuseipdb"] = {
                        "abuse_score": score,
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "total_reports": data.get("totalReports", 0),
                        "is_whitelisted": data.get("isWhitelisted", False),
                    }
                    if score >= 25:
                        ioc.is_malicious = True
                    ioc.threat_score = max(ioc.threat_score, score)
                    results["abuseipdb"] = ioc.enrichment["abuseipdb"]
            except Exception as e:
                logger.warning(f"[IOC] AbuseIPDB error on {ioc.value}: {e}")

        # ALIENVAULT OTX
        elif s.name == SERVICE_OTX:
            try:
                otx_type = None
                if ioc.ioc_type == "ip":
                    otx_type = "IPv4"
                elif ioc.ioc_type == "domain":
                    otx_type = "domain"
                elif ioc.ioc_type in ["hash_sha256", "hash_md5"]:
                    otx_type = "file"

                if otx_type:
                    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc.value}/general"
                    headers = {"X-OTX-API-KEY": s.key, "Accept": "application/json"}
                    resp = requests.get(url, headers=headers, proxies=proxy_dict, timeout=8)
                    if resp.status_code == 200:
                        data = resp.json()
                        pulses = data.get("pulse_info", {}).get("pulses", [])
                        pulse_count = data.get("pulse_info", {}).get("count", 0)
                        tags = list({t for p in pulses for t in p.get("tags", [])})[:8]
                        malware_families = list(
                            {
                                m.get("display_name")
                                for p in pulses
                                for m in p.get("malware_families", [])
                                if m.get("display_name")
                            }
                        )[:4]

                        ioc.enrichment["otx"] = {
                            "pulse_count": pulse_count,
                            "tags": tags,
                            "malware_families": malware_families,
                        }
                        if pulse_count > 0:
                            ioc.is_malicious = True
                            ioc.threat_score = max(ioc.threat_score, min(100, pulse_count * 25))
                        results["otx"] = ioc.enrichment["otx"]
            except Exception as e:
                logger.warning(f"[IOC] AlienVault OTX error on {ioc.value}: {e}")

        # GREYNOISE
        elif s.name == SERVICE_GREYNOISE and ioc.ioc_type == "ip":
            try:
                url = f"https://api.greynoise.io/v3/community/{ioc.value}"
                headers = {"key": s.key, "Accept": "application/json"}
                resp = requests.get(url, headers=headers, proxies=proxy_dict, timeout=8)
                if resp.status_code == 200:
                    data = resp.json()
                    classification = data.get("classification", "unknown")
                    noise = data.get("noise", False)
                    riot = data.get("riot", False)
                    name = data.get("name", "")

                    ioc.enrichment["greynoise"] = {
                        "classification": classification,
                        "noise": noise,
                        "riot": riot,
                        "actor": name,
                    }
                    if classification == "malicious":
                        ioc.is_malicious = True
                        ioc.threat_score = max(ioc.threat_score, 90)
                    elif riot or classification == "benign":
                        ioc.threat_score = min(ioc.threat_score, 15)
                    results["greynoise"] = ioc.enrichment["greynoise"]
            except Exception as e:
                logger.warning(f"[IOC] GreyNoise error on {ioc.value}: {e}")

        # VIRUSTOTAL
        elif s.name == SERVICE_VIRUSTOTAL:
            try:
                endpoint = None
                if ioc.ioc_type in ["hash_sha256", "hash_md5"]:
                    endpoint = f"files/{ioc.value}"
                elif ioc.ioc_type == "ip":
                    endpoint = f"ip_addresses/{ioc.value}"
                elif ioc.ioc_type == "domain":
                    endpoint = f"domains/{ioc.value}"

                if endpoint:
                    url = f"https://www.virustotal.com/api/v3/{endpoint}"
                    headers = {"x-apikey": s.key, "Accept": "application/json"}
                    resp = requests.get(url, headers=headers, proxies=proxy_dict, timeout=8)
                    if resp.status_code == 200:
                        attrs = resp.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                        total = sum(stats.values()) if stats else 0

                        ioc.enrichment["virustotal"] = {
                            "positives": positives,
                            "total": total,
                            "last_analysis_stats": stats,
                            "permalink": f"https://www.virustotal.com/gui/{endpoint}",
                        }
                        if positives >= 3:
                            ioc.is_malicious = True
                            ioc.threat_score = max(ioc.threat_score, min(100, positives * 10))
                        results["virustotal"] = ioc.enrichment["virustotal"]
            except Exception as e:
                logger.warning(f"[IOC] VirusTotal error on {ioc.value}: {e}")

    ioc.save()
    return results


def export_iocs_to_misp(dump: Dump, iocs: list[DumpIOC], author: Any = None) -> dict[str, Any]:
    """Export a collection of DumpIOC objects to a MISP instance."""
    try:
        misp_info = Service.objects.get(name=SERVICE_MISP)
    except Service.DoesNotExist:
        raise ValueError("MISP service is not configured in Admin > Services.")

    proxy_dict = misp_info.proxy if (misp_info.proxy and isinstance(misp_info.proxy, dict)) else None
    misp = PyMISP(misp_info.url, misp_info.key, ssl=False, proxies=proxy_dict)

    event = MISPEvent()
    event.info = f"[Orochi] Threat Intel IOC Report: {dump.name}"
    event.distribution = 0  # Your organisation only
    event.threat_level_id = 1 if dump.risk_score >= 75 else 2 if dump.risk_score >= 50 else 3
    event.analysis = 2  # Completed

    event.add_tag("orochi")
    event.add_tag("memory-forensics")
    event.add_tag("threat-intel")
    if dump.operating_system:
        event.add_tag(f"os:{dump.operating_system}")

    exported_count = 0
    for ioc in iocs:
        comment = f"From {ioc.source_plugin}"
        if ioc.context.get("pid"):
            comment += f" | PID: {ioc.context['pid']}"
        if ioc.context.get("process"):
            comment += f" ({ioc.context['process']})"

        if ioc.ioc_type == "ip":
            event.add_attribute("ip-dst", value=ioc.value, to_ids=ioc.is_malicious, comment=comment)
            exported_count += 1
        elif ioc.ioc_type == "hash_sha256":
            event.add_attribute("sha256", value=ioc.value, to_ids=ioc.is_malicious, comment=comment)
            exported_count += 1
        elif ioc.ioc_type == "hash_md5":
            event.add_attribute("md5", value=ioc.value, to_ids=ioc.is_malicious, comment=comment)
            exported_count += 1
        elif ioc.ioc_type == "domain":
            event.add_attribute("domain", value=ioc.value, to_ids=ioc.is_malicious, comment=comment)
            exported_count += 1
        elif ioc.ioc_type == "url":
            event.add_attribute("url", value=ioc.value, to_ids=ioc.is_malicious, comment=comment)
            exported_count += 1
        elif ioc.ioc_type == "yara":
            event.add_attribute("yara", value=ioc.value, to_ids=True, comment=comment)
            exported_count += 1

    res = misp.add_event(event)
    event_id = None
    event_uuid = None
    if isinstance(res, dict):
        event_id = res.get("Event", {}).get("id") or res.get("id")
        event_uuid = res.get("Event", {}).get("uuid") or res.get("uuid")
    elif hasattr(res, "id"):
        event_id = getattr(res, "id", None)
        event_uuid = getattr(res, "uuid", None)

    return {
        "success": True,
        "message": f"Successfully exported {exported_count} IOCs to MISP",
        "event_id": event_id,
        "event_uuid": event_uuid,
        "exported_count": exported_count,
    }


def export_iocs_to_stix(dump: Dump, iocs: list[DumpIOC]) -> dict[str, Any]:
    """Export DumpIOC records to standard STIX 2.1 JSON bundle."""
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"
    identity_id = "identity--e1a2f3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b"

    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "Orochi Collaborative Forensics Platform",
            "identity_class": "system",
        }
    ]

    for ioc in iocs:
        pattern = None
        name = f"Indicator: {ioc.value}"
        if ioc.ioc_type == "ip":
            pattern = f"[ipv4-addr:value = '{ioc.value}']"
            name = f"Malicious IP: {ioc.value}"
        elif ioc.ioc_type == "hash_sha256":
            pattern = f"[file:hashes.'SHA-256' = '{ioc.value}']"
            name = f"File Hash SHA256: {ioc.value}"
        elif ioc.ioc_type == "hash_md5":
            pattern = f"[file:hashes.'MD5' = '{ioc.value}']"
            name = f"File Hash MD5: {ioc.value}"
        elif ioc.ioc_type == "domain":
            pattern = f"[domain-name:value = '{ioc.value}']"
            name = f"C2 Domain: {ioc.value}"
        elif ioc.ioc_type == "url":
            pattern = f"[url:value = '{ioc.value}']"
            name = f"Malicious URL: {ioc.value}"
        elif ioc.ioc_type == "yara":
            pattern = "[file:name MATCHES '.*']"  # STIX pattern for matched signature
            name = f"YARA Signature: {ioc.value}"

        if pattern:
            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created_by_ref": identity_id,
                "created": now_iso,
                "modified": now_iso,
                "name": name,
                "description": f"Extracted by Orochi from memory dump '{dump.name}' via {ioc.source_plugin}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso,
                "confidence": ioc.threat_score if ioc.threat_score > 0 else 50,
                "labels": ["malicious-activity" if ioc.is_malicious else "anomalous-activity"],
                "custom_properties": {
                    "x_orochi_dump": dump.name,
                    "x_orochi_source_plugin": ioc.source_plugin,
                    "x_orochi_context": ioc.context,
                    "x_orochi_enrichment": ioc.enrichment,
                },
            }
            objects.append(indicator_obj)

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
