import ipaddress
import logging
from pathlib import Path
from typing import Any

from orochi.website.detection.engine import get_plugin_rows
from orochi.website.models import Dump

logger = logging.getLogger(__name__)

# Known malicious or common C2 ports to highlight
HIGH_RISK_PORTS = {4444, 1337, 31337, 6667, 8888, 9999, 4443, 8443, 7001, 8088, 5555, 6000, 7777, 8008, 9001, 9090}

# Standard server ports
COMMON_SERVICES = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3389: "RDP",
    445: "SMB",
    139: "NetBIOS",
    135: "RPC",
    8080: "HTTP-Proxy",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
}


def is_external_ip(ip_str: str) -> bool:
    """Checks if an IP address string is a valid public/routable IP."""
    if not ip_str or ip_str in ("*", "0.0.0.0", "::", "::1", "255.255.255.255"):
        return False
    try:
        # Strip port or scope if present
        clean_ip = ip_str.split("%")[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or ip_obj.is_link_local
        )
    except ValueError:
        return False


def resolve_geoip(ip_str: str) -> dict[str, Any]:
    """
    Resolves an external IP address using MaxMind GeoLite2 databases if available.
    Returns dictionary with country_code, country_name, city, latitude, longitude, and asn.
    """
    clean_ip = ip_str.split("%")[0].strip()
    geo_info = {
        "country_code": "XX",
        "country_name": "Unknown",
        "city": "",
        "latitude": None,
        "longitude": None,
        "asn": "",
        "asn_org": "",
    }

    try:
        import geoip2.database
        from geoip2.errors import GeoIP2Error

        # 1. City / Coordinates
        city_db = Path("/maxmind/GeoLite2-City.mmdb")
        if city_db.exists():
            try:
                with geoip2.database.Reader(str(city_db)) as reader:
                    resp = reader.city(clean_ip)
                    if resp.country.iso_code:
                        geo_info["country_code"] = resp.country.iso_code
                        geo_info["country_name"] = resp.country.name or resp.country.iso_code
                    if resp.city.name:
                        geo_info["city"] = resp.city.name
                    if resp.location.latitude is not None and resp.location.longitude is not None:
                        geo_info["latitude"] = round(resp.location.latitude, 4)
                        geo_info["longitude"] = round(resp.location.longitude, 4)
            except (GeoIP2Error, Exception) as e:
                logger.debug(f"GeoLite2-City lookup error for {clean_ip}: {e}")

        # 2. Country fallback if City didn't provide it
        if geo_info["country_code"] == "XX":
            country_db = Path("/maxmind/GeoLite2-Country.mmdb")
            if country_db.exists():
                try:
                    with geoip2.database.Reader(str(country_db)) as reader:
                        resp = reader.country(clean_ip)
                        if resp.country.iso_code:
                            geo_info["country_code"] = resp.country.iso_code
                            geo_info["country_name"] = resp.country.name or resp.country.iso_code
                except (GeoIP2Error, Exception) as e:
                    logger.debug(f"GeoLite2-Country lookup error for {clean_ip}: {e}")

        # 3. ASN
        asn_db = Path("/maxmind/GeoLite2-ASN.mmdb")
        if asn_db.exists():
            try:
                with geoip2.database.Reader(str(asn_db)) as reader:
                    resp = reader.asn(clean_ip)
                    if resp.autonomous_system_number:
                        geo_info["asn"] = f"AS{resp.autonomous_system_number}"
                    if resp.autonomous_system_organization:
                        geo_info["asn_org"] = resp.autonomous_system_organization
            except (GeoIP2Error, Exception) as e:
                logger.debug(f"GeoLite2-ASN lookup error for {clean_ip}: {e}")

    except ImportError:
        pass

    return geo_info


def extract_network_report(dump: Dump) -> dict[str, Any]:
    """
    Extracts all network sockets from available Volatility plugins for the dump,
    correlates with triage findings, resolves external GeoIPs, and constructs
    both a topology graph (nodes & edges) and an interactive geo-map dataset.
    """
    plugin_suffixes = [
        "netscan.NetScan",
        "netstat.NetStat",
        "sockstat.Sockstat",
        "sockscan.Sockscan",
        "linux.netstat.NetStat",
        "linux.sockstat.Sockstat",
        "linux.netscan.NetScan",
        "mac.netstat.NetStat",
    ]

    raw_rows = get_plugin_rows(dump, plugin_suffixes)

    # Correlate with triage findings for this dump
    suspicious_pids = set()
    suspicious_ports = set()
    for finding in dump.triage_findings.all():
        raw_d = finding.raw_data or {}
        if pid := raw_d.get("PID"):
            try:
                suspicious_pids.add(int(pid))
            except (ValueError, TypeError):
                pass
        if f_port := raw_d.get("ForeignPort"):
            try:
                suspicious_ports.add(int(f_port))
            except (ValueError, TypeError):
                pass
        if l_port := raw_d.get("LocalPort"):
            try:
                suspicious_ports.add(int(l_port))
            except (ValueError, TypeError):
                pass

    sockets = []
    geo_points_map = {}
    nodes_map = {}
    edges = []

    geoip_cache = {}

    for row in raw_rows:
        proto = str(row.get("Proto") or "TCP").upper()
        l_addr = str(row.get("LocalAddr") or row.get("Local IP") or "0.0.0.0").strip()
        f_addr = str(row.get("ForeignAddr") or row.get("Foreign IP") or "*").strip()
        state = str(row.get("State") or "UNKNOWN").upper()
        created = str(row.get("Created") or row.get("Time") or "")

        # Ports
        l_port_raw = row.get("LocalPort") or row.get("Local Port") or 0
        try:
            l_port = int(l_port_raw)
        except (ValueError, TypeError):
            l_port = 0

        f_port_raw = row.get("ForeignPort") or row.get("Foreign Port") or 0
        try:
            f_port = int(f_port_raw)
        except (ValueError, TypeError):
            f_port = 0

        # PID & Process name
        pid_raw = row.get("PID") or row.get("Pid") or 0
        try:
            pid = int(pid_raw)
        except (ValueError, TypeError):
            pid = 0

        owner = str(row.get("Owner") or row.get("Process") or "unknown").strip()
        proc_display = owner

        is_external = is_external_ip(f_addr)
        is_listening = state in ("LISTEN", "LISTENING") or (l_port > 0 and f_addr in ("*", "0.0.0.0", "::"))
        is_suspicious = (
            pid in suspicious_pids
            or f_port in suspicious_ports
            or f_port in HIGH_RISK_PORTS
            or l_port in HIGH_RISK_PORTS
        )

        service_name = COMMON_SERVICES.get(f_port or l_port, "")

        geo_info = {
            "country_code": "XX",
            "country_name": "Unknown",
            "city": "",
            "latitude": None,
            "longitude": None,
            "asn": "",
            "asn_org": "",
        }

        if is_external:
            if f_addr not in geoip_cache:
                geoip_cache[f_addr] = resolve_geoip(f_addr)
            geo_info = geoip_cache[f_addr]

            # Aggregate into geo_points for map rendering
            if geo_info.get("latitude") and geo_info.get("longitude"):
                geo_key = f"{geo_info['latitude']}_{geo_info['longitude']}"
                if geo_key not in geo_points_map:
                    geo_points_map[geo_key] = {
                        "latitude": geo_info["latitude"],
                        "longitude": geo_info["longitude"],
                        "ip": f_addr,
                        "country_code": geo_info["country_code"],
                        "country_name": geo_info["country_name"],
                        "city": geo_info["city"],
                        "asn": geo_info["asn"],
                        "asn_org": geo_info["asn_org"],
                        "connections_count": 0,
                        "processes": set(),
                        "ports": set(),
                        "is_suspicious": False,
                    }
                geo_points_map[geo_key]["connections_count"] += 1
                if proc_display:
                    geo_points_map[geo_key]["processes"].add(f"{proc_display} (PID {pid})")
                if f_port:
                    geo_points_map[geo_key]["ports"].add(f_port)
                if is_suspicious:
                    geo_points_map[geo_key]["is_suspicious"] = True

        socket_entry = {
            "proto": proto,
            "local_addr": l_addr,
            "local_port": l_port,
            "foreign_addr": f_addr,
            "foreign_port": f_port,
            "state": state,
            "pid": pid,
            "process": proc_display,
            "created": created,
            "is_external": is_external,
            "is_listening": is_listening,
            "is_suspicious": is_suspicious,
            "service": service_name,
            "country_code": geo_info.get("country_code", "XX"),
            "country_name": geo_info.get("country_name", ""),
            "city": geo_info.get("city", ""),
            "asn": geo_info.get("asn", ""),
            "asn_org": geo_info.get("asn_org", ""),
        }
        sockets.append(socket_entry)

        # ---------------- Topology Graph Construction ----------------
        # 1. Process Node
        proc_node_id = f"proc_{pid}_{proc_display}"
        if proc_node_id not in nodes_map:
            nodes_map[proc_node_id] = {
                "id": proc_node_id,
                "label": f"{proc_display}\n(PID {pid})" if pid else proc_display,
                "name": proc_display,
                "pid": pid,
                "type": "process",
                "risk": "Critical" if pid in suspicious_pids else ("Medium" if is_suspicious else "Normal"),
                "is_suspicious": is_suspicious or pid in suspicious_pids,
                "connections": 0,
            }
        nodes_map[proc_node_id]["connections"] += 1

        # 2. Endpoint / Socket Node
        if is_external:
            target_node_id = f"remote_{f_addr}"
            target_label = f"{f_addr}\n{geo_info['country_code']} - {geo_info['asn'] or 'Remote'}"
            target_type = "external_ip"
        elif is_listening:
            target_node_id = f"listen_{l_addr}_{l_port}"
            target_label = f"LISTEN\n{l_addr}:{l_port}"
            target_type = "listening_port"
        else:
            target_node_id = f"local_{f_addr}_{f_port}" if f_addr != "*" else f"local_{l_addr}_{l_port}"
            target_label = f"{f_addr}:{f_port}" if f_addr != "*" else f"{l_addr}:{l_port}"
            target_type = "local_ip"

        if target_node_id not in nodes_map:
            nodes_map[target_node_id] = {
                "id": target_node_id,
                "label": target_label,
                "name": f_addr if (is_external or f_addr != "*") else f"{l_addr}:{l_port}",
                "type": target_type,
                "is_external": is_external,
                "country_code": geo_info.get("country_code", "XX"),
                "country_name": geo_info.get("country_name", ""),
                "asn": geo_info.get("asn", ""),
                "asn_org": geo_info.get("asn_org", ""),
                "risk": "High" if is_suspicious else "Normal",
                "is_suspicious": is_suspicious,
                "connections": 0,
            }
        nodes_map[target_node_id]["connections"] += 1

        # 3. Edge
        edge_id = f"{proc_node_id}-->{target_node_id}_{proto}_{f_port or l_port}"
        edges.append(
            {
                "id": edge_id,
                "from": proc_node_id,
                "to": target_node_id,
                "proto": proto,
                "state": state,
                "port": f_port or l_port,
                "is_suspicious": is_suspicious,
                "label": f"{proto} {f_port or l_port} ({state})",
            }
        )

    # Prepare geo points list
    geo_points = []
    for pt in geo_points_map.values():
        geo_points.append(
            {
                "latitude": pt["latitude"],
                "longitude": pt["longitude"],
                "ip": pt["ip"],
                "country_code": pt["country_code"],
                "country_name": pt["country_name"],
                "city": pt["city"],
                "asn": pt["asn"],
                "asn_org": pt["asn_org"],
                "connections_count": pt["connections_count"],
                "processes": sorted(pt["processes"]),
                "ports": sorted(pt["ports"]),
                "is_suspicious": pt["is_suspicious"],
            }
        )

    # Summary metrics
    external_count = sum(1 for s in sockets if s["is_external"])
    listening_count = sum(1 for s in sockets if s["is_listening"])
    suspicious_count = sum(1 for s in sockets if s["is_suspicious"])
    countries_count = len({s["country_code"] for s in sockets if s["country_code"] != "XX"})

    return {
        "dump": {
            "name": dump.name,
            "index": dump.index,
            "operating_system": dump.operating_system,
        },
        "stats": {
            "total_sockets": len(sockets),
            "external_connections": external_count,
            "listening_ports": listening_count,
            "suspicious_connections": suspicious_count,
            "unique_countries": countries_count,
            "unique_remote_hosts": len(geoip_cache),
        },
        "nodes": list(nodes_map.values()),
        "edges": edges,
        "geo_points": geo_points,
        "sockets": sockets,
    }
