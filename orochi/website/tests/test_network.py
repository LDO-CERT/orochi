from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Dump, Plugin, Result, TriageFinding, Value
from orochi.website.network import extract_network_report, is_external_ip, resolve_geoip

pytestmark = pytest.mark.django_db
User = get_user_model()


@pytest.fixture
def network_dump(admin):
    dump = Dump.objects.create(
        index="test_dump_net_123",
        name="network_host.raw",
        author=admin,
        operating_system="Windows",
        color="#06b6d4",
    )
    assign_perm("website.can_see", admin, dump)
    return dump


def test_is_external_ip():
    """Verify private, loopback, multicast, and bogons are filtered correctly."""
    assert not is_external_ip("127.0.0.1")
    assert not is_external_ip("192.168.1.50")
    assert not is_external_ip("10.0.0.1")
    assert not is_external_ip("172.16.5.10")
    assert not is_external_ip("0.0.0.0")
    assert not is_external_ip("*")
    assert not is_external_ip("::1")
    assert not is_external_ip("invalid_ip")

    # Public routable IPs
    assert is_external_ip("8.8.8.8")
    assert is_external_ip("185.199.108.153")
    assert is_external_ip("1.1.1.1")


@patch("pathlib.Path.exists", return_value=False)
def test_resolve_geoip_fallback(mock_exists):
    """Verify resolve_geoip returns clean default when databases are not present."""
    res = resolve_geoip("8.8.8.8")
    assert res["country_code"] == "XX"
    assert res["country_name"] == "Unknown"
    assert res["latitude"] is None


def test_extract_network_report_windows(network_dump):
    """Test full network report extraction from windows.netscan.NetScan output."""
    p_netscan = Plugin.objects.create(name="windows.netscan.NetScan", operating_system="Windows")
    res_netscan = Result.objects.create(dump=network_dump, plugin=p_netscan, result=RESULT_STATUS_SUCCESS)

    # 1. Normal listening socket
    Value.objects.create(
        result=res_netscan,
        value={
            "Proto": "TCP",
            "LocalAddr": "0.0.0.0",
            "LocalPort": 445,
            "ForeignAddr": "*",
            "ForeignPort": 0,
            "State": "LISTENING",
            "PID": 4,
            "Owner": "System",
        },
    )

    # 2. External connection to high-risk C2 port
    Value.objects.create(
        result=res_netscan,
        value={
            "Proto": "TCP",
            "LocalAddr": "192.168.1.100",
            "LocalPort": 49152,
            "ForeignAddr": "185.199.108.153",
            "ForeignPort": 4444,
            "State": "ESTABLISHED",
            "PID": 1337,
            "Owner": "powershell.exe",
        },
    )

    # 3. Add TriageFinding for PID 1337
    TriageFinding.objects.create(
        dump=network_dump,
        rule_id="NET_SUSPICIOUS_C2",
        rule_name="Suspicious C2 Socket",
        category="Network & C2",
        severity="Critical",
        score=40,
        raw_data={"PID": 1337, "ForeignPort": 4444},
    )

    report = extract_network_report(network_dump)

    assert report["dump"]["index"] == network_dump.index
    assert report["stats"]["total_sockets"] == 2
    assert report["stats"]["external_connections"] == 1
    assert report["stats"]["listening_ports"] == 1
    assert report["stats"]["suspicious_connections"] == 1

    # Check sockets
    c2_socket = next(s for s in report["sockets"] if s["pid"] == 1337)
    assert c2_socket["is_external"] is True
    assert c2_socket["is_suspicious"] is True
    assert c2_socket["foreign_port"] == 4444

    # Check nodes
    proc_node = next(n for n in report["nodes"] if n["type"] == "process" and n["pid"] == 1337)
    assert proc_node["risk"] == "Critical"
    assert proc_node["is_suspicious"] is True

    # Check edges
    c2_edge = next(e for e in report["edges"] if e["port"] == 4444)
    assert c2_edge["is_suspicious"] is True


def test_dump_network_views(client, admin, network_dump):
    """Test HTML and HTMX partial views for network topology."""
    client.force_login(admin)

    # 1. Full page view
    url = reverse("website:dump_network", kwargs={"index": network_dump.index})
    resp = client.get(url)
    assert resp.status_code == 200
    content = resp.content.decode()
    assert "Network Connection Graph & Geo-Map" in content
    assert "net-topology-canvas" in content
    # Ensure json_script tag contains direct JSON object (not double-encoded JSON string)
    assert '<script id="network-data-json" type="application/json">{"dump":' in content

    # 2. HTMX partial view
    partial_url = reverse("website:partial_dump_network", kwargs={"index": network_dump.index})
    partial_resp = client.get(partial_url)
    assert partial_resp.status_code == 200
    partial_content = partial_resp.content.decode()
    assert "network-hub-root" in partial_content
    assert '<script id="network-data-json" type="application/json">{"dump":' in partial_content


def test_dump_network_api(client, admin, network_dump):
    """Test Ninja API endpoint GET /api/dumps/{index}/network."""
    client.force_login(admin)

    # Seed netscan socket
    p_netscan = Plugin.objects.create(name="windows.netscan.NetScan", operating_system="Windows")
    res_netscan = Result.objects.create(dump=network_dump, plugin=p_netscan, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res_netscan,
        value={
            "Proto": "TCP",
            "LocalAddr": "0.0.0.0",
            "LocalPort": 80,
            "ForeignAddr": "*",
            "ForeignPort": 0,
            "State": "LISTENING",
            "PID": 100,
            "Owner": "httpd.exe",
        },
    )

    resp = client.get(f"/api/dumps/{network_dump.index}/network")
    assert resp.status_code == 200
    data = resp.json()
    assert data["dump"]["name"] == network_dump.name
    assert data["stats"]["total_sockets"] == 1
    assert data["stats"]["listening_ports"] == 1
    assert len(data["sockets"]) == 1
    assert data["sockets"][0]["process"] == "httpd.exe"
