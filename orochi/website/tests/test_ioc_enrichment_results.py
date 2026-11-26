"""Enrichment reports what actually came back (#1548, found on the first real VirusTotal run)."""

from unittest.mock import MagicMock, patch

import pytest

from orochi.website.defaults import SERVICE_VIRUSTOTAL
from orochi.website.ioc import enrich_ioc, enrich_iocs
from orochi.website.models import DumpIOC, Service

pytestmark = pytest.mark.django_db


def _resp(status, body=None, headers=None):
    r = MagicMock(status_code=status, headers=headers or {}, text=str(body))
    r.json.return_value = body or {}
    return r


@pytest.fixture
def vt(db):
    return Service.objects.create(name=SERVICE_VIRUSTOTAL, url="-", key="k")


def _ioc(dump, value):
    return DumpIOC.objects.create(dump=dump, ioc_type="hash_sha256", value=value, source_plugin="dumpfiles", context={})


def test_unknown_hash_is_recorded_as_not_found(dump, vt):
    ioc = _ioc(dump, "a" * 64)
    with patch("orochi.website.ioc.requests.get", return_value=_resp(404)):
        enrich_ioc(ioc)
    ioc.refresh_from_db()
    assert ioc.enrichment["virustotal"]["found"] is False


def test_rate_limited_lookup_is_retried(dump, vt):
    ioc = _ioc(dump, "b" * 64)
    ok = _resp(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "undetected": 60}}}})
    with (
        patch("orochi.website.ioc.requests.get", side_effect=[_resp(429, headers={"Retry-After": "1"}), ok]) as get,
        patch("orochi.website.ioc.time.sleep") as sleep,
    ):
        enrich_ioc(ioc)
    ioc.refresh_from_db()
    assert get.call_count == 2 and sleep.call_args.args[0] == 1
    assert ioc.enrichment["virustotal"]["positives"] == 5 and ioc.is_malicious


def test_summary_counts_answers_unknowns_and_failures(dump, vt):
    iocs = [_ioc(dump, c * 64) for c in "cde"]
    answers = {
        "c" * 64: _resp(200, {"data": {"attributes": {"last_analysis_stats": {"undetected": 70}}}}),
        "d" * 64: _resp(404),
        "e" * 64: _resp(401, "WrongCredentialsError"),
    }
    with patch("orochi.website.ioc.requests.get", side_effect=lambda url, **kw: answers[url.rsplit("/", 1)[1]]):
        summary = enrich_iocs(iocs)
    assert (summary["answered"], summary["not_found"], summary["failed"]) == (1, 1, 1)
    assert summary["success"] is False and "1 failed" in summary["message"]


# AbuseIPDB, AlienVault OTX and GreyNoise (found on the first run with real keys)


@pytest.fixture
def ip_services(db):
    from orochi.website.defaults import SERVICE_ABUSEIPDB, SERVICE_GREYNOISE, SERVICE_OTX

    for name in (SERVICE_ABUSEIPDB, SERVICE_OTX, SERVICE_GREYNOISE):
        Service.objects.create(name=name, url="-", key="k")


def _ip(dump, value):
    return DumpIOC.objects.create(dump=dump, ioc_type="ip", value=value, source_plugin="netscan", context={})


def _by_provider(answers):
    def get(url, **kw):
        for host, resp in answers.items():
            if host in url:
                return resp
        raise AssertionError(url)

    return get


def test_ip_providers_record_results_unknowns_and_tor(dump, ip_services):
    ioc = _ip(dump, "185.220.101.45")
    answers = {
        "abuseipdb": _resp(200, {"data": {"abuseConfidenceScore": 100, "totalReports": 309, "isTor": True}}),
        "otx": _resp(200, {"pulse_info": {"count": 50, "pulses": []}}),
        "greynoise": _resp(200, {"classification": "malicious", "noise": True, "link": "https://viz/x"}),
    }
    with patch("orochi.website.ioc.requests.get", side_effect=_by_provider(answers)):
        enrich_ioc(ioc)
    ioc.refresh_from_db()
    e = ioc.enrichment
    assert e["abuseipdb"]["found"] and e["abuseipdb"]["is_tor"] and e["abuseipdb"]["abuse_score"] == 100
    assert e["otx"]["pulse_count"] == 50 and e["greynoise"]["classification"] == "malicious"
    assert ioc.is_malicious and ioc.threat_score >= 90


def test_greynoise_unknown_ip_is_not_seen_and_errors_are_kept(dump, ip_services):
    ioc = _ip(dump, "91.214.124.88")
    answers = {
        "abuseipdb": _resp(401, "invalid key"),
        "otx": _resp(200, {"pulse_info": {"count": 0, "pulses": []}}),
        "greynoise": _resp(404, {"message": "IP not observed scanning the internet."}),
    }
    with patch("orochi.website.ioc.requests.get", side_effect=_by_provider(answers)):
        summary = enrich_iocs([ioc])
    ioc.refresh_from_db()
    e = ioc.enrichment
    assert e["greynoise"]["found"] is False and "not observed" in e["greynoise"]["message"]
    assert e["abuseipdb"]["error"].startswith("HTTP 401")
    assert summary["failed"] == 1 and not ioc.is_malicious


def test_network_error_is_recorded_not_swallowed(dump, ip_services):
    import requests

    ioc = _ip(dump, "203.0.113.9")
    with patch("orochi.website.ioc.requests.get", side_effect=requests.ConnectionError("unreachable")):
        summary = enrich_iocs([ioc])
    ioc.refresh_from_db()
    assert {k for k, v in ioc.enrichment.items() if v.get("error")} == {"abuseipdb", "otx", "greynoise"}
    assert summary["failed"] == 1


def test_hub_shows_not_seen_and_error_badges(client, admin, dump, ip_services):
    from django.urls import reverse

    DumpIOC.objects.create(
        dump=dump,
        ioc_type="ip",
        value="91.214.124.88",
        source_plugin="netscan",
        context={},
        enrichment={
            "greynoise": {"found": False, "message": "IP not observed", "permalink": "https://viz/x"},
            "abuseipdb": {"error": "HTTP 429: too many"},
        },
    )
    client.force_login(admin)
    html = client.get(
        reverse("website:dump_iocs", kwargs={"index": dump.index}), HTTP_HX_REQUEST="true"
    ).content.decode()
    assert "GreyNoise: not seen" in html and "AbuseIPDB: error" in html and "HTTP 429: too many" in html
