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
