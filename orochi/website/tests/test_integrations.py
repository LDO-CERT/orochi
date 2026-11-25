import pytest
from django.urls import reverse

from orochi.website import integrations, notifications
from orochi.website.defaults import SERVICE_SIEM, SERVICE_THEHIVE, SERVICE_WEBHOOK
from orochi.website.models import Case, DumpIOC, Finding, Service

pytestmark = pytest.mark.django_db


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body or {}
        self.content = b"{}"
        self.text = "{}"

    def json(self):
        return self._body


@pytest.fixture
def http(monkeypatch):
    """Record outgoing requests.post calls and answer from a queue (default 200)."""
    calls, responses = [], []

    def fake_post(url, **kwargs):
        calls.append({"url": url, **kwargs})
        return responses.pop(0) if responses else FakeResponse()

    monkeypatch.setattr(integrations.requests, "post", fake_post)
    monkeypatch.setattr(notifications.requests, "post", fake_post)
    return calls, responses


@pytest.fixture
def case_with_findings(user, dump):
    case = Case.objects.create(name="Incident 42", user=user, folder=dump.folder)
    Finding.objects.create(case=case, severity="Critical", note="beacon", mitre_attack_technique="T1071", tags=["c2"])
    DumpIOC.objects.create(dump=dump, ioc_type="ip", value="203.0.113.7", source_plugin="netscan", threat_score=90)
    return case


@pytest.mark.parametrize(
    ("url", "proxy", "provider", "expected_provider", "expected_auth"),
    [
        ("https://splunk.local:8088/services/collector/event", None, None, "splunk", "Splunk tok"),
        ("https://es.local:9200/orochi/_doc", None, None, "elastic", "ApiKey tok"),
        ("https://dce.ingest.monitor.azure.com/dataCollectionRules/x", None, None, "sentinel", "Bearer tok"),
        # Provider stored in the Service proxy JSON wins over URL heuristics
        ("https://siem.local:9200/x", {"provider": "splunk"}, None, "splunk", "Splunk tok"),
        # Explicit provider wins over everything
        ("https://siem.local:8088/x", {"provider": "splunk"}, "elastic", "elastic", "ApiKey tok"),
    ],
)
def test_forward_to_siem_provider_selection(http, url, proxy, provider, expected_provider, expected_auth):
    calls, _ = http
    svc = Service.objects.create(name=SERVICE_SIEM, url=url, key="tok", proxy=proxy)
    res = integrations.forward_to_siem({"event": "x", "title": "t"}, provider=provider, service=svc)
    assert res["provider"] == expected_provider
    assert calls[0]["headers"]["Authorization"] == expected_auth
    assert calls[0]["verify"] is True
    assert calls[0]["proxies"] is None  # "provider" is not a proxy
    if expected_provider == "sentinel":
        assert isinstance(calls[0]["json"], list)
    elif expected_provider == "splunk":
        assert calls[0]["json"]["event"]["title"] == "t"


def test_forward_to_siem_keeps_full_authorization_value(http):
    calls, _ = http
    svc = Service.objects.create(name=SERVICE_SIEM, url="https://es.local:9200/_doc", key="Bearer abc")
    integrations.forward_to_siem({"event": "x"}, service=svc)
    assert calls[0]["headers"]["Authorization"] == "Bearer abc"


def test_case_siem_forward_endpoint(client, user, case_with_findings, http):
    calls, responses = http
    Service.objects.create(name=SERVICE_SIEM, url="https://splunk.local:8088/services/collector/event", key="tok")
    client.force_login(user)
    url = f"/api/cases/{case_with_findings.pk}/siem/forward"

    resp = client.post(url)
    assert resp.status_code == 200
    event = calls[0]["json"]["event"]
    assert event["severity"] == "Critical"
    assert event["iocs"][0]["value"] == "203.0.113.7"

    responses.append(FakeResponse(status_code=403))
    assert client.post(url).status_code == 502


def test_case_siem_forward_requires_service(client, user, case_with_findings):
    client.force_login(user)
    resp = client.post(f"/api/cases/{case_with_findings.pk}/siem/forward")
    assert resp.status_code == 400


def test_thehive_payload(case_with_findings):
    payload = integrations.build_thehive_case_payload(case_with_findings)
    assert payload["severity"] == 4
    assert "mitre:T1071" in payload["tags"] and "c2" in payload["tags"]
    assert payload["observables"][0]["dataType"] == "ip"
    assert payload["tasks"][0]["title"].startswith("[Critical]")


@pytest.mark.parametrize(
    "configured_url", ["https://hive.local", "https://hive.local/", "https://hive.local/api/v1/case"]
)
def test_thehive_export_pushes_case_and_observables(http, case_with_findings, configured_url):
    calls, responses = http
    Service.objects.create(name=SERVICE_THEHIVE, url=configured_url, key="hivekey")
    responses.append(FakeResponse(201, {"_id": "~123"}))

    res = integrations.export_case_to_thehive(case_with_findings)

    assert res["thehive_case_id"] == "~123"
    assert res["exported_observables"] == 1
    assert calls[0]["url"] == "https://hive.local/api/v1/case"
    assert "observables" not in calls[0]["json"]
    assert calls[1]["url"] == "https://hive.local/api/v1/case/~123/observable"
    assert calls[0]["headers"]["Authorization"] == "Bearer hivekey"


def test_thehive_export_without_push_makes_no_request(http, case_with_findings):
    calls, _ = http
    res = integrations.export_case_to_thehive(case_with_findings, push=False)
    assert res["pushed"] is False
    assert calls == []


def test_thehive_export_endpoint_errors(client, user, case_with_findings, http):
    calls, responses = http
    client.force_login(user)
    url = f"/api/cases/{case_with_findings.pk}/export/thehive"
    assert client.post(url).status_code == 400  # not configured

    Service.objects.create(name=SERVICE_THEHIVE, url="https://hive.local", key="k")
    responses.append(FakeResponse(500))
    assert client.post(url).status_code == 400


def test_integrations_respect_case_permissions(client, readonly_user, case_with_findings):
    client.force_login(readonly_user)
    assert client.post(f"/api/cases/{case_with_findings.pk}/siem/forward").status_code in (403, 404)
    assert client.post(f"/api/cases/{case_with_findings.pk}/export/thehive").status_code in (403, 404)


def test_siem_receives_events_even_without_personal_notifications(http, user):
    calls, _ = http
    Service.objects.create(name=SERVICE_SIEM, url="https://splunk.local:8088/services/collector/event", key="t")
    Service.objects.create(name=SERVICE_WEBHOOK, url="https://hooks.local/x", key="")
    user.enable_notifications = False
    user.notify_via_webhook = True
    user.save()

    notifications.send_external_notifications(user, "Dump ready", "done")

    assert [c["url"] for c in calls] == ["https://splunk.local:8088/services/collector/event"]


def test_case_page_shows_buttons_only_for_configured_integrations(client, user, case_with_findings):
    client.force_login(user)
    url = reverse("website:case_detail", args=[case_with_findings.pk])

    page = client.get(url, HTTP_HX_REQUEST="true").content.decode()
    assert "/export/thehive" not in page
    assert "/siem/forward" not in page

    Service.objects.create(name=SERVICE_THEHIVE, url="https://hive.local", key="k")
    page = client.get(url, HTTP_HX_REQUEST="true").content.decode()
    assert f"/api/cases/{case_with_findings.pk}/export/thehive" in page
    assert "/siem/forward" not in page
