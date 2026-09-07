import pytest
from django.urls import reverse

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Case, Dump, Result, Value

pytestmark = pytest.mark.django_db


def test_api_search_unauthenticated(client):
    response = client.get("/api/search/?q=malware")
    assert response.status_code in (401, 403)


def test_api_search_authenticated(client, admin, dump, plugin):
    client.force_login(admin)

    # Setup test entities
    case = Case.objects.create(
        name="ApiSearch APT Case", description="In-depth analysis", user=admin
    )
    dump.name = "ApiSearch Windows Server"
    dump.save()
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    val = Value.objects.create(
        result=res, value={"PID": 9999, "Name": "apisearch_payload.dll"}
    )

    # Global search across all data
    response = client.get("/api/search/?q=ApiSearch")
    assert response.status_code == 200
    data = response.json()

    assert data["query"] == "ApiSearch"
    assert data["total_count"] >= 3
    assert data["cases_count"] >= 1
    assert any(c["id"] == case.pk for c in data["cases"])
    assert data["dumps_count"] >= 1
    assert any(d["id"] == dump.pk for d in data["dumps"])
    assert data["plugin_results_count"] >= 1
    assert any(r["id"] == val.pk for r in data["plugin_results"])


def test_api_search_scopes(client, admin, dump, plugin):
    client.force_login(admin)
    Case.objects.create(name="ScopedApi UniqueCase", user=admin)
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res, value={"Name": "ScopedApi UniqueProcess"})

    # Cases scope
    resp_cases = client.get("/api/search/?q=ScopedApi&scope=cases")
    assert resp_cases.status_code == 200
    data_cases = resp_cases.json()
    assert data_cases["cases_count"] == 1
    assert data_cases["plugin_results_count"] == 0

    # Results scope
    resp_res = client.get("/api/search/?q=ScopedApi&scope=results")
    assert resp_res.status_code == 200
    data_res = resp_res.json()
    assert data_res["cases_count"] == 0
    assert data_res["plugin_results_count"] == 1
