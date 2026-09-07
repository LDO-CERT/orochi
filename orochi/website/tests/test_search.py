import pytest
from django.urls import reverse

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Case, Result, Value
from orochi.website.search import execute_vector_search

pytestmark = pytest.mark.django_db


def test_case_vector_search(admin):
    c1 = Case.objects.create(
        name="Operation Dragonfly",
        description="Investigation into advanced persistent threat intrusion",
        user=admin,
    )
    c2 = Case.objects.create(
        name="Ransomware Incident",
        description="LockBit payload executed on accounting workstation",
        user=admin,
    )

    res = execute_vector_search(admin, "Dragonfly", scope="cases")
    assert res["cases_count"] == 1
    assert res["cases"][0]["id"] == c1.pk

    res_desc = execute_vector_search(admin, "LockBit", scope="cases")
    assert res_desc["cases_count"] == 1
    assert res_desc["cases"][0]["id"] == c2.pk

    res_both = execute_vector_search(admin, "incident", scope="cases")
    assert res_both["cases_count"] == 1
    assert res_both["cases"][0]["id"] == c2.pk


def test_dump_vector_search(admin, dump):
    dump.comment = "Memory dump from production database node"
    dump.description = "Captured using LiME on Linux kernel 5.15"
    dump.md5 = "d41d8cd98f00b204e9800998ecf8427e"
    dump.save()

    res = execute_vector_search(admin, "production database", scope="dumps")
    assert res["dumps_count"] == 1
    assert res["dumps"][0]["id"] == dump.pk

    res_hash = execute_vector_search(
        admin, "d41d8cd98f00b204e9800998ecf8427e", scope="dumps"
    )
    assert res_hash["dumps_count"] == 1
    assert res_hash["dumps"][0]["id"] == dump.pk


def test_plugin_result_vector_search(admin, dump, plugin):
    res = Result.objects.create(
        dump=dump,
        plugin=plugin,
        result=RESULT_STATUS_SUCCESS,
    )
    v1 = Value.objects.create(
        result=res,
        value={
            "PID": 4040,
            "PPID": 1,
            "ImageFileName": "trojan_stealer.exe",
            "CommandLine": "/usr/bin/trojan_stealer --exfiltrate",
        },
    )

    search_res = execute_vector_search(admin, "stealer", scope="results")
    assert search_res["plugin_results_count"] == 1
    assert search_res["plugin_results"][0]["id"] == v1.pk
    assert search_res["plugin_results"][0]["dump_name"] == dump.name
    assert search_res["plugin_results"][0]["plugin_name"] == plugin.name
    assert "workbench_url" in search_res["plugin_results"][0]


def test_permission_isolation(user, admin, dump, plugin):
    # Admin owns a private case
    Case.objects.create(
        name="TopSecret Case Admin Only",
        description="Confidential forensic investigation",
        user=admin,
    )

    # Admin dump is only assigned can_see to admin (from conftest.py)
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res, value={"SecretKey": "supersecretkey123"})

    # Non-admin user searches for the secret case, dump, and plugin value
    user_search = execute_vector_search(user, "TopSecret", scope="all")
    assert user_search["total_count"] == 0
    assert user_search["cases_count"] == 0

    user_val_search = execute_vector_search(user, "supersecretkey123", scope="all")
    assert user_val_search["total_count"] == 0
    assert user_val_search["plugin_results_count"] == 0

    # Admin searches and sees both
    admin_search = execute_vector_search(admin, "TopSecret", scope="all")
    assert admin_search["cases_count"] == 1

    admin_val_search = execute_vector_search(admin, "supersecretkey123", scope="all")
    assert admin_val_search["plugin_results_count"] == 1


def test_global_search_view(client, admin):
    client.force_login(admin)
    case = Case.objects.create(name="ViewTest Forensic Investigation", user=admin)

    # HTML page request
    url = reverse("website:global_search")
    response = client.get(url, {"q": "ViewTest"})
    assert response.status_code == 200
    assert "ViewTest" in response.content.decode()
    assert "Forensic Investigation" in response.content.decode()

    # AJAX request
    ajax_resp = client.get(url, {"q": "ViewTest", "ajax": 1})
    assert ajax_resp.status_code == 200
    data = ajax_resp.json()
    assert data["cases_count"] == 1
    assert data["cases"][0]["name"] == case.name


def test_search_scopes(admin, dump, plugin):
    Case.objects.create(name="ScopeTarget Case", user=admin)
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res, value={"Name": "ScopeTarget Process"})

    # Only cases
    r_cases = execute_vector_search(admin, "ScopeTarget", scope="cases")
    assert r_cases["cases_count"] == 1
    assert r_cases["plugin_results_count"] == 0

    # Only plugin results
    r_results = execute_vector_search(admin, "ScopeTarget", scope="results")
    assert r_results["cases_count"] == 0
    assert r_results["plugin_results_count"] == 1


def test_add_to_existing_case_from_search(client, admin, dump, plugin):
    client.force_login(admin)
    case = Case.objects.create(name="Existing Case Test", user=admin)
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    v1 = Value.objects.create(
        result=res, value={"PID": 100, "ImageFileName": "proc1.exe"}
    )
    v2 = Value.objects.create(
        result=res, value={"PID": 200, "ImageFileName": "proc2.exe"}
    )

    url = reverse("website:add_to_case_from_search")
    payload = {
        "case_mode": "existing",
        "case_id": case.pk,
        "selected_values[]": [v1.pk, v2.pk],
        "notes": "Suspicious processes found in memory",
        "ajax": 1,
    }

    response = client.post(url, payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["evidences_count"] == 2
    assert case.evidences.count() == 2

    ev1 = case.evidences.filter(result_row__PID=100).first()
    assert ev1 is not None
    assert ev1.dump == dump
    assert ev1.plugin == plugin.name
    assert "proc1.exe" in ev1.name
    assert ev1.description == "Suspicious processes found in memory"


def test_create_new_case_from_search(client, admin, dump, plugin):
    client.force_login(admin)
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    v = Value.objects.create(result=res, value={"PID": 300, "Name": "malware.elf"})

    url = reverse("website:add_to_case_from_search")
    payload = {
        "case_mode": "new",
        "case_name": "Newly Created Case From Search",
        "case_description": "Auto-created from global search triage",
        "folder_name": "SearchTriageFolder",
        "is_ctf": "on",
        "selected_values[]": [v.pk],
        "notes": "Evidence note",
        "ajax": 1,
    }

    response = client.post(url, payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True

    created_case = Case.objects.get(name="Newly Created Case From Search", user=admin)
    assert created_case.description == "Auto-created from global search triage"
    assert created_case.folder.name == "SearchTriageFolder"
    assert created_case.is_ctf is True
    assert created_case.evidences.count() == 1


def test_add_dumps_to_case_from_search(client, admin, dump):
    client.force_login(admin)
    case = Case.objects.create(name="Dump Evidence Case", user=admin)

    url = reverse("website:add_to_case_from_search")
    payload = {
        "case_mode": "existing",
        "case_id": case.pk,
        "selected_dumps[]": [dump.pk],
        "notes": "Full dump evidence",
        "ajax": 1,
    }

    response = client.post(url, payload)
    assert response.status_code == 200
    assert case.evidences.count() == 1
    ev = case.evidences.first()
    assert ev.dump == dump
    assert "Dump: test_dump" in ev.name


def test_add_to_case_permission_check(client, user, admin, dump, plugin):
    client.force_login(user)
    # Case owned by admin
    admin_case = Case.objects.create(name="Admin Private Case", user=admin)
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    v = Value.objects.create(result=res, value={"PID": 999})

    url = reverse("website:add_to_case_from_search")
    # User cannot add to admin's private case
    payload = {
        "case_mode": "existing",
        "case_id": admin_case.pk,
        "selected_values[]": [v.pk],
        "ajax": 1,
    }

    resp = client.post(url, payload)
    assert resp.status_code == 404

    # User creates their own case, but tries to add a dump they cannot see
    user_case = Case.objects.create(name="User Case", user=user)
    payload_user = {
        "case_mode": "existing",
        "case_id": user_case.pk,
        "selected_values[]": [v.pk],
        "ajax": 1,
    }
    resp_user = client.post(url, payload_user)
    assert resp_user.status_code == 200
    # 0 evidences created because user has no can_see on dump
    assert resp_user.json()["evidences_count"] == 0
    assert user_case.evidences.count() == 0
