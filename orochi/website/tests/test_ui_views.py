import json
from pathlib import Path
from uuid import uuid4

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import (
    Bookmark,
    Case,
    Dump,
    Evidence,
    Finding,
    Folder,
    Plugin,
    Result,
    Value,
)

pytestmark = pytest.mark.django_db


def test_indices_view(client, admin, dump):
    client.force_login(admin)
    url = reverse("website:indices")
    response = client.get(url)
    assert response.status_code == 200
    assert dump.name in response.content.decode()


def test_parameters_view_get_and_htmx(client, admin, dump):
    client.force_login(admin)
    url = reverse("website:parameters")
    query_params = {
        "selected_plugin": "windows.pslist.PsList",
        "selected_indexes[]": [dump.index],
    }

    # Standard JSON GET
    response = client.get(url, query_params)
    assert response.status_code == 200
    assert "html_form" in response.json()

    # HTMX GET
    response = client.get(url, query_params, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert "<form" in response.content.decode()


def test_generate_special_columns(client, admin):
    client.force_login(admin)
    url = reverse("website:generate")

    # Non-AJAX request should return 405 Method Not Allowed
    resp = client.get(url)
    assert resp.status_code == 200
    assert resp.json().get("status_code") == 405

    # Loading placeholder
    resp = client.get(
        url,
        {"columns[]": ["Loading"], "draw": "1"},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["data"] == [["Please wait"]]

    # Empty placeholder
    resp = client.get(
        url,
        {"columns[]": ["Empty"], "draw": "2"},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["data"] == [["Empty data"]]


def test_generate_data_with_values(client, admin, dump, plugin):
    client.force_login(admin)
    url = reverse("website:generate")

    result = Result.objects.create(
        dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=result,
        value={"PID": 4, "ImageFileName": "System", "Offset": "0x1234"},
    )

    params = {
        "columns[]": ["PID", "ImageFileName"],
        "indexes[]": [dump.index],
        "plugin": plugin.name,
        "start": "0",
        "length": "10",
        "order[0][column]": "0",
        "order[0][dir]": "asc",
        "draw": "1",
        "search[value]": "",
    }
    resp = client.get(url, params, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["recordsTotal"] == 1
    assert data["recordsFiltered"] == 1
    assert len(data["data"]) == 1
    assert "4" in str(data["data"][0])


def test_tree_view(client, admin, dump, user):
    client.force_login(admin)
    p_tree, _ = Plugin.objects.get_or_create(
        name="linux.pstree.pstree", defaults={"operating_system": "Linux"}
    )
    result = Result.objects.create(
        dump=dump, plugin=p_tree, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=result,
        value={"PID": 100, "PPID": 1, "ImageFileName": "systemd"},
    )

    url = reverse("website:tree")
    params = {
        "plugin": "linux.pstree.pstree",
        "indexes[]": [dump.index],
    }
    resp = client.get(url, params)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["title"] == 100
    assert data[0]["PPID"] == 1

    # Unauthorized access check
    client.force_login(user)
    resp_unauth = client.get(url, params)
    assert resp_unauth.status_code == 200
    assert resp_unauth.json().get("status_code") == 403


def test_vt_view(client, admin, tmp_path):
    client.force_login(admin)
    url = reverse("website:vt")

    # Existing VT file
    vt_file = tmp_path / "vt_report.json"
    vt_file.write_text(json.dumps({"positives": 7, "total": 70}))

    resp = client.get(url, {"path": str(vt_file)})
    assert resp.status_code == 200
    assert "VirusTotal Report" in resp.content.decode()
    assert "positives" in resp.content.decode()

    # Non-existent VT file
    resp_missing = client.get(url, {"path": str(tmp_path / "non_existent.json")})
    assert resp_missing.status_code == 200
    assert "VT report not found" in resp_missing.content.decode()


def test_hex_view_and_hex_queries(client, admin, dump, user):
    client.force_login(admin)

    # 1. Hex view page
    hex_url = reverse("website:hex_view", kwargs={"index": dump.index})
    resp = client.get(hex_url)
    assert resp.status_code == 200
    assert dump.name in resp.content.decode()

    # 2. Get hex data chunk
    get_hex_url = reverse("website:get_hex", kwargs={"index": dump.index})
    resp = client.get(get_hex_url, {"start": 0, "length": 2, "draw": 1})
    assert resp.status_code == 200
    data = resp.json()
    assert "data" in data
    assert data["recordsTotal"] > 0

    # 3. Search hex data
    search_hex_url = reverse("website:search_hex", kwargs={"index": dump.index})
    # dump.upload contains b"file_content"
    resp = client.get(search_hex_url, {"findstr": "file", "last": -1})
    assert resp.status_code == 200
    assert resp.json()["found"] == 1
    assert resp.json()["pos"] == 0

    # Search for non-existent text
    resp_missing = client.get(
        search_hex_url, {"findstr": "not_present_xyz", "last": -1}
    )
    assert resp_missing.status_code == 200
    assert resp_missing.json()["found"] == -1

    # Unauthorized access
    client.force_login(user)
    resp_unauth = client.get(get_hex_url, {"start": 0, "length": 2, "draw": 1})
    assert resp_unauth.json().get("status_code") == 403

    resp_unauth_search = client.get(search_hex_url, {"findstr": "file", "last": -1})
    assert resp_unauth_search.json().get("status_code") == 403


def test_json_view(client, admin, dump, tmp_path):
    client.force_login(admin)
    # json_view requires filepath.split('/')[2] == dump.index
    target_dir = Path(f"tmp/dumps/{dump.index}")
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / "hive.json"
    target_file.write_text(json.dumps({"Root": {"Key": "Value"}}))

    try:
        url = reverse("website:json_view", kwargs={"filepath": str(target_file)})
        resp = client.get(url)
        assert resp.status_code == 200
        assert "Root" in resp.content.decode()
    finally:
        if target_file.exists():
            target_file.unlink()
        if target_dir.exists():
            target_dir.rmdir()


def test_diff_view(client, admin, dump, plugin, folder, user):
    client.force_login(admin)
    dump2 = Dump.objects.create(
        operating_system="Linux",
        name="test_dump2",
        index=str(uuid4()),
        author=admin,
        folder=folder,
        upload=SimpleUploadedFile("test2.raw", b"second_dump_content"),
    )
    assign_perm("can_see", admin, dump2)

    res1 = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res1, value={"PID": 1, "Name": "init"})

    res2 = Result.objects.create(
        dump=dump2, plugin=plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(result=res2, value={"PID": 1, "Name": "systemd"})

    url = reverse(
        "website:diff_view",
        kwargs={"index_a": dump.index, "index_b": dump2.index, "plugin": plugin.name},
    )
    resp = client.get(url)
    assert resp.status_code == 200
    assert "info_a" in resp.context
    assert "info_b" in resp.context
    assert "init" in resp.context["info_a"]
    assert "systemd" in resp.context["info_b"]

    # Unauthorized user returns 404
    client.force_login(user)
    resp_unauth = client.get(url)
    assert resp_unauth.status_code == 404


def test_bookmarks_navigation_and_edit(client, admin, dump, plugin, bookmark):
    client.force_login(admin)

    # 1. Navigation with indexes and plugin
    url_without_query = reverse(
        "website:bookmarks",
        kwargs={"indexes": dump.index, "plugin": plugin.name},
    )
    resp = client.get(url_without_query)
    assert resp.status_code == 200
    assert resp.context["selected_indexes"] == [dump.index]
    assert resp.context["selected_plugin"] == plugin.name

    # 2. Navigation with indexes, plugin and query
    url_with_query = reverse(
        "website:bookmarks",
        kwargs={"indexes": dump.index, "plugin": plugin.name, "query": "PID:4"},
    )
    resp = client.get(url_with_query)
    assert resp.status_code == 200
    assert resp.context["selected_query"] == "PID:4"

    # 3. Edit bookmark GET form
    edit_url = reverse("website:edit_bookmark")
    resp_edit = client.get(edit_url, {"pk": bookmark.pk})
    assert resp_edit.status_code == 200
    assert "html_form" in resp_edit.json()


def test_case_lifecycle(client, admin):
    client.force_login(admin)

    # 1. Case create GET
    resp_get = client.get(reverse("website:case_create"), HTTP_HX_REQUEST="true")
    assert resp_get.status_code == 200
    assert "<form" in resp_get.content.decode()

    # 2. Case create POST
    resp_post = client.post(
        reverse("website:case_create"),
        {
            "name": "Forensic Investigation Alpha",
            "description": "Analyzing suspicious activity",
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_post.status_code == 200
    assert "Case has been created" in resp_post.headers.get("HX-Trigger", "")
    case = Case.objects.get(name="Forensic Investigation Alpha", user=admin)

    # 3. Case detail
    resp_detail = client.get(reverse("website:case_detail", kwargs={"pk": case.pk}))
    assert resp_detail.status_code == 200
    assert case.name in resp_detail.content.decode()

    # 4. Case edit GET and POST
    resp_edit_get = client.get(
        reverse("website:case_edit"),
        {"pk": case.pk},
        HTTP_HX_REQUEST="true",
    )
    assert resp_edit_get.status_code == 200

    resp_edit_post = client.post(
        reverse("website:case_edit") + f"?pk={case.pk}",
        {
            "name": "Forensic Investigation Alpha (Updated)",
            "description": "Updated notes",
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_edit_post.status_code == 200
    case.refresh_from_db()
    assert case.name == "Forensic Investigation Alpha (Updated)"

    # 5. Case MITRE export
    resp_mitre = client.get(
        reverse("website:case_mitre_export", kwargs={"pk": case.pk})
    )
    assert resp_mitre.status_code == 200
    assert resp_mitre.headers.get("Content-Type") == "application/json"
    layer_data = json.loads(resp_mitre.content)
    assert "name" in layer_data
    assert "techniques" in layer_data

    # 6. Case delete
    resp_del = client.post(
        reverse("website:case_delete", kwargs={"pk": case.pk}),
        HTTP_HX_REQUEST="true",
    )
    assert resp_del.status_code == 200
    assert "Case has been deleted" in resp_del.headers.get("HX-Trigger", "")
    assert not Case.objects.filter(pk=case.pk).exists()


def test_evidence_and_finding_lifecycle(client, admin, dump):
    client.force_login(admin)
    case = Case.objects.create(name="Evidence Case", user=admin)

    # 1. Create Evidence
    resp_ev = client.post(
        reverse("website:evidence_create"),
        {
            "name": "Bash Process Evidence",
            "case": case.pk,
            "dump": dump.pk,
            "plugin": "linux.bash.Bash",
            "description": "Suspicious bash command execution",
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_ev.status_code == 200
    assert "Evidence has been created" in resp_ev.headers.get("HX-Trigger", "")
    evidence = Evidence.objects.get(name="Bash Process Evidence", case=case)

    # 2. Create Finding GET and POST
    resp_find_get = client.get(
        reverse("website:finding_create", kwargs={"evidence_pk": evidence.pk}),
        HTTP_HX_REQUEST="true",
    )
    assert resp_find_get.status_code == 200

    resp_find_post = client.post(
        reverse("website:finding_create", kwargs={"evidence_pk": evidence.pk}),
        {
            "severity": "High",
            "note": "Command injection via bash script",
            "mitre_attack_technique": "T1059.004",
            "evidence": evidence.pk,
            "case": case.pk,
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_find_post.status_code == 200
    assert "Finding has been created" in resp_find_post.headers.get("HX-Trigger", "")
    finding = Finding.objects.get(case=case, evidence=evidence)
    assert finding.severity == "High"
    assert finding.mitre_attack_technique == "T1059.004"

    # 3. Edit Finding GET and POST
    resp_find_edit_get = client.get(
        reverse("website:finding_edit", kwargs={"pk": finding.pk}),
        HTTP_HX_REQUEST="true",
    )
    assert resp_find_edit_get.status_code == 200

    resp_find_edit_post = client.post(
        reverse("website:finding_edit", kwargs={"pk": finding.pk}),
        {
            "severity": "Critical",
            "note": "Escalated to critical severity",
            "mitre_attack_technique": "T1059.004",
            "evidence": evidence.pk,
            "case": case.pk,
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_find_edit_post.status_code == 200
    finding.refresh_from_db()
    assert finding.severity == "Critical"

    # 4. Delete Finding POST
    resp_find_del = client.post(
        reverse("website:finding_delete", kwargs={"pk": finding.pk}),
        HTTP_HX_REQUEST="true",
    )
    assert resp_find_del.status_code == 200
    assert not Finding.objects.filter(pk=finding.pk).exists()


def test_symbols_views(client, admin):
    client.force_login(admin)

    # 1. list_symbols
    resp_list = client.get(reverse("website:list_symbols"))
    assert resp_list.status_code == 200
    assert "website/list_symbols.html" in [t.name for t in resp_list.templates]

    # 2. upload_symbols GET
    resp_sym = client.get(reverse("website:upload_symbols"))
    assert resp_sym.status_code == 200
    assert "html_form" in resp_sym.json()

    # 3. upload_packages GET
    resp_pkg = client.get(reverse("website:upload_packages"))
    assert resp_pkg.status_code == 200
    assert "html_form" in resp_pkg.json()

    # 4. download_isf GET
    resp_isf = client.get(reverse("website:download_isf"))
    assert resp_isf.status_code == 200
    assert "html_form" in resp_isf.json()
