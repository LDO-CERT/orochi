import base64
import json
from pathlib import Path
from uuid import uuid4

import pytest
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import (
    Case,
    Dump,
    Evidence,
    Finding,
    Host,
    Plugin,
    Result,
    TimelineEvent,
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


def test_temporal_diff_view(client, admin, dump, plugin, folder, user):
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

    ps_plugin, _ = Plugin.objects.get_or_create(
        name="linux.pslist.PsList", operating_system="Linux"
    )
    res1 = Result.objects.create(
        dump=dump, plugin=ps_plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(result=res1, value={"PID": 1, "COMM": "init"})

    res2 = Result.objects.create(
        dump=dump2, plugin=ps_plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(result=res2, value={"PID": 1, "COMM": "init"})
    Value.objects.create(result=res2, value={"PID": 999, "COMM": "backdoor"})

    url = reverse(
        "website:temporal_diff",
        kwargs={"index_a": dump.index, "index_b": dump2.index},
    )
    resp = client.get(url)
    assert resp.status_code == 200
    assert "diff" in resp.context
    assert resp.context["diff"]["summary"]["new_processes"] == 1
    assert "backdoor" in resp.content.decode()

    # Test reverse parameter
    resp_rev = client.get(f"{url}?reverse=1")
    assert resp_rev.status_code == 200
    assert resp_rev.context["reverse_order"] is True

    # Unauthorized user returns 404
    client.force_login(user)
    resp_unauth = client.get(url)
    assert resp_unauth.status_code == 404

    # Non-existent dump returns 404
    client.force_login(admin)
    url_bad = reverse(
        "website:temporal_diff",
        kwargs={"index_a": dump.index, "index_b": str(uuid4())},
    )
    resp_bad = client.get(url_bad)
    assert resp_bad.status_code == 404


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


def test_case_status_and_collaborators(client, admin, user):
    client.force_login(admin)

    # 1. Create case with collaborator and status
    resp_create = client.post(
        reverse("website:case_create"),
        {
            "name": "Collaborative Case",
            "description": "Joint investigation",
            "status": "Open",
            "collaborators": [user.pk],
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_create.status_code == 200
    case = Case.objects.get(name="Collaborative Case", user=admin)
    assert user in case.collaborators.all()
    assert case.status == "Open"

    # 2. Case detail renders owner, collaborator, and status
    resp_detail = client.get(reverse("website:case_detail", kwargs={"pk": case.pk}))
    assert resp_detail.status_code == 200
    content = resp_detail.content.decode()
    assert admin.username in content
    assert user.username in content
    assert "Open" in content

    # 3. Change status via case_change_status: Close case
    resp_close = client.post(
        reverse("website:case_change_status", kwargs={"pk": case.pk}),
        {"status": "Closed"},
    )
    assert resp_close.status_code == 200
    assert "Case status updated to Closed" in resp_close.headers.get("HX-Trigger", "")
    case.refresh_from_db()
    assert case.status == "Closed"

    # 4. Change status to In Progress
    resp_prog = client.post(
        reverse("website:case_change_status", kwargs={"pk": case.pk}),
        {"status": "In Progress"},
    )
    assert resp_prog.status_code == 200
    case.refresh_from_db()
    assert case.status == "In Progress"

    # 5. Invalid status returns 400
    resp_bad = client.post(
        reverse("website:case_change_status", kwargs={"pk": case.pk}),
        {"status": "InvalidStatusXYZ"},
    )
    assert resp_bad.status_code == 400

    # 6. Collaborator can view case_detail
    client.force_login(user)
    resp_collab_detail = client.get(
        reverse("website:case_detail", kwargs={"pk": case.pk})
    )
    assert resp_collab_detail.status_code == 200

    # 7. Collaborator can change status (e.g. back to Closed)
    resp_collab_close = client.post(
        reverse("website:case_change_status", kwargs={"pk": case.pk}),
        {"status": "Closed"},
    )
    assert resp_collab_close.status_code == 200
    case.refresh_from_db()
    assert case.status == "Closed"

    # 8. Collaborator sees case in their index
    resp_index = client.get(reverse("website:index"))
    assert resp_index.status_code == 200
    assert case in resp_index.context["cases"]


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


def test_evidence_create_with_uuid_and_auto_name(client, admin, dump):
    client.force_login(admin)
    case = Case.objects.create(name="Forensic Case UUID", user=admin)

    # 1. Test GET modal with UUID dump index, case, and encoded result_row in query params
    encoded_row = base64.b64encode(
        json.dumps({"PID": 9999, "ImageFileName": "malware.exe"}).encode("utf-8")
    ).decode("utf-8")
    resp_get = client.get(
        reverse("website:evidence_create")
        + f"?dump={dump.index}&plugin=windows.pslist&case={case.pk}&result_row={encoded_row}",
        HTTP_HX_REQUEST="true",
    )
    assert resp_get.status_code == 200
    content_get = resp_get.content.decode("utf-8")
    assert f'value="{dump.pk}"' in content_get
    assert f'value="{case.name}"' in content_get
    assert 'id="cases_datalist"' in content_get
    assert "setupCaseAutocomplete('id_case', 'cases_datalist')" in content_get

    # 2. Test POST with dump.index (UUID) and blank name - auto name generation
    resp_post = client.post(
        reverse("website:evidence_create"),
        {
            "name": "",  # Blank name -> should auto-generate
            "case": case.pk,
            "dump": str(dump.index),  # UUID string as sent from row_actions
            "plugin": "windows.pslist",
            "result_row": json.dumps({"PID": 9999, "ImageFileName": "malware.exe"}),
            "description": "Suspicious process",
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_post.status_code == 200
    trigger = json.loads(resp_post.headers.get("HX-Trigger", "{}"))
    assert trigger.get("showMessage", {}).get("type") == "success"
    assert trigger.get("closeModal") is True
    assert trigger.get("refreshCaseDetail") is True

    evidence = Evidence.objects.get(case=case)
    assert evidence.dump == dump
    assert evidence.plugin == "windows.pslist"
    assert evidence.result_row == {"PID": 9999, "ImageFileName": "malware.exe"}
    assert evidence.name == f"[windows.pslist] ImageFileName:malware.exe ({dump.name})"

    # 3. Test POST validation error: missing required case should render error without silent failure
    resp_invalid = client.post(
        reverse("website:evidence_create"),
        {
            "name": "Failed Evidence",
            "case": "",
            "dump": str(dump.index),
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_invalid.status_code == 200
    assert "HX-Trigger" not in resp_invalid.headers
    content_invalid = resp_invalid.content.decode("utf-8")
    assert "has-error" in content_invalid
    assert "This field is required." in content_invalid

    # 4. Test POST creating a brand new case on-the-fly
    resp_new_case = client.post(
        reverse("website:evidence_create"),
        {
            "name": "Evidence in Brand New Case",
            "case": "Brand New Dynamic Case",
            "dump": str(dump.index),
            "plugin": "windows.pslist",
            "result_row": json.dumps({"PID": 1234, "ImageFileName": "cmd.exe"}),
            "description": "Dynamic case test",
        },
        HTTP_HX_REQUEST="true",
    )
    assert resp_new_case.status_code == 200
    new_case = Case.objects.get(name="Brand New Dynamic Case", user=admin)
    assert Evidence.objects.filter(
        case=new_case, name="Evidence in Brand New Case"
    ).exists()


def test_evidence_delete_and_timeline_cleanup(client, admin, dump):
    client.force_login(admin)
    case = Case.objects.create(name="Evidence Test Case", user=admin)

    # 1. Create Evidence -> generates TimelineEvent
    evidence = Evidence.objects.create(
        name="Test Evidence For Deletion",
        case=case,
        dump=dump,
    )
    assert Evidence.objects.filter(pk=evidence.pk).exists()
    assert TimelineEvent.objects.filter(
        source_evidence=evidence, event_type="Evidence Added"
    ).exists()

    # 2. Delete Evidence via view
    resp_del = client.post(
        reverse("website:evidence_delete", kwargs={"pk": evidence.pk}),
        HTTP_HX_REQUEST="true",
    )
    assert resp_del.status_code == 200
    trigger = json.loads(resp_del.headers.get("HX-Trigger", "{}"))
    assert trigger.get("showMessage", {}).get("type") == "success"
    assert trigger.get("refreshCaseDetail") is True

    # 3. Verify Evidence is deleted AND associated TimelineEvent is removed
    assert not Evidence.objects.filter(pk=evidence.pk).exists()
    assert not TimelineEvent.objects.filter(
        source_evidence=evidence, event_type="Evidence Added"
    ).exists()
    assert not TimelineEvent.objects.filter(
        case=case, event_type="Evidence Added"
    ).exists()


def test_dump_upload_folder_and_host_autocomplete(client, admin, dump):
    client.force_login(admin)
    Host.objects.create(name="workstation-99")

    # 1. Check create dump dialog contains setupFolderAutocomplete and setupHostAutocomplete
    resp_create = client.get(reverse("website:index_create"))
    assert resp_create.status_code == 200
    html_create = resp_create.json().get("html_form", "")
    assert "setupFolderAutocomplete('id_folder', 'folders_list')" in html_create
    assert "setupHostAutocomplete('id_host', 'hosts_list')" in html_create
    assert 'id="folders_list"' in html_create
    assert 'id="hosts_list"' in html_create
    assert "workstation-99" in html_create

    # 2. Check edit dump dialog contains setupFolderAutocomplete and setupHostAutocomplete
    resp_edit = client.get(reverse("website:index_edit") + f"?index={dump.index}")
    assert resp_edit.status_code == 200
    html_edit = resp_edit.json().get("html_form", "")
    assert "setupFolderAutocomplete('id_folder', 'folders_list')" in html_edit
    assert "setupHostAutocomplete('id_host', 'hosts_list')" in html_edit
    assert 'id="folders_list"' in html_edit
    assert 'id="hosts_list"' in html_edit


def test_dump_creation_mutual_exclusivity(client, admin):
    client.force_login(admin)
    resp = client.get(reverse("website:index_create"))
    assert resp.status_code == 200
    html = resp.json().get("html_form", "")

    # Check field containers for upload and local_folder
    assert 'id="field_container_upload"' in html
    assert 'id="field_container_local_folder"' in html

    # Check mutual exclusivity logic
    assert "function deleteUploadedFile()" in html
    assert "function onFileUploadingOrUploaded()" in html
    assert "function onFileUploadRemoved()" in html
    assert "function updateSubmitButtonState()" in html
    assert "#field_container_local_folder" in html
    assert "deleteUploadedFile();" in html

    # Check index.html mutual exclusivity integration
    resp_index = client.get(reverse("website:index"))
    assert resp_index.status_code == 200
    index_content = resp_index.content.decode("utf-8")
    assert "MUTUAL EXCLUSIVITY BETWEEN LOCAL FOLDER & UPLOAD" in index_content
    assert "deleteUploadedFile" in index_content


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


def test_case_detail_htmx_swap_and_indices_markup(client, admin, dump):
    client.force_login(admin)
    case = Case.objects.create(name="Investigation Alpha", user=admin)

    # 1. Cases list rendered in index should swap innerHTML into #main_stage, include case-item class, and render empty stage
    resp_cases = client.get(reverse("website:index"))
    assert resp_cases.status_code == 200
    content_cases = resp_cases.content.decode()
    assert 'hx-target="#main_stage"' in content_cases
    assert 'hx-swap="innerHTML"' in content_cases
    assert 'class="case-item' in content_cases
    assert f'data-case-id="{case.pk}"' in content_cases
    assert 'id="empty_stage"' in content_cases
    assert 'id="tmpl_empty_stage"' in content_cases
    assert "deselectCase" in content_cases
    assert "renderEmptyStage" in content_cases
    assert "Select index(es) and plugin!" not in content_cases

    # 2. Case detail via HTMX should render root id="case_detail_view", close button, and evidence delete action
    ev = Evidence.objects.create(name="Sample Ev", case=case, dump=dump)
    resp_case_detail = client.get(
        reverse("website:case_detail", kwargs={"pk": case.pk}),
        HTTP_HX_REQUEST="true",
    )
    assert resp_case_detail.status_code == 200
    content_detail = resp_case_detail.content.decode()
    assert 'id="case_detail_view"' in content_detail
    assert 'id="btn_close_case"' in content_detail
    assert 'id="main_stage"' not in content_detail
    assert reverse("website:evidence_delete", kwargs={"pk": ev.pk}) in content_detail

    # 3. Indices list should render recognizable dump markers (dump_title, check_icon inside color_box, --dump-color)
    resp_indices = client.get(reverse("website:indices"))
    assert resp_indices.status_code == 200
    content_indices = resp_indices.content.decode()
    assert "dump_container" in content_indices
    assert "color_box" in content_indices
    assert "check_icon" in content_indices
    assert "dump_title" in content_indices
    assert "--dump-color:" in content_indices


def test_analysis_and_note_table_styles(client, admin, dump, plugin):
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)

    # 1. Test analysis view renders container card and datatables element
    resp_analysis = client.get(
        reverse("website:analysis"),
        {
            "plugin": plugin.name,
            "indexes[]": [dump.index],
        },
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp_analysis.status_code == 200
    content_analysis = resp_analysis.content.decode()
    assert "id='example'" in content_analysis or 'id="example"' in content_analysis
    assert "rounded-2xl" in content_analysis
    assert "border-zinc-200" in content_analysis
    assert "list-dump" in content_analysis
    assert "text-amber-500" in content_analysis  # Bookmark icon color
    assert "text-blue-500" in content_analysis  # Compare icon color

    # 2. Test index view contains modernized datatables export buttons and pagination icons
    resp_index = client.get(reverse("website:index"))
    assert resp_index.status_code == 200
    content_index = resp_index.content.decode()
    assert "dt-btn-export" in content_index
    assert "fa-file-csv" in content_index
    assert "fa-file-excel" in content_index
    assert "No data available in table" in content_index
    assert "fa-database" in content_index


def test_toast_swal_styles_and_container_transparency(client, admin):
    client.force_login(admin)
    resp = client.get(reverse("website:index"))
    assert resp.status_code == 200
    content = resp.content.decode()

    # Verify cache buster version
    assert "style.css?v=20260907_2" in content
    # Verify backdrop: false in toast helper
    assert "backdrop: false" in content

    # Verify style.css rules for toast transparent backdrop
    css_path = Path("orochi/static/css/style.css")
    css_content = css_path.read_text()
    assert "body.swal2-toast-shown .swal2-container" in css_content
    assert "backdrop-filter: none !important" in css_content
    assert "pointer-events: none !important" in css_content


def test_custom_plugin_gui_widgets(client, admin, dump):
    client.force_login(admin)
    url_analysis = reverse("website:analysis")

    # 1. Terminal replay widget with linux.bash.Bash
    bash_plugin, _ = Plugin.objects.get_or_create(
        name="linux.bash.Bash", operating_system="Linux"
    )
    res_bash = Result.objects.create(
        dump=dump, plugin=bash_plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=res_bash,
        value={
            "PID": 101,
            "Process": "bash",
            "Command": "whoami",
            "CommandTime": "2026-09-07T10:00:00Z",
        },
    )
    Value.objects.create(
        result=res_bash,
        value={
            "PID": 101,
            "Process": "bash",
            "Command": "id",
            "CommandTime": "2026-09-07T10:00:05Z",
        },
    )

    resp = client.get(
        url_analysis,
        {"indexes[]": [dump.index], "plugin": bash_plugin.name},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    content = resp.content.decode()
    assert "Command History Replay" in content
    assert "whoami" in content
    assert "copyTerminalText" in content

    # 2. Kernel integrity widget with linux.check_syscall.Check_syscall
    syscall_plugin, _ = Plugin.objects.get_or_create(
        name="linux.check_syscall.Check_syscall", operating_system="Linux"
    )
    res_sys = Result.objects.create(
        dump=dump, plugin=syscall_plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=res_sys,
        value={
            "Index": 0,
            "Handler Symbol": "__x64_sys_read",
            "Handler Address": 12345,
        },
    )
    Value.objects.create(
        result=res_sys,
        value={
            "Index": 1,
            "Handler Symbol": "UNKNOWN_HOOKED_ROOTKIT",
            "Handler Address": 67890,
        },
    )

    resp = client.get(
        url_analysis,
        {"indexes[]": [dump.index], "plugin": syscall_plugin.name},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    content = resp.content.decode()
    assert "Kernel Integrity Alert: 1 Potential Hook(s) Detected!" in content
    assert "Filter Hooked Entries" in content

    # 3. Network summary widget with linux.sockstat.Sockstat
    sock_plugin, _ = Plugin.objects.get_or_create(
        name="linux.sockstat.Sockstat", operating_system="Linux"
    )
    res_sock = Result.objects.create(
        dump=dump, plugin=sock_plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=res_sock,
        value={
            "PID": 10,
            "State": "LISTEN",
            "Source Addr": "0.0.0.0",
            "Source Port": "80",
        },
    )
    Value.objects.create(
        result=res_sock,
        value={
            "PID": 11,
            "State": "ESTABLISHED",
            "Source Addr": "192.168.1.5",
            "Destination Addr": "1.2.3.4",
        },
    )

    resp = client.get(
        url_analysis,
        {"indexes[]": [dump.index], "plugin": sock_plugin.name},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    content = resp.content.decode()
    assert "Network Sockets & Connection Triage" in content
    assert "Listening Services" in content
    assert "Established" in content

    # 4. Privilege summary widget with linux.capabilities.Capabilities
    cap_plugin, _ = Plugin.objects.get_or_create(
        name="linux.capabilities.Capabilities", operating_system="Linux"
    )
    res_cap = Result.objects.create(
        dump=dump, plugin=cap_plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=res_cap,
        value={"Pid": 1, "Name": "root_daemon", "cap_effective": "cap_sys_admin"},
    )
    Value.objects.create(
        result=res_cap, value={"Pid": 2, "Name": "user_daemon", "cap_effective": ""}
    )

    resp = client.get(
        url_analysis,
        {"indexes[]": [dump.index], "plugin": cap_plugin.name},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    content = resp.content.decode()
    assert "Process Privilege & Capability Analysis" in content
    assert "Filter High-Risk Tokens" in content

    # 5. Malfind code inspector with windows.malware.malfind.Malfind
    malfind_plugin, _ = Plugin.objects.get_or_create(
        name="windows.malware.malfind.Malfind", operating_system="Windows"
    )
    res_mal = Result.objects.create(
        dump=dump, plugin=malfind_plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=res_mal,
        value={
            "PID": 404,
            "Process": "svchost.exe",
            "Start VPN": "0x1000",
            "End VPN": "0x2000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "HexDump": "4d 5a 90 00 03 00 00 00",
            "Disasm": "push ebp\nmov ebp, esp",
        },
    )

    resp = client.get(
        url_analysis,
        {"indexes[]": [dump.index], "plugin": malfind_plugin.name},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    content = resp.content.decode()
    assert "Injected Code & Memory Regions Detected" in content
    assert "PE / MZ Header Found" in content
    assert "PAGE_EXECUTE_READWRITE" in content


def test_mountinfo_tree_view(client, admin, dump):
    client.force_login(admin)
    url_analysis = reverse("website:analysis")
    url_tree = reverse("website:tree")

    mount_plugin, _ = Plugin.objects.get_or_create(
        name="linux.mountinfo.MountInfo", operating_system="Linux"
    )
    res = Result.objects.create(
        dump=dump, plugin=mount_plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=res,
        value={"MOUNT ID": 1, "PARENT_ID": 1, "MOUNT_POINT": "/", "FSTYPE": "ext4"},
    )
    Value.objects.create(
        result=res,
        value={"MOUNT ID": 2, "PARENT_ID": 1, "MOUNT_POINT": "/var", "FSTYPE": "ext4"},
    )
    Value.objects.create(
        result=res,
        value={
            "MOUNT ID": 3,
            "PARENT_ID": 2,
            "MOUNT_POINT": "/var/log",
            "FSTYPE": "ext4",
        },
    )

    # Check analysis renders tree template
    resp_analysis = client.get(
        url_analysis,
        {"indexes[]": [dump.index], "plugin": mount_plugin.name},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp_analysis.status_code == 200
    assert "demo-tree" in resp_analysis.content.decode()

    # Check tree view returns hierarchical JSON with children
    resp_tree = client.get(
        url_tree,
        {"indexes[]": [dump.index], "plugin": mount_plugin.name},
    )
    assert resp_tree.status_code == 200
    data = resp_tree.json()
    assert len(data) == 1  # Root /
    assert data[0]["title"] == "/"
    assert "children" in data[0]
    assert len(data[0]["children"]) == 1  # /var
    assert data[0]["children"][0]["title"] == "/var"
    assert "children" in data[0]["children"][0]
    assert data[0]["children"][0]["children"][0]["title"] == "/var/log"


def test_htmx_process_defensive_wrapper_and_datatable_guards(client, admin):
    """Verify that HTMX process calls are defensively guarded across templates and vendor asset."""
    client.force_login(admin)
    resp = client.get(reverse("website:index"))
    assert resp.status_code == 200
    content = resp.content.decode()

    # 1. Base template must include the safe htmx.process wrapper
    assert "_origHtmxProcess" in content
    assert "htmx.process = function(elt)" in content
    assert (
        "elt instanceof Element || elt instanceof Document || elt instanceof DocumentFragment"
        in content
    )

    # 2. Index template must guard tbody in drawCallback and index-list in refresh_sidebar
    assert "settings.nTBody" in content
    assert "indexListEl && typeof htmx !== 'undefined'" in content

    # 3. Static htmx.min.js must contain null-safety checks in ie(e) and kt(e)
    static_root = Path(settings.APPS_DIR) / "static"
    htmx_path = static_root / "js" / "htmx" / "htmx.min.js"
    assert htmx_path.exists()
    htmx_js = htmx_path.read_text(encoding="utf-8")
    assert (
        'function ie(e){if(!e||typeof e!=="object")return{};const t="htmx-internal-data";'
        in htmx_js
    )
    assert (
        "function kt(e){if(!e)return;e=y(e);if(!e||!(e instanceof Element||e instanceof Document||e instanceof DocumentFragment))return;"
        in htmx_js
    )
    assert (
        'function Pt(t){if(!t||typeof t!=="object")return;if(g(t,Q.config.disableSelector))'
        in htmx_js
    )


def test_timeliner_analysis_view_with_fallback_and_summary(client, admin, dump):
    """Test that timeliner.Timeliner renders interactive chart via DB fallback and category summary pills."""
    client.force_login(admin)
    url_analysis = reverse("website:analysis")

    plugin, _ = Plugin.objects.get_or_create(
        name="timeliner.Timeliner", operating_system="Linux"
    )
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res,
        value={
            "Plugin": "PsList",
            "Description": "Process 1 (systemd)",
            "Created Date": "2021-03-03T13:34:47+00:00",
        },
    )
    Value.objects.create(
        result=res,
        value={
            "Plugin": "Bash",
            "Description": "cat /etc/shadow",
            "Modified Date": "2021-03-03T14:15:00+00:00",
        },
    )
    Value.objects.create(
        result=res,
        value={
            "Plugin": "Files",
            "Description": "Cached Inode /etc/passwd",
            "Accessed Date": "2021-03-03T15:00:00+00:00",
        },
    )

    resp = client.get(
        url_analysis,
        {"indexes[]": [dump.index], "plugin": plugin.name},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    content = resp.content.decode()
    # Check chart is generated via DB values fallback
    assert "Interactive Event Timeline" in content
    assert "plotly" in content.lower()
    # Check category summary pills and counts
    assert "Timeline Event Categories" in content
    assert "Total Events:" in content
    assert "PsList" in content
    assert "Bash" in content
    assert "Files" in content
    # Check cross-filtering listener
    assert "attachTimelineListener" in content


def test_generate_fast_large_dataset(client, admin, dump, plugin):
    """Test that generate() efficiently pages large datasets and renders row_actions only on returned page."""
    client.force_login(admin)
    url = reverse("website:generate")

    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    bulk_values = [
        Value(
            result=res,
            value={"PID": i, "Process": f"proc_{i}", "Time": "2021-03-03T12:00:00"},
        )
        for i in range(250)
    ]
    Value.objects.bulk_create(bulk_values)

    params = {
        "columns[]": ["PID", "Process", "Time", "actions"],
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
    assert data["recordsTotal"] == 250
    assert data["recordsFiltered"] == 250
    assert len(data["data"]) == 10
    # actions column should have been rendered on the paged items
    assert "Add to Case" in data["data"][0][3]


def test_timeliner_multiple_dumps_partial_bodyfile(client, admin, dump):
    """Test timeliner with multiple dumps where only one dump has on-disk bodyfile."""
    client.force_login(admin)
    url_analysis = reverse("website:analysis")

    # Create Dump 2 without bodyfile
    dump2 = Dump.objects.create(
        index=str(uuid4()),
        name="dump_two.vmem",
        author=admin,
        upload=SimpleUploadedFile("dump_two.vmem", b"sample content"),
        operating_system="Linux",
        color="#e11d48",
    )
    assign_perm("website.can_see", admin, dump2)

    plugin, _ = Plugin.objects.get_or_create(
        name="timeliner.Timeliner", operating_system="Linux"
    )

    # Dump 1 has an on-disk volatility.body file
    _ = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    body_dir = Path(dump.upload.path).parent / "timeliner.Timeliner"
    body_dir.mkdir(parents=True, exist_ok=True)
    body_file = body_dir / "volatility.body"
    body_file.write_text("pslist - Process 1234 (bash)|0|0|0|0|0|0|1614778487\n")

    # Dump 2 does NOT have a bodyfile on disk, but has DB values
    res2 = Result.objects.create(
        dump=dump2, plugin=plugin, result=RESULT_STATUS_SUCCESS
    )
    Value.objects.create(
        result=res2,
        value={
            "Plugin": "Lsof",
            "Description": "Open file /tmp/dump2",
            "Created Date": "2021-03-03T16:00:00+00:00",
        },
    )

    resp = client.get(
        url_analysis,
        {"indexes[]": [dump.index, dump2.index], "plugin": plugin.name},
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    content = resp.content.decode()

    # Both dump names should be clearly displayed on individual timeline cards
    assert dump.name in content
    assert dump2.name in content
    assert "Interactive Event Timeline" in content
    # Multi-dump categories should be accumulated
    assert "Timeline Event Categories" in content


def test_sidebar_host_grouping(client, admin, dump, folder):
    """Test sidebar groups dumps from the same host together."""
    from orochi.website.models import Host
    from orochi.website.templatetags.custom_tags import organize_dumps

    client.force_login(admin)

    host = Host.objects.create(name="finance-pc")
    dump.host = host
    dump.save()

    dump2 = Dump.objects.create(
        name="dump_t2_pc",
        operating_system="Windows",
        author=admin,
        folder=folder,
        host=host,
        index=str(uuid4()),
        upload=SimpleUploadedFile("t2.raw", b"test content 2"),
    )
    assign_perm("can_see", admin, dump2)

    dump3 = Dump.objects.create(
        name="standalone_dump",
        operating_system="Linux",
        author=admin,
        folder=folder,
        host=None,
        index=str(uuid4()),
        upload=SimpleUploadedFile("stand.raw", b"standalone content"),
    )
    assign_perm("can_see", admin, dump3)

    url = reverse("website:indices")
    resp = client.get(url)
    assert resp.status_code == 200
    content = resp.content.decode()

    # Host group markup
    assert "finance-pc" in content
    assert "host-group" in content
    assert 'data-host="finance-pc"' in content
    assert "Diff" in content
    assert "temporal_diff" in content
    assert dump.name in content
    assert dump2.name in content
    assert dump3.name in content

    # Test organize_dumps filter directly
    test_tuples = [
        (
            folder.name,
            dump.index,
            dump.name,
            dump.color,
            dump.operating_system,
            dump.author,
            "dump.raw",
            1,
            "",
            False,
            host.name,
        ),
        (
            folder.name,
            dump2.index,
            dump2.name,
            dump2.color,
            dump2.operating_system,
            dump2.author,
            "dump2.raw",
            1,
            "",
            False,
            host.name,
        ),
        (
            folder.name,
            dump3.index,
            dump3.name,
            dump3.color,
            dump3.operating_system,
            dump3.author,
            "dump3.raw",
            1,
            "",
            False,
            None,
        ),
    ]
    organized = organize_dumps(test_tuples)
    assert organized["has_hosts"] is True
    assert organized["total_count"] == 3
    assert len(organized["by_folder"]) == 1
    folder_entry = organized["by_folder"][0]
    assert len(folder_entry["hosts"]) == 1
    host_entry = folder_entry["hosts"][0]
    assert host_entry["name"] == "finance-pc"
    assert host_entry["count"] == 2
    assert host_entry["can_diff"] is True
    assert len(folder_entry["standalone"]) == 1
    assert folder_entry["standalone"][0]["name"] == "standalone_dump"


def test_analysis_note_host_and_list_dump_attributes(
    client, admin, dump, folder, plugin
):
    """Test analysis note includes host information so UI enables temporal diff only for same host."""
    from orochi.website.models import Host

    client.force_login(admin)
    host = Host.objects.create(name="finance-pc")
    dump.host = host
    dump.save()

    dump2 = Dump.objects.create(
        name="dump_t2_pc",
        operating_system="Windows",
        author=admin,
        folder=folder,
        host=None,
        index=str(uuid4()),
        upload=SimpleUploadedFile("t2.raw", b"test content 2"),
    )
    assign_perm("can_see", admin, dump2)

    Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Result.objects.create(dump=dump2, plugin=plugin, result=RESULT_STATUS_SUCCESS)

    resp = client.get(
        reverse("website:analysis"),
        {
            "plugin": plugin.name,
            "indexes[]": [dump.index, dump2.index],
        },
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )
    assert resp.status_code == 200
    content = resp.content.decode()

    # Verify list-dump buttons render with data-host
    assert f'data-index="{dump.index}"' in content
    assert f'data-host="{host.name}"' in content
    assert f'data-index="{dump2.index}"' in content
    assert 'data-host=""' in content
    assert 'id="temporal-diff-dump"' in content
