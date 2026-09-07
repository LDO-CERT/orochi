import json
from pathlib import Path
from uuid import uuid4

import pytest
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Case, Dump, Evidence, Finding, Plugin, Result, Value

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


def test_case_detail_htmx_swap_and_indices_markup(client, admin, dump):
    client.force_login(admin)
    case = Case.objects.create(name="Investigation Alpha", user=admin)

    # 1. Cases list rendered in index should swap innerHTML into #main_stage
    resp_cases = client.get(reverse("website:index"))
    assert resp_cases.status_code == 200
    content_cases = resp_cases.content.decode()
    assert 'hx-target="#main_stage"' in content_cases
    assert 'hx-swap="innerHTML"' in content_cases

    # 2. Case detail via HTMX should render root id="case_detail_view" to avoid colliding with #main_stage
    resp_case_detail = client.get(
        reverse("website:case_detail", kwargs={"pk": case.pk}),
        HTTP_HX_REQUEST="true",
    )
    assert resp_case_detail.status_code == 200
    content_detail = resp_case_detail.content.decode()
    assert 'id="case_detail_view"' in content_detail
    assert 'id="main_stage"' not in content_detail

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
    res1 = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
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
