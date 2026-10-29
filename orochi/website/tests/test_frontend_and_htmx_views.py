import json
from uuid import uuid4

import pytest
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils import timezone
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import (
    Bookmark,
    Case,
    Dump,
    Evidence,
    Finding,
    Folder,
    Host,
    Plugin,
    Result,
    TimelineEvent,
    Value,
)
from orochi.website.templatetags.custom_tags import (
    can_run_plugin_filter,
    epoch,
    has_group,
    has_role_filter,
    in_list,
    is_checkbox,
    mitre_id,
    mitre_url,
    organize_dumps,
    split_pipe,
    starts_with,
    user_role,
)

pytestmark = pytest.mark.django_db


def test_template_tags_utility_filters():
    """Test standard template tag filters in custom_tags."""
    from django.forms.widgets import CheckboxInput, TextInput

    class MockField:
        def __init__(self, widget):
            self.field = type("Field", (), {"widget": widget})()

    assert is_checkbox(MockField(CheckboxInput())) is True
    assert is_checkbox(MockField(TextInput())) is False

    # in_list
    assert in_list("apple", "apple,banana") is True
    assert in_list("orange", "apple,banana") is False

    # starts_with
    assert starts_with("windows.pslist", "windows.") is True
    assert starts_with("linux.pslist", "windows.") is False

    # epoch
    assert epoch(0).year == 1970
    assert epoch(None) is None

    # split_pipe
    pipe_res = split_pipe("PID: 100|Image: svchost.exe|raw_item")
    assert len(pipe_res) == 3
    assert pipe_res[0] == {"key": "PID", "value": "100", "raw": "PID: 100"}
    assert pipe_res[1] == {"key": "Image", "value": "svchost.exe", "raw": "Image: svchost.exe"}
    assert pipe_res[2] == {"key": "", "value": "raw_item", "raw": "raw_item"}
    assert split_pipe("") == []
    assert split_pipe(None) == []

    # mitre_url and mitre_id
    assert mitre_url("T1055") == "https://attack.mitre.org/techniques/T1055/"
    assert mitre_url("T1055.001") == "https://attack.mitre.org/techniques/T1055/001/"
    assert mitre_url("") == "https://attack.mitre.org"
    assert mitre_url(None) == "https://attack.mitre.org"

    assert mitre_id("T1055 - Process Injection") == "T1055"
    assert mitre_id("T1055.001 - DLL Injection") == "T1055.001"
    assert mitre_id("InvalidPattern") == "InvalidPattern"
    assert mitre_id("") == ""
    assert mitre_id(None) == ""


def test_roles_and_permissions_template_tags(admin, user):
    """Test group and RBAC helper filters in custom_tags."""
    group_analyst, _ = Group.objects.get_or_create(name="Analyst")
    user.groups.add(group_analyst)

    assert has_group(user, "Analyst") is True
    assert has_group(user, "Admin") is False

    # user_role
    assert user_role(admin) == "Admin"
    assert user_role(user) == "Analyst"

    from django.contrib.auth import get_user_model

    User = get_user_model()
    ro_user = User.objects.create_user(username="readonly_tester", password="password123")
    group_ro, _ = Group.objects.get_or_create(name="ReadOnly")
    ro_user.groups.add(group_ro)
    assert user_role(ro_user) == "ReadOnly"

    # has_role_filter
    assert has_role_filter(admin, "Admin") is True
    assert has_role_filter(user, "Admin") is False
    assert has_role_filter(user, "Analyst") is True
    assert has_role_filter(ro_user, "ReadOnly") is True

    # can_run_plugin_filter
    plugin_admin = Plugin.objects.create(name="test.admin.plugin", min_role="Admin")
    plugin_analyst = Plugin.objects.create(name="test.analyst.plugin", min_role="Analyst")

    assert can_run_plugin_filter(admin, plugin_admin) is True
    assert can_run_plugin_filter(user, plugin_admin) is False
    assert can_run_plugin_filter(user, plugin_analyst) is True


def test_organize_dumps_edge_cases():
    """Test organize_dumps template filter with empty, single, and heterogeneous collections."""
    # Empty collection
    res_empty = organize_dumps([])
    assert res_empty["total_count"] == 0
    assert res_empty["by_folder"] == []
    assert res_empty["has_hosts"] is False

    # Dumps across folders and hosts
    raw_tuples = [
        ("Incident A", "idx1", "Dump 1", "#ff0000", "Windows", "alice", "d1.raw", 1, "", False, "host-srv01"),
        ("Incident A", "idx2", "Dump 2", "#00ff00", "Windows", "alice", "d2.raw", 1, "", False, "host-srv01"),
        ("Incident A", "idx3", "Dump 3", "#0000ff", "Linux", "alice", "d3.raw", 1, "", False, None),
        ("Incident B", "idx4", "Dump 4", "#ffff00", "Windows", "bob", "d4.raw", 1, "", False, "host-db01"),
    ]
    res = organize_dumps(raw_tuples)
    assert res["total_count"] == 4
    assert res["has_hosts"] is True
    assert len(res["by_folder"]) == 2

    folder_a = next(f for f in res["by_folder"] if f["folder"] == "Incident A")
    assert len(folder_a["hosts"]) == 1
    assert folder_a["hosts"][0]["name"] == "host-srv01"
    assert folder_a["hosts"][0]["can_diff"] is True
    assert len(folder_a["standalone"]) == 1
    assert folder_a["standalone"][0]["name"] == "Dump 3"


def test_case_detail_view_full_and_htmx(client, user):
    """Test case_detail view for both full HTML page and HTMX partial response."""
    client.force_login(user)
    folder = Folder.objects.create(name="Folder-Forensics", user=user)
    case = Case.objects.create(name="Investigation-Detail", user=user, folder=folder, description="Test description")
    dump = Dump.objects.create(name="RAM-HostA", index="idx_case_detail", author=user, folder=folder)
    assign_perm("can_see", user, dump)

    ev = Evidence.objects.create(case=case, dump=dump, name="Evidence 1")
    Finding.objects.create(case=case, evidence=ev, severity="High", note="Malicious injection detected")
    TimelineEvent.objects.create(
        case=case, timestamp=timezone.now(), event_type="Manual Note", description="Started triage."
    )

    url = reverse("website:case_detail", kwargs={"pk": case.pk})

    # Full HTML Request
    resp = client.get(url)
    assert resp.status_code == 200
    content = resp.content.decode()
    assert "Investigation-Detail" in content
    assert "Malicious injection detected" in content

    # HTMX Partial Request
    resp_htmx = client.get(url, HTTP_HX_REQUEST="true")
    assert resp_htmx.status_code == 200
    assert "website/partial_case_detail.html" in [t.name for t in resp_htmx.templates if t.name]


def test_case_change_status_htmx(client, user):
    """Test case_change_status view with valid status and invalid status."""
    client.force_login(user)
    case = Case.objects.create(name="Status-Change-Case", user=user, status=Case.STATUS_OPEN)
    url = reverse("website:case_change_status", kwargs={"pk": case.pk})

    # Valid status change POST
    resp_valid = client.post(url, {"status": Case.STATUS_IN_PROGRESS})
    assert resp_valid.status_code == 200
    assert "HX-Trigger" in resp_valid.headers
    trigger_data = json.loads(resp_valid.headers["HX-Trigger"])
    assert trigger_data["refreshCaseDetail"] is True
    assert "In Progress" in trigger_data["showMessage"]["content"]

    case.refresh_from_db()
    assert case.status == Case.STATUS_IN_PROGRESS

    # Invalid status change POST
    resp_invalid = client.post(url, {"status": "NonExistentStatus"})
    assert resp_invalid.status_code == 400


def test_diff_view_between_dumps(client, user):
    """Test diff_view comparing plugin results between two dumps."""
    client.force_login(user)
    p_pslist, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList")

    dump1 = Dump.objects.create(name="Dump-Diff-1", index="idx_diff_1", author=user)
    dump2 = Dump.objects.create(name="Dump-Diff-2", index="idx_diff_2", author=user)
    assign_perm("can_see", user, dump1)
    assign_perm("can_see", user, dump2)

    res1 = Result.objects.create(dump=dump1, plugin=p_pslist, result=RESULT_STATUS_SUCCESS)
    res2 = Result.objects.create(dump=dump2, plugin=p_pslist, result=RESULT_STATUS_SUCCESS)

    Value.objects.create(result=res1, value={"PID": 100, "ImageFileName": "svchost.exe"})
    Value.objects.create(result=res2, value={"PID": 100, "ImageFileName": "svchost.exe"})
    Value.objects.create(result=res2, value={"PID": 200, "ImageFileName": "beacon.exe"})

    url = reverse(
        "website:diff_view",
        kwargs={"index_a": dump1.index, "index_b": dump2.index, "plugin": p_pslist.name},
    )
    resp = client.get(url)
    assert resp.status_code == 200
    assert "dump_a" in resp.context
    assert "dump_b" in resp.context
    assert "Dump-Diff-1" in resp.content.decode()
    assert "Dump-Diff-2" in resp.content.decode()


def test_temporal_diff_view_same_host(client, user):
    """Test temporal_diff view showing cross-dump state progression for the same host."""
    client.force_login(user)
    host = Host.objects.create(name="ws-finance-01")
    dump1 = Dump.objects.create(name="Dump-T1", index="idx_t1", author=user, host=host)
    dump2 = Dump.objects.create(name="Dump-T2", index="idx_t2", author=user, host=host)
    assign_perm("can_see", user, dump1)
    assign_perm("can_see", user, dump2)

    url = reverse("website:temporal_diff", kwargs={"index_a": dump1.index, "index_b": dump2.index})
    resp = client.get(url)
    assert resp.status_code == 200
    content = resp.content.decode()
    assert "Dump-T1" in content
    assert "Dump-T2" in content
    assert "ws-finance-01" in content


def test_bookmarks_view_and_add_bookmark(client, user):
    """Test adding and retrieving user bookmarks on plugin results."""
    from orochi.website.defaults import IconEnum

    client.force_login(user)
    p_ps, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList")
    dump = Dump.objects.create(name="Dump-Bookmark", index=str(uuid4()), author=user)
    assign_perm("can_see", user, dump)

    # 1. Add Bookmark POST
    url_add = reverse("website:add_bookmark")
    resp_add = client.post(
        url_add,
        {
            "selected_indexes": dump.index,
            "selected_plugin": p_ps.name,
            "name": "Suspicious PID Bookmark",
            "query": "PID: 4444",
            "star": True,
            "icon": IconEnum.SS_ORI.value,
        },
    )
    assert resp_add.status_code == 200
    assert Bookmark.objects.filter(user=user, name="Suspicious PID Bookmark").exists()

    # 2. Get Bookmarks View
    url_get = reverse(
        "website:bookmarks",
        kwargs={"indexes": dump.index, "plugin": p_ps.name},
    )
    resp_get = client.get(url_get)
    assert resp_get.status_code == 200
    assert "Suspicious PID Bookmark" in resp_get.content.decode()
