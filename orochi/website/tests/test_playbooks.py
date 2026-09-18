from unittest.mock import MagicMock, patch

import pytest
from django.urls import reverse

from orochi.website.defaults import RESULT_STATUS_RUNNING
from orochi.website.models import Plugin, Result
from orochi.website.playbooks import (
    get_available_playbooks,
    get_playbook,
    resolve_playbook_plugins,
)
from orochi.website.tasks import run_playbook_task

pytestmark = pytest.mark.django_db


def test_playbooks_catalog_definitions():
    """Verify predefined playbooks catalog and OS filtering."""
    all_pbs = get_available_playbooks()
    assert len(all_pbs) >= 6

    win_pbs = get_available_playbooks("Windows")
    assert len(win_pbs) >= 3
    for p in win_pbs:
        assert p["operating_system"].lower() == "windows"

    linux_pbs = get_available_playbooks("Linux")
    assert len(linux_pbs) >= 2
    for p in linux_pbs:
        assert p["operating_system"].lower() == "linux"

    mac_pbs = get_available_playbooks("Mac")
    assert len(mac_pbs) >= 1
    for p in mac_pbs:
        assert p["operating_system"].lower() == "mac"

    pb = get_playbook("win_malware_quick")
    assert pb is not None
    assert pb["id"] == "win_malware_quick"
    assert "windows.pslist.PsList" in pb["plugins"]


def test_resolve_playbook_plugins(dump):
    """Test resolution of playbook plugin names against database Plugin records."""
    dump.operating_system = "Windows"
    dump.save()

    p1, _ = Plugin.objects.get_or_create(
        name="windows.pslist.PsList",
        operating_system=dump.operating_system,
    )
    p2, _ = Plugin.objects.get_or_create(
        name="windows.netscan.NetScan",
        operating_system=dump.operating_system,
    )

    pb = get_playbook("win_malware_quick")
    resolved = resolve_playbook_plugins(dump, pb)
    assert p1 in resolved
    assert p2 in resolved


def test_run_playbook_task(admin, dump):
    """Test background task orchestration of playbook plugins."""
    dump.operating_system = "Windows"
    dump.save()

    p1, _ = Plugin.objects.get_or_create(
        name="windows.pslist.PsList",
        operating_system=dump.operating_system,
    )
    p2, _ = Plugin.objects.get_or_create(
        name="windows.netscan.NetScan",
        operating_system=dump.operating_system,
    )

    with (
        patch("orochi.api.routers.dumps.plugin_f_and_f") as mock_f_and_f,
        patch("orochi.website.tasks.evaluate_dump_triage") as mock_eval_triage,
        patch("orochi.website.tasks._send_task_notification"),
    ):
        res = run_playbook_task.call(
            dump_pk=dump.pk,
            playbook_id="win_malware_quick",
            user_pk=admin.pk,
        )

        assert res["dump_pk"] == dump.pk
        assert res["playbook_id"] == "win_malware_quick"
        assert len(res["launched_plugins"]) >= 2
        assert mock_f_and_f.call_count >= 2
        mock_eval_triage.assert_called_once_with(dump)

        # Verify Result objects updated to RUNNING
        r1 = Result.objects.get(dump=dump, plugin=p1)
        assert r1.result == RESULT_STATUS_RUNNING


def test_api_playbooks_list_and_detail(client, admin):
    """Test GET /api/playbooks/ and GET /api/playbooks/{id}."""
    client.force_login(admin)

    # 1. List all
    resp = client.get("/api/playbooks/")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 6

    # 2. Filter by OS
    resp_win = client.get("/api/playbooks/?os=Windows")
    assert resp_win.status_code == 200
    for p in resp_win.json():
        assert p["operating_system"] == "Windows"

    # 3. Get single
    resp_single = client.get("/api/playbooks/win_malware_quick")
    assert resp_single.status_code == 200
    assert resp_single.json()["id"] == "win_malware_quick"

    # 4. 404 for unknown
    resp_404 = client.get("/api/playbooks/nonexistent_playbook")
    assert resp_404.status_code == 404


def test_api_launch_playbook(client, admin, dump):
    """Test POST /api/playbooks/{id}/launch/{dump_index}."""
    client.force_login(admin)
    dump.operating_system = "Windows"
    dump.save()

    with patch("orochi.api.routers.playbooks.run_playbook_task") as mock_task:
        mock_res = MagicMock()
        mock_res.id = "task-playbook-test-123"
        mock_task.enqueue.return_value = mock_res

        # Valid launch
        resp = client.post(f"/api/playbooks/win_malware_quick/launch/{dump.index}")
        assert resp.status_code == 200
        assert resp.json()["task_id"] == "task-playbook-test-123"
        mock_task.enqueue.assert_called_once_with(
            dump_pk=dump.pk,
            playbook_id="win_malware_quick",
            user_pk=admin.pk,
        )

        # OS mismatch
        resp_mismatch = client.post(f"/api/playbooks/linux_quick_triage/launch/{dump.index}")
        assert resp_mismatch.status_code == 400
        assert "is designed for Linux" in resp_mismatch.json()["errors"]


def test_dump_playbooks_view(client, admin, dump):
    """Test GET and POST on website /dump/{index}/playbooks."""
    client.force_login(admin)
    dump.operating_system = "Windows"
    dump.save()

    # 1. GET view
    url = reverse("website:dump_playbooks", kwargs={"index": dump.index})
    resp = client.get(url)
    assert resp.status_code == 200
    assert "Auto-Triage Playbooks" in resp.content.decode("utf-8")

    # 2. POST launch via view
    with patch("orochi.website.tasks.run_playbook_task") as mock_task:
        mock_res = MagicMock()
        mock_res.id = "task-playbook-view-456"
        mock_task.enqueue.return_value = mock_res

        resp_post = client.post(url, data={"playbook_id": "win_malware_quick"})
        assert resp_post.status_code == 200
        assert "task-playbook-view-456" in resp_post.content.decode("utf-8")
        mock_task.enqueue.assert_called_once_with(
            dump_pk=dump.pk,
            playbook_id="win_malware_quick",
            user_pk=admin.pk,
        )


def test_create_and_delete_custom_playbook_engine(admin):
    """Test custom playbook creation and deletion via engine functions."""
    from orochi.website.playbooks import create_custom_playbook, delete_custom_playbook

    p1, _ = Plugin.objects.get_or_create(
        name="windows.pslist.PsList",
        operating_system="Windows",
    )
    p2, _ = Plugin.objects.get_or_create(
        name="windows.cmdline.CmdLine",
        operating_system="Windows",
    )

    # 1. Create custom playbook
    pb = create_custom_playbook(
        name="Memory Forensics Alpha",
        operating_system="Windows",
        plugin_names=["windows.pslist.PsList", "windows.cmdline.CmdLine"],
        user=admin,
        description="Test description",
        icon="fa-bug",
        color="rose",
        tags=["alpha", "test"],
    )

    assert pb is not None
    assert pb["is_custom"] is True
    assert pb["name"] == "Memory Forensics Alpha"
    assert "windows.pslist.PsList" in pb["plugins"]
    assert "windows.cmdline.CmdLine" in pb["plugins"]
    assert pb["id"].startswith("custom_memory_forensics_alpha")

    # 2. Check get_available_playbooks includes it
    all_win = get_available_playbooks("Windows", user=admin)
    matching = [x for x in all_win if x["id"] == pb["id"]]
    assert len(matching) == 1
    assert matching[0]["can_delete"] is True

    # 3. Built-in cannot be deleted
    with pytest.raises(ValueError, match="Built-in"):
        delete_custom_playbook("win_malware_quick", user=admin)

    # 4. Delete custom playbook
    success = delete_custom_playbook(pb["id"], user=admin)
    assert success is True
    assert get_playbook(pb["id"]) is None


def test_api_custom_playbook_crud(client, admin, user):
    """Test API POST /api/playbooks/, PUT /api/playbooks/{id}, and DELETE /api/playbooks/{id}."""
    Plugin.objects.get_or_create(
        name="windows.pslist.PsList",
        operating_system="Windows",
    )
    Plugin.objects.get_or_create(
        name="windows.netscan.NetScan",
        operating_system="Windows",
    )

    # 1. Create custom playbook via API
    client.force_login(admin)
    create_resp = client.post(
        "/api/playbooks/",
        data={
            "name": "API Custom Playbook",
            "operating_system": "Windows",
            "plugin_names": ["windows.pslist.PsList"],
            "description": "Created via API",
            "icon": "fa-terminal",
            "color": "purple",
            "tags": ["api", "custom"],
        },
        content_type="application/json",
    )
    assert create_resp.status_code == 200
    pb_data = create_resp.json()
    assert pb_data["is_custom"] is True
    assert pb_data["name"] == "API Custom Playbook"
    pb_id = pb_data["id"]

    # 2. Update custom playbook via API PUT
    put_resp = client.put(
        f"/api/playbooks/{pb_id}",
        data={
            "name": "API Custom Playbook Updated",
            "description": "Updated description",
            "color": "rose",
            "plugin_names": ["windows.pslist.PsList", "windows.netscan.NetScan"],
        },
        content_type="application/json",
    )
    assert put_resp.status_code == 200
    updated_data = put_resp.json()
    assert updated_data["name"] == "API Custom Playbook Updated"
    assert updated_data["color"] == "rose"
    assert len(updated_data["plugins"]) == 2

    # 3. Unauthorized user cannot update or delete admin's playbook
    client.force_login(user)
    put_forbidden = client.put(
        f"/api/playbooks/{pb_id}",
        data={"name": "Hacked Playbook"},
        content_type="application/json",
    )
    assert put_forbidden.status_code == 400

    del_forbidden = client.delete(f"/api/playbooks/{pb_id}")
    assert del_forbidden.status_code == 400

    # 4. Admin can delete
    client.force_login(admin)
    del_resp = client.delete(f"/api/playbooks/{pb_id}")
    assert del_resp.status_code == 200
    assert "deleted successfully" in del_resp.json()["message"]


def test_list_playbooks_view_get(client, admin):
    """Test GET /playbooks view and context statistics."""
    client.force_login(admin)
    url = reverse("website:list_playbooks")
    response = client.get(url)
    assert response.status_code == 200
    assert "playbooks" in response.context
    assert "stats" in response.context
    assert "plugins_by_os" in response.context
    assert response.context["stats"]["total"] >= 6
    content = response.content.decode("utf-8")
    assert "Incident Response Playbooks" in content
    assert "New Custom Playbook" in content


def test_list_playbooks_view_crud(client, admin):
    """Test creating, editing, and deleting a playbook via /playbooks view."""
    client.force_login(admin)
    Plugin.objects.get_or_create(
        name="windows.pslist.PsList",
        operating_system="Windows",
    )
    Plugin.objects.get_or_create(
        name="windows.netscan.NetScan",
        operating_system="Windows",
    )

    url = reverse("website:list_playbooks")

    # 1. Create custom playbook via POST action=create
    resp_create = client.post(
        url,
        data={
            "action": "create",
            "name": "SecOps Triage Workflow",
            "operating_system": "Windows",
            "description": "Initial triage workflow",
            "plugins": ["windows.pslist.PsList"],
            "color": "emerald",
            "icon": "fa-bolt",
            "tags": "secops, triage",
        },
        follow=True,
    )
    assert resp_create.status_code == 200
    assert "created successfully" in resp_create.content.decode("utf-8")

    from orochi.website.models import Playbook

    created_pb = Playbook.objects.filter(name="SecOps Triage Workflow").first()
    assert created_pb is not None
    assert created_pb.operating_system == "Windows"

    # 2. Edit custom playbook via POST action=edit
    resp_edit = client.post(
        url,
        data={
            "action": "edit",
            "playbook_id": created_pb.playbook_id,
            "name": "SecOps Triage Workflow V2",
            "operating_system": "Windows",
            "description": "Updated triage workflow with netscan",
            "plugins": ["windows.pslist.PsList", "windows.netscan.NetScan"],
            "color": "rose",
            "icon": "fa-shield-halved",
            "tags": "secops, updated",
        },
        follow=True,
    )
    assert resp_edit.status_code == 200
    assert "updated successfully" in resp_edit.content.decode("utf-8")

    created_pb.refresh_from_db()
    assert created_pb.name == "SecOps Triage Workflow V2"
    assert created_pb.color == "rose"
    assert created_pb.plugins.count() == 2

    # 3. Delete custom playbook via POST action=delete
    resp_delete = client.post(
        url,
        data={
            "action": "delete",
            "playbook_id": created_pb.playbook_id,
        },
        follow=True,
    )
    assert resp_delete.status_code == 200
    assert "deleted successfully" in resp_delete.content.decode("utf-8")
    assert not Playbook.objects.filter(playbook_id=created_pb.playbook_id).exists()


def test_dump_playbooks_dialog_view_and_launch(client, admin, dump):
    """Test dump_playbooks dialog: displays Manage Playbooks link and launches playbooks."""
    client.force_login(admin)
    dump.operating_system = "Windows"
    dump.save()

    Plugin.objects.get_or_create(
        name="windows.pslist.PsList",
        operating_system="Windows",
    )
    Plugin.objects.get_or_create(
        name="windows.netscan.NetScan",
        operating_system="Windows",
    )

    url = reverse("website:dump_playbooks", kwargs={"index": dump.index})

    # 1. GET dialog: verify "Manage Playbooks" button is present and create form is absent
    resp_get = client.get(url)
    assert resp_get.status_code == 200
    content = resp_get.content.decode("utf-8")
    assert "Manage Playbooks" in content
    assert "togglePlaybookCreator" not in content

    # 2. POST to launch playbook
    with patch("orochi.website.tasks.run_playbook_task") as mock_task:
        mock_res = MagicMock()
        mock_res.id = "test-task-123"
        mock_task.enqueue.return_value = mock_res
        resp_launch = client.post(
            url,
            data={"playbook_id": "win_malware_quick"},
        )
        assert resp_launch.status_code == 200
        mock_task.enqueue.assert_called_once()
        assert "test-task-123" in resp_launch.content.decode("utf-8")
