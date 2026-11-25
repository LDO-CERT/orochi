"""Regression tests for Issue #1671: fresh installation usable by non-superusers and completion events."""

import json
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command

from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
    SERVICE_WEBHOOK,
)
from orochi.website.models import Dump, Plugin, Result, Service, UserPlugin
from orochi.website.roles import ROLE_ANALYST

pytestmark = pytest.mark.django_db
User = get_user_model()


def _make_analyst(username: str = "fresh_analyst"):
    user = User.objects.create_user(
        username=username,
        email=f"{username}@example.com",
        password="testpassword123",
        is_superuser=False,
        is_staff=False,
    )
    if hasattr(user, "role"):
        user.role = ROLE_ANALYST
    user.enable_notifications = True
    user.notify_on_dump_completion = True
    user.notify_via_webhook = True
    user.save()
    return user


def test_non_superuser_api_upload_is_visible_to_uploader(client):
    """AC1 (#1671): An Analyst who uploads a dump through the API can read it back."""
    analyst = _make_analyst("analyst_uploader")
    client.force_login(analyst)

    upload = SimpleUploadedFile("sample.raw", b"MZ" + b"\x00" * 64, content_type="application/octet-stream")
    payload = json.dumps({"name": "AnalystDump", "operating_system": "Windows"})
    with patch("orochi.api.routers.dumps.index_f_and_f"):
        resp = client.post(
            "/api/dumps/",
            data={"payload": payload, "upload": upload},
        )
    assert resp.status_code in (200, 201), resp.content
    dump = Dump.objects.get(name="AnalystDump")
    assert dump.author == analyst

    detail_resp = client.get(f"/api/dumps/{dump.index}")
    assert detail_resp.status_code == 200, detail_resp.content
    assert detail_resp.json()["name"] == "AnalystDump"


def test_newly_created_user_receives_userplugin_entries_for_existing_catalogue():
    """AC2 (#1671): Users created after plugin sync automatically get UserPlugin entries."""
    plugin, _ = Plugin.objects.get_or_create(
        name="windows.pslist.PsList",
        defaults={"operating_system": "Windows", "disabled": False},
    )
    new_analyst = _make_analyst("analyst_post_sync")
    assert UserPlugin.objects.filter(user=new_analyst, plugin=plugin).exists()


def test_post_install_plugins_sync_waits_for_scheduler_receipt():
    """AC3 (#1671): Documented post-install plugins_sync confirms scheduler receipt before exiting."""
    fake_task = MagicMock()
    fake_task.enqueue.return_value = MagicMock(id="task-sync-123")
    with (
        patch("orochi.website.management.commands.plugins_sync.sync_volatility_plugins", fake_task),
        patch("orochi.website.management.commands.plugins_sync.wait_for_scheduler", return_value=True) as mock_wait,
    ):
        call_command("plugins_sync")
    fake_task.enqueue.assert_called_once()
    mock_wait.assert_called_once_with("task-sync-123")


def test_plugin_completion_triggers_configured_webhook():
    """AC4 (#1671): Plugin completion fires the configured webhook via registered signals."""
    analyst = _make_analyst("analyst_webhook")
    Service.objects.create(name=SERVICE_WEBHOOK, url="http://127.0.0.1:9999/hook", key="")
    plugin, _ = Plugin.objects.get_or_create(
        name="windows.cmdline.CmdLine",
        defaults={"operating_system": "Windows", "disabled": False},
    )
    dump = Dump.objects.create(
        name="WebhookDump",
        operating_system="Windows",
        author=analyst,
        status=DUMP_STATUS_COMPLETED,
    )
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_RUNNING)

    with (
        patch("orochi.website.signals.notify_user"),
        patch("orochi.website.signals.close_old_connections"),
        patch("orochi.website.signals.threading.Thread") as mock_thread,
        patch("orochi.website.notifications.requests.post") as mock_post,
    ):
        mock_thread.side_effect = lambda target=None, *args, **kwargs: MagicMock(start=target)
        res.result = RESULT_STATUS_SUCCESS
        res.save()

    assert mock_post.called
    called_url = mock_post.call_args.args[0]
    assert called_url == "http://127.0.0.1:9999/hook"
