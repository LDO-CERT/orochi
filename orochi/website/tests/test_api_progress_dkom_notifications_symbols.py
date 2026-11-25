"""Regression tests for Phase 2 Batch 1: #1661 (API progress), #1662 (Linux DKOM), #1664/#1566 (Notifications), #1553 (Symbol Assistant)."""

from unittest.mock import MagicMock, patch

import pytest
from django.core.files import File
from guardian.shortcuts import assign_perm

from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_RUNNING,
    RESULT_STATUS_SUCCESS,
    RESULT_STATUS_UNSATISFIED,
    SERVICE_SLACK,
    SERVICE_WEBHOOK,
    SymbolStatus,
)
from orochi.website.detection.rules import evaluate_dkom_unlinked
from orochi.website.models import Case, Finding, Plugin, Result, Service, Value
from orochi.website.notifications import html_to_slack_mrkdwn, send_external_notifications
from orochi.website.symbols_assistant import diagnose_symbols, retry_unsatisfied_plugins

pytestmark = pytest.mark.django_db


# =====================================================================
# #1661 — API progress observability
# =====================================================================
def test_api_progress_observability_endpoints(client, admin, dump):
    """AC1-AC3 (#1661): dump detail, plugin list, and /plugin/{name} expose states and row counts."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    dump.status = DUMP_STATUS_COMPLETED
    dump.symbol_status = SymbolStatus.OK
    dump.save(update_fields=["status", "symbol_status"])

    plugin, _ = Plugin.objects.get_or_create(
        name="windows.pslist.PsList",
        defaults={"operating_system": "Windows"},
    )
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_RUNNING)

    # 1. Dump detail exposes processing status and symbol_status
    detail = client.get(f"/api/dumps/{dump.index}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["status"] == DUMP_STATUS_COMPLETED
    assert body["symbol_status"] == SymbolStatus.OK

    # 2. /plugin/{name} returns HTTP 200 (not 500) with running state and 0 rows
    st_running = client.get(f"/api/dumps/{dump.index}/plugin/{plugin.name}")
    assert st_running.status_code == 200
    items = st_running.json()
    assert len(items) == 1
    assert items[0]["result"] == RESULT_STATUS_RUNNING
    assert items[0]["row_count"] == 0

    # Transition to SUCCESS with 3 stored rows
    Value.objects.bulk_create([Value(result=res, value={"PID": i}) for i in (4, 100, 200)])
    res.result = RESULT_STATUS_SUCCESS
    res.save()

    st_done = client.get(f"/api/dumps/{dump.index}/plugin/{plugin.name}")
    assert st_done.status_code == 200
    assert st_done.json()[0]["result"] == RESULT_STATUS_SUCCESS
    assert st_done.json()[0]["row_count"] == 3

    # 3. /plugins returns per-plugin result state and row count
    plist = client.get(f"/api/dumps/{dump.index}/plugins")
    assert plist.status_code == 200
    entry = next(p for p in plist.json() if p["name"] == plugin.name)
    assert entry["result"] == RESULT_STATUS_SUCCESS
    assert entry["row_count"] == 3


# =====================================================================
# #1662 — Linux DKOM terminated processes & COMM
# =====================================================================
def test_dkom_linux_four_case_fixture():
    """Regression test (#1662): only a genuinely unlinked live process is flagged, using COMM."""
    pslist = [
        {"PID": 100, "TID": 100, "COMM": "systemd", "EXIT_STATE": "0"},
    ]
    psscan = [
        # 1. Running thread (TID != PID) of visible process -> must NOT be flagged
        {"PID": 100, "TID": 105, "COMM": "systemd-worker", "EXIT_STATE": "0"},
        # 2. EXIT_ZOMBIE thread-group leader -> must NOT be flagged
        {"PID": 201, "TID": 201, "COMM": "bash", "EXIT_STATE": "EXIT_ZOMBIE"},
        # 3. EXIT_DEAD leader -> must NOT be flagged
        {"PID": 202, "TID": 202, "COMM": "sed", "EXIT_STATE": "EXIT_DEAD"},
        # 4. Genuinely unlinked live process (no kernel-object offset) -> MUST be flagged with COMM name
        {"PID": 666, "TID": 666, "COMM": "rootkit_agent", "EXIT_STATE": "0"},
    ]
    findings = evaluate_dkom_unlinked(pslist, psscan)
    assert len(findings) == 1
    f = findings[0]
    assert f.entity == "rootkit_agent (PID 666)"
    assert "Unknown" not in f.entity
    assert "T1014" not in f.mitre_technique


# =====================================================================
# #1664 & #1566 — Slack formatting (no HTML) & High-severity finding alerts
# =====================================================================
def test_slack_payload_contains_no_html_tags(admin):
    """Regression test (#1664): Slack text uses Slack mrkdwn with zero HTML tags."""
    admin.enable_notifications = True
    admin.notify_on_task_completion = True
    admin.notify_via_slack = True
    admin.notify_via_webhook = False
    admin.notify_via_email = False
    admin.save()
    Service.objects.create(name=SERVICE_SLACK, url="http://127.0.0.1:9998/slack", key="")

    html_msg = "Playbook <b>Windows Quick Malware Triage</b> launched for dump <b>NAME</b><br>Status: <b style='color:green'>OK</b>"
    with patch("orochi.website.notifications.requests.post") as mock_post:
        send_external_notifications(admin, "Playbook Launched", html_msg, event_type="task")

    assert mock_post.called
    text = mock_post.call_args.kwargs["json"]["text"]
    assert "<b>" not in text and "</b>" not in text and "<br>" not in text
    assert "*Windows Quick Malware Triage*" in text
    assert html_to_slack_mrkdwn("<b>hello</b>") == "*hello*"


def test_critical_finding_triggers_notification_respecting_preferences(admin):
    """Regression test (#1566): Critical finding notifies enabled channels and skips disabled ones."""
    admin.enable_notifications = True
    admin.notify_via_webhook = True
    admin.notify_via_slack = False
    admin.notify_via_email = False
    admin.save()
    Service.objects.create(name=SERVICE_WEBHOOK, url="http://127.0.0.1:9997/hook", key="")
    Service.objects.create(name=SERVICE_SLACK, url="http://127.0.0.1:9997/slack", key="")

    case = Case.objects.create(name="Incident 42", user=admin)
    with (
        patch("orochi.website.signals.notify_user"),
        patch("orochi.website.signals.close_old_connections"),
        patch("orochi.website.signals.threading.Thread") as mock_thread,
        patch("orochi.website.notifications.requests.post") as mock_post,
    ):
        mock_thread.side_effect = lambda target=None, *args, **kwargs: MagicMock(start=target)
        Finding.objects.create(
            case=case,
            severity="Critical",
            mitre_attack_technique="T1055",
            note="Injected shellcode in lsass.exe",
        )

    called_urls = [c.args[0] for c in mock_post.call_args_list]
    assert "http://127.0.0.1:9997/hook" in called_urls
    assert "http://127.0.0.1:9997/slack" not in called_urls


# =====================================================================
# #1553 — Smart Symbol Assistant (arch, wrong OS, wrong kernel, retry)
# =====================================================================
def test_symbol_assistant_32bit_windows_architecture(dump):
    """AC1 (#1553): 32-bit PAE Windows image reports x86 (PAE), not amd64."""
    dump.operating_system = "Windows"
    dump.save(update_fields=["operating_system"])
    info_plugin, _ = Plugin.objects.get_or_create(
        name="windows.info.Info",
        defaults={"operating_system": "Windows"},
    )
    res = Result.objects.create(dump=dump, plugin=info_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.bulk_create(
        [
            Value(result=res, value={"Variable": "Is64Bit", "Value": "False"}),
            Value(result=res, value={"Variable": "IsPAE", "Value": "True"}),
            Value(result=res, value={"Variable": "NtMajorVersion", "Value": "5"}),
            Value(result=res, value={"Variable": "NtMinorVersion", "Value": "1"}),
            Value(result=res, value={"Variable": "NTBuildLab", "Value": "2600.xpsp.080413-2111"}),
        ]
    )

    diag = diagnose_symbols(dump)
    assert diag["arch"] == "x86 (PAE)"
    assert diag["distro"] == "Windows XP"
    assert "2600" in (diag["kernel"] or "")
    assert any(a["type"] == "retry" for a in diag["actions"])


def test_symbol_assistant_detects_wrong_os_and_wrong_kernel(dump, tmp_path):
    """AC2 & AC3 (#1553): Detects wrong OS (Windows image registered as Linux) and wrong_kernel."""
    # Case A: Windows image registered as Linux
    fake_win = tmp_path / "winxp.raw"
    fake_win.write_bytes(b"\x00" * 128 + b"ntkrnlpa.exe\x00NTBuildLab" + b"\x00" * 128)
    dump.operating_system = "Linux"
    dump.banner = ""
    with open(fake_win, "rb") as f:
        dump.upload.save("winxp.raw", File(f))
    dump.save()

    diag_wrong_os = diagnose_symbols(dump)
    assert diag_wrong_os["symbol_status"] == SymbolStatus.UNSUPPORTED
    assert diag_wrong_os["remediation_type"] == "wrong_os"
    assert diag_wrong_os["detected_os"] == "Windows"

    # Case B: Linux dump with mismatched local symbol table -> wrong_kernel
    dump.banner = "Linux version 5.15.0-99-generic (buildd@lcy02) (gcc (Ubuntu 11.4.0) 11.4.0) #109-Ubuntu SMP x86_64"
    dump.save(update_fields=["banner"])
    fake_finder = MagicMock(_config_path="automagic.LinuxSymbolFinder")
    fake_finder.banners = [
        b"Linux version 5.15.0-72-generic (buildd@lcy02) (gcc (Ubuntu 11.4.0) 11.4.0) #79-Ubuntu SMP x86_64\n"
    ]
    with patch("orochi.website.symbols_assistant.automagic.available", return_value=[fake_finder]):
        diag_wk = diagnose_symbols(dump)
    assert diag_wk["symbol_status"] == SymbolStatus.WRONG_KERNEL


def test_symbol_assistant_retry_unsatisfied_plugins(admin, dump):
    """AC4 (#1553): Retry action re-runs plugins that failed with RESULT_STATUS_UNSATISFIED."""
    p1, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", defaults={"operating_system": "Linux"})
    p2, _ = Plugin.objects.get_or_create(name="linux.bash.Bash", defaults={"operating_system": "Linux"})
    r1 = Result.objects.create(dump=dump, plugin=p1, result=RESULT_STATUS_UNSATISFIED)
    r2 = Result.objects.create(dump=dump, plugin=p2, result=RESULT_STATUS_SUCCESS)

    with patch("orochi.website.views.common.index_f_and_f") as mock_submit:
        retried = retry_unsatisfied_plugins(dump, user=admin)

    assert retried == ["linux.pslist.PsList"]
    r1.refresh_from_db()
    r2.refresh_from_db()
    assert r1.result == RESULT_STATUS_RUNNING
    assert r2.result == RESULT_STATUS_SUCCESS
    mock_submit.assert_called_once()
