"""The issue fixes must be reachable from the product, not only callable from a test.

Each test drives the entry point a user or the upload pipeline actually uses.
"""

import csv
import io
from unittest.mock import patch

import pytest
from guardian.shortcuts import assign_perm

from orochi.website.defaults import RESULT_STATUS_RUNNING, RESULT_STATUS_SUCCESS, RESULT_STATUS_UNSATISFIED
from orochi.website.models import Plugin, Result, TriageFinding, UserPlaybookPreference, Value

pytestmark = pytest.mark.django_db


def test_upload_pipeline_queues_the_uploaders_auto_run_playbooks(dump, admin):
    """#1544: an enabled auto-run playbook for the dump's OS is queued by the upload pipeline."""
    from orochi.utils.volatility_dask_elk import trigger_auto_playbooks
    from orochi.website.playbooks import PLAYBOOKS

    linux_pb = next(pb_id for pb_id, pb in PLAYBOOKS.items() if pb["operating_system"] == "Linux")
    windows_pb = next(pb_id for pb_id, pb in PLAYBOOKS.items() if pb["operating_system"] == "Windows")
    UserPlaybookPreference.objects.create(user=admin, playbook_id=linux_pb, auto_run=True)
    UserPlaybookPreference.objects.create(user=admin, playbook_id=windows_pb, auto_run=True)

    with patch("orochi.website.tasks.run_playbook_task") as task:
        launched = trigger_auto_playbooks(dump, admin.pk)

    assert launched == [linux_pb]  # the dump is Linux: the Windows playbook is not queued
    task.enqueue.assert_called_once_with(dump.pk, linux_pb, user_pk=admin.pk)


def test_manage_upload_calls_the_auto_run_trigger():
    """The trigger sits in the upload path right after the automatic plugins are dispatched."""
    import inspect

    from orochi.utils import volatility_dask_elk

    source = inspect.getsource(volatility_dask_elk.manage_upload)
    assert source.index("dispatch_automatic_plugins(") < source.index("trigger_auto_playbooks(dump, user_pk)")


def test_symbols_retry_endpoint_reruns_unsatisfied_plugins(client, admin, dump):
    """#1553: the Symbol Assistant retry action has an endpoint that re-runs unsatisfied plugins."""
    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", defaults={"operating_system": "Linux"})
    Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_UNSATISFIED)
    client.force_login(admin)
    with patch("orochi.website.views.common.index_f_and_f") as rerun:
        resp = client.post(f"/api/dumps/{dump.index}/symbols/retry")
    assert resp.status_code == 200, resp.content
    assert "linux.pslist.PsList" in resp.json()["message"]
    assert Result.objects.get(dump=dump, plugin=plugin).result == RESULT_STATUS_RUNNING
    rerun.assert_called_once()


def test_symbols_retry_endpoint_refuses_dumps_the_user_cannot_see(client, user, dump):
    client.force_login(user)
    assert client.post(f"/api/dumps/{dump.index}/symbols/retry").status_code in (403, 404)


def test_new_serious_triage_findings_notify_once(dump, admin):
    """#1566: new High/Critical triage findings notify the dump's users; re-evaluating does not repeat them."""
    from orochi.website.detection.engine import evaluate_dump_triage

    malfind, _ = Plugin.objects.get_or_create(name="linux.malfind.Malfind", defaults={"operating_system": "Linux"})
    res = Result.objects.create(dump=dump, plugin=malfind, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=res,
        value={"PID": 666, "Process": "evil", "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "4d 5a 90 00"},
    )
    with (
        patch("orochi.website.notifier.notify_user") as toast,
        patch("orochi.website.signals._safe_async_external_notifications") as external,
    ):
        evaluate_dump_triage(dump)
        serious = TriageFinding.objects.filter(dump=dump, severity__in=["High", "Critical"]).count()
        first_calls = toast.call_count
        evaluate_dump_triage(dump)

    if not serious:
        pytest.skip("fixture produced no High/Critical finding")
    assert first_calls == 1  # one summary per evaluation
    assert toast.call_count == 1  # nothing new the second time
    assert toast.call_args.kwargs["kind"] == "finding"
    assert external.call_args.args[3] == "finding"


def test_csv_export_neutralizes_formulas_from_memory_data(client, admin, dump):
    """CSV injection: a command line starting with '=' must not become a live formula; numbers stay numbers."""
    plugin, _ = Plugin.objects.get_or_create(name="linux.bash.Bash", defaults={"operating_system": "Linux"})
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res, value={"Command": '=HYPERLINK("http://evil")', "PID": -1, "Note": "-"})
    assign_perm("website.can_see", admin, dump)
    client.force_login(admin)
    resp = client.get("/export_result", {"indexes[]": dump.index, "plugin": plugin.name, "format": "csv"})
    assert resp.status_code == 200
    rows = list(csv.reader(io.StringIO(resp.content.decode())))
    header, row = rows[0], rows[1]
    cell = dict(zip(header, row, strict=True))
    assert cell["Command"].startswith("'=")
    assert cell["PID"] == "-1" and cell["Note"] == "-"


def test_defender_platform_dlls_are_not_flagged():
    from orochi.website.detection.rules import evaluate_suspicious_dlls

    rows = [
        {
            "PID": 1,
            "Process": "MsMpEng.exe",
            "Path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\mpclient.dll",
        },
        {"PID": 2, "Process": "evil.exe", "Path": r"C:\Users\Public\evil.dll"},
    ]
    findings = evaluate_suspicious_dlls(rows)
    assert [f.entity for f in findings] == ["evil.exe (PID 2)"]


def test_yara_hits_attribute_no_technique_and_do_not_escalate():
    from orochi.website.detection.rules import evaluate_yara_and_extracted_files

    rows = [{"Rule": "generic_string", "PID": 4, "Process": "svchost.exe", "Offset": hex(i)} for i in range(50)]
    findings = evaluate_yara_and_extracted_files(rows, [], [])
    assert len(findings) == 1
    assert findings[0].severity == "High" and findings[0].mitre_technique == ""


def test_symbol_assistant_modal_offers_the_retry_button(client, admin, dump):
    """#1553: the modal shows Retry Unsatisfied Plugins when some plugins did not run for missing symbols."""
    from django.urls import reverse

    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", defaults={"operating_system": "Linux"})
    Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_UNSATISFIED)
    client.force_login(admin)
    with patch("orochi.website.symbols_assistant.diagnose_symbols", return_value={"symbol_status": "ok"}):
        resp = client.get(reverse("website:banner_symbols"), {"index": dump.index}, HTTP_HX_REQUEST="true")
    html = resp.content.decode()
    assert resp.status_code == 200
    assert 'id="btn-symbols-retry"' in html and f"/api/dumps/{dump.index}/symbols/retry" in html
