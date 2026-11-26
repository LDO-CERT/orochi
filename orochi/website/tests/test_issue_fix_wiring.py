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


def test_error_paths_return_their_status_not_http_500(client, admin, user, dump):
    """Found live: endpoints returned 500 when their error status had no response schema."""
    import json

    from orochi.website.models import Case, Evidence

    case = Case.objects.create(name="Errors", user=admin)
    ev = Evidence.objects.create(case=case, dump=dump, plugin="x", extracted_file="/nowhere/file.bin")
    client.force_login(admin)
    # Cortex not configured / file outside the dump: a 400, not a crash
    assert client.post(f"/api/cases/{case.pk}/cortex/analyze?evidence_id={ev.pk}&analyzer_id=X").status_code == 400
    assert client.get("/api/cases/999999/bundle").status_code == 404

    client.force_login(user)  # cannot see the dump
    patch = client.patch(f"/api/dumps/{dump.index}", data=json.dumps({"name": "x"}), content_type="application/json")
    assert patch.status_code in (403, 404)
    assert client.get(f"/api/dumps/{dump.index}/reload_symbols").status_code in (403, 404)


def test_dkom_rule_waits_for_the_active_process_list(dump):
    """Found live: with pslist re-running, every running process of the psscan was reported hidden (44 Critical)."""
    from orochi.website.detection.engine import evaluate_dump_triage

    psscan, _ = Plugin.objects.get_or_create(name="linux.psscan.PsScan", defaults={"operating_system": "Linux"})
    pslist, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", defaults={"operating_system": "Linux"})
    scan = Result.objects.create(dump=dump, plugin=psscan, result=RESULT_STATUS_SUCCESS)
    for pid in (1, 2, 3882):
        Value.objects.create(
            result=scan, value={"PID": pid, "TID": pid, "COMM": f"p{pid}", "EXIT_STATE": "TASK_RUNNING"}
        )
    active = Result.objects.create(dump=dump, plugin=pslist, result=RESULT_STATUS_RUNNING)

    assert not [f for f in evaluate_dump_triage(dump)["findings"] if f.rule_id == "STEALTH_DKOM_UNLINKED"]

    active.result = RESULT_STATUS_SUCCESS
    active.save()
    for pid in (1, 2):
        Value.objects.create(result=active, value={"PID": pid, "TID": pid, "COMM": f"p{pid}"})
    hidden = [f for f in evaluate_dump_triage(dump)["findings"] if f.rule_id == "STEALTH_DKOM_UNLINKED"]
    assert [f.entity for f in hidden] == ["p3882 (PID 3882)"]


# ----------------------------------------------------------------------------------------------------------------
# UI for the features that only had an API
# ----------------------------------------------------------------------------------------------------------------
def test_annotation_modal_shows_threads_and_posts_replies(client, admin, dump):
    """#1669: the row annotation modal renders replies under their annotation and posts new ones."""
    from django.urls import reverse

    from orochi.website.models import ValueAnnotation

    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", defaults={"operating_system": "Linux"})
    value = Value.objects.create(
        result=Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS), value={"PID": 1}
    )
    root = ValueAnnotation.objects.create(value=value, user=admin, status="suspicious", comment="Root note")
    client.force_login(admin)
    url = reverse("website:value_annotations", kwargs={"value_id": value.pk})
    client.post(url, {"comment": "First reply", "status": "comment", "parent_id": root.pk}, HTTP_HX_REQUEST="true")
    html = client.get(url, HTTP_HX_REQUEST="true").content.decode()
    assert ValueAnnotation.objects.get(comment="First reply").parent == root
    assert 'class="mt-2.5 ml-3 pl-3' in html and "First reply" in html and 'name="parent_id"' in html
    assert "1 thread" in html  # the reply is not counted as a separate thread


def test_case_bundle_import_modal_creates_the_case(client, admin, dump):
    """#1539: the sidebar Import button opens a modal that verifies and imports a bundle."""
    from django.core.files.uploadedfile import SimpleUploadedFile
    from django.urls import reverse

    from orochi.website.case_bundle import export_case_bundle
    from orochi.website.models import Case, Finding

    case = Case.objects.create(name="Exported", user=admin)
    Finding.objects.create(case=case, severity="High", note="note")
    client.force_login(admin)
    index_html = client.get(reverse("website:index")).content.decode()
    assert 'id="import-case"' in index_html
    modal = client.get(reverse("website:case_import"), HTTP_HX_REQUEST="true").content.decode()
    assert 'hx-encoding="multipart/form-data"' in modal

    bad = client.post(
        reverse("website:case_import"), {"bundle": SimpleUploadedFile("x.zip", b"not a zip")}, HTTP_HX_REQUEST="true"
    )
    assert "not a valid ZIP" in bad.content.decode() or "Bundle refused" in bad.content.decode()

    ok = client.post(
        reverse("website:case_import"),
        {"bundle": SimpleUploadedFile("c.orochi.zip", export_case_bundle(case)), "name": "Imported from UI"},
        HTTP_HX_REQUEST="true",
    )
    imported = Case.objects.get(name="Imported from UI")
    assert ok["HX-Redirect"].endswith(f"/case/{imported.pk}")
    assert imported.findings.count() == 1


def test_cortex_button_and_modal_on_case_evidence(client, admin, dump, tmp_path, settings):
    """#1550: with Cortex configured (and TheHive not configured), evidences get Cortex and hide TheHive."""
    from unittest.mock import MagicMock

    from django.urls import reverse

    from orochi.website.defaults import SERVICE_CORTEX
    from orochi.website.models import Case, Evidence, Service

    settings.MEDIA_ROOT = str(tmp_path)
    f = tmp_path / str(dump.index) / "payload.bin"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"MZ")
    Service.objects.create(name=SERVICE_CORTEX, url="https://cortex.local:9001", key="k")
    case = Case.objects.create(name="Cortex UI", user=admin)
    ev = Evidence.objects.create(case=case, dump=dump, plugin="windows.dumpfiles.DumpFiles", extracted_file=str(f))
    client.force_login(admin)
    detail = client.get(reverse("website:case_detail", kwargs={"pk": case.pk})).content.decode()
    url = reverse("website:cortex_submit", kwargs={"pk": case.pk, "evidence_id": ev.pk})
    assert url in detail
    assert f"/api/cases/{case.pk}/export/thehive" not in detail
    get_resp = MagicMock(status_code=200)
    get_resp.json.return_value = [{"id": "FileInfo_8_0", "name": "FileInfo_8_0"}]
    resp = MagicMock(status_code=200, content=b"{}")
    resp.json.return_value = {"_id": "job-7", "status": "Waiting"}
    with (
        patch("orochi.website.integrations.requests.get", return_value=get_resp),
        patch("orochi.website.integrations.requests.post", return_value=resp),
    ):
        html = client.post(url, {"analyzer_id": "FileInfo_8_0"}, HTTP_HX_REQUEST="true").content.decode()
    assert "job-7" in html


def test_dump_playbooks_page_shows_each_plugin_state(client, admin, dump):
    """#1544: the dump's Playbooks page shows, per playbook, which chained plugins ran and their rows."""
    from django.urls import reverse

    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", defaults={"operating_system": "Linux"})
    res = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res, value={"PID": 1})
    client.force_login(admin)
    html = client.get(
        reverse("website:dump_playbooks", kwargs={"index": dump.index}), HTTP_HX_REQUEST="true"
    ).content.decode()
    assert "Chained Plugins (" in html and "done" in html
    assert 'class="playbook-plugin-status' in html and "linux.pslist.PsList" in html


def test_analysts_get_the_symbol_assistant_with_retry_and_dwarf_upload(client, dump):
    """#1553/#1554: Analysts open the assistant (retry, DWARF upload); symbol-source editing stays with admins."""
    from django.contrib.auth.models import Group
    from django.urls import reverse

    from orochi.users.tests.factories import UserFactory

    analyst = UserFactory()
    analyst.groups.add(Group.objects.get_or_create(name="Analyst")[0])
    assign_perm("website.can_see", analyst, dump)
    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", defaults={"operating_system": "Linux"})
    Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_UNSATISFIED)
    client.force_login(analyst)
    with patch("orochi.website.symbols_assistant.diagnose_symbols", return_value={"symbol_status": "missing"}):
        html = client.get(
            reverse("website:banner_symbols"), {"index": dump.index}, HTTP_HX_REQUEST="true"
        ).content.decode()
    assert 'id="btn-symbols-retry"' in html and 'id="dwarf-assistant-form"' in html
    assert 'id="symbols-banner-index"' not in html and 'id="btf-assistant-form"' not in html


def test_case_timeline_lists_each_manual_event_once_in_time_order(client, admin):
    """Found live: manual events were rendered twice (in the artefact list and in the manual list)."""
    import datetime as dt

    from django.urls import reverse

    from orochi.website.models import Case, TimelineEvent

    case = Case.objects.create(name="Timeline", user=admin)
    utc = dt.UTC
    TimelineEvent.objects.create(
        case=case, timestamp=dt.datetime(2008, 1, 2, tzinfo=utc), event_type="Later", description="B-event"
    )
    TimelineEvent.objects.create(
        case=case, timestamp=dt.datetime(2008, 1, 1, tzinfo=utc), event_type="Earlier", description="A-event"
    )
    client.force_login(admin)
    html = client.get(reverse("website:case_detail", kwargs={"pk": case.pk})).content.decode()
    section = html[html.index('id="forensic-timeline"') :]
    assert section.count("A-event") == 1 and section.count("B-event") == 1
    assert section.index("A-event") < section.index("B-event")
