"""Regression tests for Issue #1539: portable SHA-256-verified Case Bundle (.orochi.zip) export and import."""

import io
import json
import zipfile

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from orochi.website.case_bundle import BundleIntegrityError, export_case_bundle, import_case_bundle, verify_case_bundle
from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Case, CaseNote, Evidence, Finding, Plugin, Result, Value

pytestmark = pytest.mark.django_db


def test_case_bundle_round_trip_preserves_counts_and_member_hashes(client, admin, user, dump):
    """AC1-AC3 (#1539): Export on instance A, verify manifest SHA-256s, import into clean case for user B."""
    client.force_login(admin)
    case = Case.objects.create(name="Handover Case", user=admin, description="CERT handover test")
    p, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList", defaults={"operating_system": "Windows"})
    res = Result.objects.create(dump=dump, plugin=p, result=RESULT_STATUS_SUCCESS, parameter={"pid": 4})
    Value.objects.create(result=res, value={"PID": 4, "ImageFileName": "System"})

    ev = Evidence.objects.create(
        case=case,
        dump=dump,
        plugin=p.name,
        result_row={"PID": 4, "ImageFileName": "System"},
        name="System Process",
    )
    Finding.objects.create(
        case=case,
        evidence=ev,
        severity="High",
        mitre_attack_technique="T1055",
        tags=["injection"],
        note="Confirmed anomaly",
    )
    CaseNote.objects.create(case=case, author=admin, title="Analyst Summary", content="Initial triage notes.")

    # Export via API
    export_resp = client.get(f"/api/cases/{case.pk}/bundle")
    assert export_resp.status_code == 200
    assert ".orochi.zip" in export_resp["Content-Disposition"]

    manifest, verified = verify_case_bundle(export_resp.content)
    assert manifest["format_version"] == "1.0"
    assert "case.json" in manifest["members"]
    assert "dumps.json" in manifest["members"]
    assert "notes.json" in manifest["members"]
    assert any(path.startswith("results/") for path in manifest["members"])
    assert len(verified) == len(manifest["members"])

    # Import into another user's clean workspace via API
    client.force_login(user)
    upload = SimpleUploadedFile("handover.orochi.zip", export_resp.content, content_type="application/zip")
    imp_resp = client.post("/api/cases/import-bundle", data={"bundle": upload})
    assert imp_resp.status_code == 201, imp_resp.content

    imported = Case.objects.get(pk=imp_resp.json()["id"])
    assert imported.user == user
    assert imported.evidences.count() == 1
    assert imported.findings.count() == 1
    assert imported.notes.count() == 1
    assert imported.findings.first().mitre_attack_technique == "T1055"


def test_case_bundle_rejects_tampered_member(admin):
    """AC4 (#1539): Modifying any byte of a bundle member causes import to fail with BundleIntegrityError."""
    case = Case.objects.create(name="Tamper Case", user=admin)
    Finding.objects.create(case=case, severity="Critical", note="Original finding")
    raw_zip = export_case_bundle(case)

    # Tamper with findings.json without updating manifest.json
    tampered_buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw_zip), "r") as zin, zipfile.ZipFile(tampered_buf, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "findings.json":
                parsed = json.loads(data.decode("utf-8"))
                parsed[0]["note"] = "TAMPERED NOTE"
                data = json.dumps(parsed).encode("utf-8")
            zout.writestr(item, data)

    with pytest.raises(BundleIntegrityError, match="Integrity check failed"):
        import_case_bundle(tampered_buf.getvalue(), admin)


def test_import_never_links_dumps_the_user_cannot_see_and_restores_bundle_files(admin, user, dump, tmp_path, settings):
    """A bundle cannot grant access to another user's dump; files carried in it are restored, foreign paths dropped."""
    from pathlib import Path

    from guardian.shortcuts import assign_perm

    settings.MEDIA_ROOT = str(tmp_path)
    case = Case.objects.create(name="Linked Case", user=admin)
    p, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList", defaults={"operating_system": "Windows"})
    res = Result.objects.create(dump=dump, plugin=p, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res, value={"PID": 4})
    extracted = tmp_path / str(dump.index) / "file.bin"
    extracted.parent.mkdir(parents=True)
    extracted.write_bytes(b"MZ")
    Evidence.objects.create(case=case, dump=dump, plugin=p.name, extracted_file=str(extracted), name="file")
    Evidence.objects.create(case=case, dump=dump, plugin=p.name, extracted_file="/etc/passwd", name="foreign")
    raw_zip = export_case_bundle(case)

    imported = import_case_bundle(raw_zip, user)
    assert all(ev.dump is None for ev in imported.evidences.all())
    by_name = {ev.name: ev for ev in imported.evidences.all()}
    assert Path(by_name["file"].extracted_file).read_bytes() == b"MZ"
    assert by_name["foreign"].extracted_file is None
    assert list((tmp_path / "case_bundles" / str(imported.pk) / "results").glob("*.json"))
    assert imported.timeline_events.filter(event_type="Bundle Imported").exists()

    assign_perm("website.can_see", user, dump)
    again = import_case_bundle(raw_zip, user)
    assert all(ev.dump == dump for ev in again.evidences.all())


def test_bundle_carries_a_custody_log(admin, dump, tmp_path, settings):
    """#1674 FR-7/FR-8: the bundle lists who did what (audit), hash checks and plugin runs."""
    from orochi.website.models import IntegrityCheck, ResultRun, TimelineEvent

    settings.MEDIA_ROOT = str(tmp_path)
    case = Case.objects.create(name="Custody", user=admin)
    p, _ = Plugin.objects.get_or_create(name="windows.pslist.PsList", defaults={"operating_system": "Windows"})
    res = Result.objects.create(dump=dump, plugin=p, result=RESULT_STATUS_SUCCESS)
    ResultRun.objects.create(
        result=res,
        number=1,
        status=RESULT_STATUS_SUCCESS,
        user=admin,
        volatility_version="2.28.3",
        rows_sha256="ab" * 32,
        row_count=3,
    )
    IntegrityCheck.objects.create(dump=dump, kind="received", actual_sha256="cd" * 32, ok=True, user=admin)
    Evidence.objects.create(case=case, dump=dump, plugin=p.name, name="row")
    TimelineEvent.objects.create(
        case=case,
        timestamp="2008-11-26T07:31:00Z",
        event_type="Manual Entry",
        description="mail opened",
        created_by=admin,
    )

    manifest, files = verify_case_bundle(export_case_bundle(case))
    custody = json.loads(files["custody.json"])
    assert "custody.json" in manifest["members"]
    assert custody["runs"][0]["user"] == admin.username and custody["runs"][0]["volatility_version"] == "2.28.3"
    assert custody["integrity"][0]["kind"] == "received"
    timeline = json.loads(files["timeline.json"])
    assert any(t["created_by"] == admin.username for t in timeline)
