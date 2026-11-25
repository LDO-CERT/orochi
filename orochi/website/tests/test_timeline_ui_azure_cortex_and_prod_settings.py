"""Regression tests for pending tasks: Case Timeline UI (#1538), Azure Blob storage (#1562), Cortex analyzer (#1550), and DEBUG=False production settings (#256/#1576)."""

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.defaults import SERVICE_THEHIVE
from orochi.website.models import Case, Evidence, ForensicNode, Service, TimelineEvent

pytestmark = pytest.mark.django_db
ROOT = Path(__file__).resolve().parents[3]


# =====================================================================
# #1538 — Case Timeline UI (Manual Create/Delete & Artefact Separation)
# =====================================================================
def test_case_detail_ui_manual_timeline_and_artefact_separation(client, admin, dump):
    """UI test (#1538): Case detail renders artefact timeline separately and supports manual event add/delete."""
    client.force_login(admin)
    assign_perm("website.can_see", admin, dump)
    case = Case.objects.create(name="UI Timeline Case", user=admin)
    ForensicNode.objects.create(
        case=case,
        dump=dump,
        node_type="process",
        label="dropper.exe (PID 777)",
        first_seen=datetime(2024, 6, 1, 10, 0, 0, tzinfo=UTC),
    )

    url = reverse("website:case_detail", kwargs={"pk": case.pk})
    # Add manual event via UI POST
    add_resp = client.post(
        url,
        {
            "action": "add_timeline_event",
            "timestamp": "2024-06-01T10:05:00",
            "event_type": "Lateral Movement",
            "description": "PsExec observed on host",
        },
    )
    assert add_resp.status_code == 302
    manual_ev = TimelineEvent.objects.get(case=case, event_type="Lateral Movement")

    page = client.get(url)
    assert page.status_code == 200
    html = page.content.decode("utf-8")
    assert "Forensic Artefact &amp; Manual Time" in html
    assert "Analyst Activity Log" in html
    assert "dropper.exe (PID 777)" in html
    assert "PsExec observed on host" in html

    # Delete manual event via UI POST
    del_resp = client.post(url, {"action": "delete_timeline_event", "event_id": str(manual_ev.pk)})
    assert del_resp.status_code == 302
    assert not TimelineEvent.objects.filter(pk=manual_ev.pk).exists()


# =====================================================================
# #1562 — Azure Blob Storage Configuration
# =====================================================================
def test_azure_blob_storage_settings_configuration():
    """Verify USE_AZURE_STORAGE=True configures AzureStorage backend in config.settings.base."""
    code = (
        "import os; os.environ['USE_AZURE_STORAGE']='True'; "
        "os.environ['AZURE_ACCOUNT_NAME']='orochistorage'; "
        "os.environ['AZURE_CONTAINER']='dumps'; "
        "import config.settings.base as b; "
        "print(b.STORAGES['default']['BACKEND']); "
        "print(b.STORAGES['default']['OPTIONS']['azure_container'])"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, check=True)
    lines = proc.stdout.strip().splitlines()
    assert lines[0] == "storages.backends.azure_storage.AzureStorage"
    assert lines[1] == "dumps"


# =====================================================================
# #1550 — Cortex Analyzer Submission on Extracted Evidence File
# =====================================================================
def test_cortex_analyzer_submission_on_case_evidence(client, admin, dump, tmp_path, settings):
    """AC (#1550): POST /api/cases/{id}/cortex/analyze submits extracted file to Cortex analyzer."""
    settings.MEDIA_ROOT = str(tmp_path)
    dump_dir = tmp_path / str(dump.index)
    dump_dir.mkdir(parents=True, exist_ok=True)
    sample = dump_dir / "payload.bin"
    sample.write_bytes(b"MZ_SUSPICIOUS_PAYLOAD")

    Service.objects.create(name=SERVICE_THEHIVE, url="https://cortex.local:9001", key="cortex_secret_key")
    case = Case.objects.create(name="Cortex Case", user=admin)
    ev = Evidence.objects.create(
        case=case,
        dump=dump,
        plugin="windows.dumpfiles.DumpFiles",
        extracted_file=str(sample),
        name="payload.bin",
    )

    client.force_login(admin)
    fake_resp = MagicMock(status_code=200, content=b'{"_id": "job-42", "status": "Waiting"}')
    fake_resp.json.return_value = {"_id": "job-42", "status": "Waiting"}

    with patch("orochi.website.integrations.requests.post", return_value=fake_resp) as mock_post:
        resp = client.post(f"/api/cases/{case.pk}/cortex/analyze?evidence_id={ev.pk}&analyzer_id=FileInfo_8_0")

    assert resp.status_code == 200, resp.content
    data = resp.json()
    assert data["success"] is True
    assert data["job_id"] == "job-42"
    assert mock_post.call_args.args[0] == "https://cortex.local:9001/api/analyzer/FileInfo_8_0/run"


def test_cortex_never_sends_the_stored_key_to_a_caller_supplied_url(client, admin, dump, tmp_path, settings):
    """A ``cortex_url`` from the request is ignored: the stored key only goes to the configured Cortex."""
    settings.MEDIA_ROOT = str(tmp_path)
    dump_dir = tmp_path / str(dump.index)
    dump_dir.mkdir(parents=True, exist_ok=True)
    sample = dump_dir / "payload.bin"
    sample.write_bytes(b"MZ")
    Service.objects.create(name=SERVICE_THEHIVE, url="https://cortex.local:9001", key="cortex_secret_key")
    case = Case.objects.create(name="Cortex Leak Case", user=admin)
    ev = Evidence.objects.create(case=case, dump=dump, plugin="windows.dumpfiles.DumpFiles", extracted_file=str(sample))
    client.force_login(admin)
    fake_resp = MagicMock(status_code=200, content=b"{}")
    fake_resp.json.return_value = {}
    with patch("orochi.website.integrations.requests.post", return_value=fake_resp) as mock_post:
        client.post(
            f"/api/cases/{case.pk}/cortex/analyze?evidence_id={ev.pk}&analyzer_id=X&cortex_url=https://attacker.example"
        )
    assert mock_post.call_args.args[0].startswith("https://cortex.local:9001/")

    from orochi.website.integrations import run_cortex_analyzer

    with pytest.raises(ValueError):
        run_cortex_analyzer(dump, str(sample), "X", cortex_url="https://attacker.example")


# =====================================================================
# #256 & #1576 — Production Settings Verification (DEBUG=False)
# =====================================================================
def test_production_settings_load_with_debug_false():
    """Verify config.settings.production loads cleanly with DEBUG=False when DJANGO_SECRET_KEY is set."""
    env = os.environ.copy()
    env.setdefault("DATABASE_URL", "postgresql://debug:debug@localhost:5432/orochi")
    env.setdefault("DASK_SCHEDULER_URL", "tcp://localhost:8786")
    env.setdefault("REDIS_URL", "redis://localhost:6379/0")
    env.setdefault("REDIS_SERVER", "localhost")
    env.setdefault("REDIS_PORT", "6379")
    env.setdefault("DJANGO_ADMIN_URL", "admin/")
    env.setdefault("DEFAULT_YARA_RULE_PATH", "/yara/default.yara")
    env.setdefault("LOCAL_YARA_PATH", "/yara")
    env.setdefault("VOLATILITY_SYMBOL_PATH", "/symbols")
    env.setdefault("VOLATILITY_PLUGIN_PATH", "/plugins")
    env["DJANGO_SECRET_KEY"] = "test-prod-secret-key-for-settings-check-1234567890"
    env["ALLOWED_HOSTS"] = "orochi.example.org"
    code = (
        "import config.settings.production as p; "
        "assert p.DEBUG is False; "
        "assert 'orochi.example.org' in p.ALLOWED_HOSTS; "
        "print('OK')"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], cwd=str(ROOT), env=env, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "OK"
