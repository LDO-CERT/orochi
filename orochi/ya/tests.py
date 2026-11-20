from unittest.mock import MagicMock, patch

import pytest
from django.contrib.admin.sites import site
from django.core.management import call_command
from django.urls import reverse

from orochi.website.models import CustomRule
from orochi.ya.admin import RuleAdmin, RulesetAdmin
from orochi.ya.models import Rule, Ruleset

pytestmark = pytest.mark.django_db


# ==============================================================================
# Model tests
# ==============================================================================
def test_ruleset_and_rule_models(admin, tmp_path):
    ruleset = Ruleset.objects.create(
        name="TestRulesetModel",
        description="A ruleset for testing",
        enabled=True,
        user=admin,
    )
    assert str(ruleset) == "TestRulesetModel"
    assert ruleset.count_rules == 0

    rule_path = tmp_path / "model_rule.yar"
    rule_path.write_text("rule ModelRule { condition: true }")

    rule = Rule.objects.create(
        ruleset=ruleset,
        path=str(rule_path),
        rule="rule ModelRule { condition: true }",
        enabled=True,
    )
    assert ruleset.count_rules == 1
    assert str(rule) == f"[TestRulesetModel] {rule_path}"


# ==============================================================================
# Views tests
# ==============================================================================
def test_ya_upload_view(client, admin):
    client.force_login(admin)
    url = reverse("ya:upload")
    resp = client.get(url)
    assert resp.status_code == 200
    assert "html_form" in resp.json()


def test_ya_detail_view(client, admin, tmp_path):
    client.force_login(admin)
    ruleset = Ruleset.objects.create(name="DetailRuleset", user=admin)
    rule_path = tmp_path / "detail_rule.yar"
    rule_path.write_text('rule DetailRule { strings: $a = "sample" condition: $a }')

    rule = Rule.objects.create(
        ruleset=ruleset,
        path=str(rule_path),
        rule=rule_path.read_text(),
    )

    url = reverse("ya:detail")
    resp = client.get(url, {"pk": rule.pk})
    assert resp.status_code == 200
    assert "html_form" in resp.json()
    assert "DetailRule" in resp.json()["html_form"]


# ==============================================================================
# Admin Actions tests
# ==============================================================================
def test_ruleset_admin_actions(admin, rf):
    ruleset_admin = RulesetAdmin(Ruleset, site)
    request = rf.get("/admin/ya/ruleset/")
    request.user = admin

    ruleset = Ruleset.objects.create(name="AdminRuleset", enabled=True)
    qs = Ruleset.objects.filter(pk=ruleset.pk)

    # Test disable
    ruleset_admin.disable(request, qs)
    ruleset.refresh_from_db()
    assert ruleset.enabled is False

    # Test enable
    ruleset_admin.enable(request, qs)
    ruleset.refresh_from_db()
    assert ruleset.enabled is True


def test_rule_admin_actions(admin, rf, tmp_path):
    rule_admin = RuleAdmin(Rule, site)
    request = rf.get("/admin/ya/rule/")
    request.user = admin

    ruleset = Ruleset.objects.create(name="RuleAdminRuleset", enabled=True)
    valid_rule_path = tmp_path / "valid_rule.yar"
    valid_rule_path.write_text("rule ValidRule { condition: true }")

    rule = Rule.objects.create(
        ruleset=ruleset,
        path=str(valid_rule_path),
        enabled=True,
    )
    qs = Rule.objects.filter(pk=rule.pk)

    # 1. Test disable
    rule_admin.disable(request, qs)
    rule.refresh_from_db()
    assert rule.enabled is False

    # 2. Test enable
    rule_admin.enable(request, qs)
    rule.refresh_from_db()
    assert rule.enabled is True

    # 3. Test recompile valid rule
    rule_admin.recompile(request, qs)
    rule.refresh_from_db()
    assert rule.enabled is True
    assert rule.error is None

    # 4. Test recompile invalid rule
    invalid_rule_path = tmp_path / "invalid_rule.yar"
    invalid_rule_path.write_text("corrupted syntax not valid yara")
    bad_rule = Rule.objects.create(
        ruleset=ruleset,
        path=str(invalid_rule_path),
        enabled=True,
    )
    bad_qs = Rule.objects.filter(pk=bad_rule.pk)
    rule_admin.recompile(request, bad_qs)
    bad_rule.refresh_from_db()
    assert bad_rule.enabled is False
    assert bad_rule.error is not None


# ==============================================================================
# Management Commands tests
# ==============================================================================
@patch("orochi.ya.management.commands.rules_sync.sync_yara_rules")
def test_rules_sync_command(mock_sync_yara_rules):
    mock_result = MagicMock()
    mock_result.id = "mock-task-yara-sync-id"
    mock_sync_yara_rules.enqueue.return_value = mock_result

    call_command("rules_sync", verbosity=0)
    mock_sync_yara_rules.enqueue.assert_called_once()


def test_generate_default_rule_command(admin, tmp_path, monkeypatch):
    default_rule_path = tmp_path / "default_compiled.yara"
    monkeypatch.setattr(
        "extra_settings.models.Setting.get",
        lambda key, default=None: str(default_rule_path),
    )

    ruleset = Ruleset.objects.create(name="DefaultSyncRuleset", user=None, enabled=True)
    rule_path = tmp_path / "compile_me.yar"
    rule_path.write_text("rule DefaultCompileMe { condition: true }")

    Rule.objects.create(
        ruleset=ruleset,
        path=str(rule_path),
        rule="rule DefaultCompileMe { condition: true }",
        enabled=True,
    )

    call_command("generate_default_rule", verbosity=0)

    assert default_rule_path.exists()
    assert CustomRule.objects.filter(user=admin, path=str(default_rule_path)).exists()


# ==============================================================================
# Feed Updater & Worker Synchronization tests (Issue #1552 / #272)
# ==============================================================================
def test_ruleset_feed_sync_and_auto_update_fields():
    """Verify new feed tracking and auto-update fields on Ruleset model."""
    from django.utils import timezone

    ruleset = Ruleset.objects.create(
        name="FeedTrackingRuleset",
        url="https://github.com/Yara-Rules/rules",
        description="Public feed for tracking",
        auto_update=True,
    )
    assert ruleset.auto_update is True
    assert ruleset.last_sync is None
    assert ruleset.last_sync_status == "IDLE"

    now = timezone.now()
    ruleset.last_sync = now
    ruleset.last_sync_status = "SUCCESS"
    ruleset.save()
    ruleset.refresh_from_db()
    assert ruleset.last_sync == now
    assert ruleset.last_sync_status == "SUCCESS"


def test_compile_default_yara_rule_helper(admin, tmp_path, monkeypatch):
    """Test orochi.ya.rules_sync.compile_default_yara_rule."""
    from orochi.ya.rules_sync import compile_default_yara_rule

    default_path = tmp_path / "default.yara"
    monkeypatch.setattr("extra_settings.models.Setting.get", lambda key, default=None: str(default_path))

    ruleset = Ruleset.objects.create(name="HelperCompileRuleset", user=None, enabled=True)
    rule_file = tmp_path / "helper_rule.yar"
    rule_file.write_text('rule HelperRule { strings: $h = "test" condition: $h }')

    Rule.objects.create(
        ruleset=ruleset,
        path=str(rule_file),
        rule=rule_file.read_text(),
        enabled=True,
    )

    res = compile_default_yara_rule()
    assert res["success"] is True
    assert res["rules_count"] == 1
    assert default_path.exists()
    assert CustomRule.objects.filter(user=admin, path=str(default_path)).exists()


def test_sync_rules_to_workers_helper(monkeypatch):
    """Test orochi.ya.rules_sync.sync_rules_to_workers with mocked Dask client."""
    from orochi.ya.rules_sync import sync_rules_to_workers

    mock_client = MagicMock()
    mock_client.scheduler_info.return_value = {"workers": {"tcp://worker1:8786": {}, "tcp://worker2:8786": {}}}
    mock_client.gather.return_value = [
        {"status": "ok", "path": "/yara/default.yara", "size_bytes": 1024},
        {"status": "ok", "path": "/yara/default.yara", "size_bytes": 1024},
    ]

    with patch("dask.distributed.Client", return_value=mock_client):
        res = sync_rules_to_workers()
        assert res["worker_count"] == 2
        assert res["status"] == "synchronized"
        assert len(res["workers"]) == 2


def test_api_list_yara_feeds(client, admin):
    """Test GET /api/rules/feeds/ returns public feeds with stats."""
    client.force_login(admin)

    Ruleset.objects.create(
        name="PublicFeed1",
        url="https://github.com/example/feed1",
        description="Feed 1",
        user=None,
        auto_update=True,
        last_sync_status="SUCCESS",
    )
    Ruleset.objects.create(
        name="UserPrivateRuleset",
        user=admin,
        description="Private user ruleset",
    )

    resp = client.get("/api/rules/feeds/")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    feed_names = [f["name"] for f in data]
    assert "PublicFeed1" in feed_names
    assert "UserPrivateRuleset" not in feed_names


def test_api_sync_yara_feeds_and_toggle(client, admin):
    """Test POST /api/rules/feeds/sync and toggle_auto_update."""
    client.force_login(admin)

    feed = Ruleset.objects.create(
        name="ToggleFeed",
        url="https://github.com/example/feed-toggle",
        user=None,
        auto_update=True,
    )

    # 1. Toggle auto update
    resp = client.post(
        f"/api/rules/feeds/{feed.pk}/toggle_auto_update",
        data={"auto_update": False},
        content_type="application/json",
    )
    assert resp.status_code == 200
    feed.refresh_from_db()
    assert feed.auto_update is False

    # 2. Sync feeds API
    with patch("orochi.api.routers.rules.sync_yara_rules") as mock_sync:
        mock_res = MagicMock()
        mock_res.id = "task-sync-1234"
        mock_sync.enqueue.return_value = mock_res

        resp = client.post(
            "/api/rules/feeds/sync",
            data={"ruleset_id": feed.pk, "compile_default": True},
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert "task-sync-1234" in resp.json()["message"]
        mock_sync.enqueue.assert_called_once_with(
            ruleset_id=feed.pk,
            compile_default=True,
            force=False,
        )


def test_api_compile_default_and_sync_workers(client, admin):
    """Test POST /api/rules/compile_default and POST /api/rules/sync_workers."""
    client.force_login(admin)

    with (
        patch("orochi.api.routers.rules.compile_default_yara_rule", return_value={"success": True, "rules_count": 5}),
        patch(
            "orochi.api.routers.rules.sync_rules_to_workers", return_value={"worker_count": 2, "status": "synchronized"}
        ),
    ):
        # Test compile_default
        resp1 = client.post("/api/rules/compile_default")
        assert resp1.status_code == 200
        assert resp1.json()["success"] is True
        assert resp1.json()["rules_count"] == 5
        assert resp1.json()["workers"]["worker_count"] == 2

        # Test sync_workers
        resp2 = client.post("/api/rules/sync_workers")
        assert resp2.status_code == 200
        assert resp2.json()["worker_count"] == 2


def test_yara_forensic_toolkit_and_endpoints(client, admin, dump, plugin, settings, tmp_path, monkeypatch):
    """
    Test all 4 YARA forensic capabilities:
    1. Live YARA-X scan against text & uploaded sample file (`POST /api/rules/test`, `POST /api/rules/scan_file`)
    2. Extracted dump artifacts scan (`target_mode="dump_files"`, saving `.yara.json` sidecar)
    3. Indexed DB forensic retro-hunt (`target_mode="db_artifacts"`)
    4. Auto-generate YARA rule from malfind hexdump (`POST /api/rules/generate`) & YARA summary MITRE correlation
    """
    import json
    from pathlib import Path

    from django.core.files.uploadedfile import SimpleUploadedFile
    from guardian.shortcuts import assign_perm

    from orochi.website.defaults import RESULT_STATUS_SUCCESS
    from orochi.website.models import Plugin, Result, Value
    from orochi.website.plugin_summaries import build_plugin_analysis_summaries

    assign_perm("website.can_see", admin, dump)
    client.force_login(admin)

    yara_root = tmp_path / "yara_store"
    yara_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("extra_settings.models.Setting.get", lambda key, *a, **kw: str(yara_root))

    sample_rule = """rule Orochi_Beacon_Test {
    meta:
        author = "Orochi Team"
        description = "Detects synthetic beacon marker"
        mitre_att = "T1055.001"
    strings:
        $a = "EVIL_BEACON_MARKER" ascii
    condition:
        $a
}"""

    # 1. Live text scan
    resp_text = client.post(
        "/api/rules/test",
        data=json.dumps(
            {
                "rule_source": sample_rule,
                "target_mode": "text",
                "sample_text": "cmd.exe /c echo EVIL_BEACON_MARKER",
            }
        ),
        content_type="application/json",
    )
    assert resp_text.status_code == 200, resp_text.json()
    data_text = resp_text.json()
    assert data_text["matched"] is True
    assert data_text["matches"][0]["rule"] == "Orochi_Beacon_Test"
    assert "T1055.001" in data_text["matches"][0]["mitre_techniques"]

    # 2. Scan uploaded sample file
    sample_upload = SimpleUploadedFile("suspect.bin", b"\x00\x01EVIL_BEACON_MARKER\x90\x90")
    resp_file = client.post(
        "/api/rules/scan_file",
        data={"sample": sample_upload, "rule_source": sample_rule},
    )
    assert resp_file.status_code == 200, resp_file.json()
    assert resp_file.json()["matched"] is True

    # 3. Scan extracted dump files + save .yara.json sidecar
    dump_extract_dir = Path(settings.MEDIA_ROOT) / str(dump.index) / "windows.malfind.Malfind"
    dump_extract_dir.mkdir(parents=True, exist_ok=True)
    extracted_file = dump_extract_dir / "pid.1337.vad.0x400000.dmp"
    extracted_file.write_bytes(b"MZ\x90\x00...EVIL_BEACON_MARKER...")

    resp_dump_files = client.post(
        "/api/rules/test",
        data=json.dumps(
            {
                "rule_source": sample_rule,
                "target_mode": "dump_files",
                "dump_indexes": [str(dump.index)],
                "save_sidecars": True,
            }
        ),
        content_type="application/json",
    )
    assert resp_dump_files.status_code == 200, resp_dump_files.json()
    df_data = resp_dump_files.json()
    assert df_data["scanned_files"] >= 1
    assert df_data["matched_files"] == 1
    assert Path(f"{extracted_file}.yara.json").exists()

    # 4. Retro-hunt indexed DB artifacts
    res_obj = Result.objects.create(dump=dump, plugin=plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(result=res_obj, value={"PID": 1337, "Command": "EVIL_BEACON_MARKER --run"})

    resp_db = client.post(
        "/api/rules/test",
        data=json.dumps(
            {
                "rule_source": sample_rule,
                "target_mode": "db_artifacts",
                "dump_indexes": [str(dump.index)],
            }
        ),
        content_type="application/json",
    )
    assert resp_db.status_code == 200, resp_db.json()
    assert resp_db.json()["matched_rows"] >= 1

    # 5. Generate YARA rule from malfind hexdump and save to personal ruleset
    resp_gen = client.post(
        "/api/rules/generate",
        data=json.dumps(
            {
                "rule_name": "Malfind_Injected_Shellcode",
                "hex_dump": "0x00400000: 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ..............",
                "strings": ["ReflectiveLoader"],
                "dump_name": dump.name,
                "process_name": "svchost.exe",
                "pid": 1337,
                "mitre_technique": "T1055",
                "save_to_ruleset": True,
            }
        ),
        content_type="application/json",
    )
    assert resp_gen.status_code == 200, resp_gen.json()
    gen_data = resp_gen.json()
    assert gen_data["saved"] is True
    assert gen_data["rule_id"] is not None
    assert "4D 5A 90 00" in gen_data["rule_text"]
    assert "T1055" in gen_data["rule_text"]

    # 6. YARA summary ribbon with MITRE ATT&CK correlation
    yara_plugin, _ = Plugin.objects.get_or_create(name="yarascan.YaraScan", defaults={"operating_system": "Other"})
    yara_res = Result.objects.create(dump=dump, plugin=yara_plugin, result=RESULT_STATUS_SUCCESS)
    Value.objects.create(
        result=yara_res,
        value={"Rule": "Malfind_Injected_Shellcode", "PID": 1337, "Offset": "0x400000"},
    )
    summaries = build_plugin_analysis_summaries(
        "yarascan.YaraScan",
        Result.objects.filter(pk=yara_res.pk),
        {dump.index: "#00ff00"},
    )
    yara_sum = summaries["yara_summary"]
    assert yara_sum is not None
    assert yara_sum["total_hits"] == 1
    assert yara_sum["unique_rules"] == 1
    assert "T1055" in yara_sum["mitre_techniques"]
