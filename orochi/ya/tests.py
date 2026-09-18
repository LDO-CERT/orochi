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
