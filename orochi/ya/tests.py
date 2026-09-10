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
