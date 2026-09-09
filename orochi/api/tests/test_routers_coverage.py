import json
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

from orochi.website.models import CustomRule, UserPlugin
from orochi.ya.models import Rule, Ruleset

pytestmark = pytest.mark.django_db


# ==============================================================================
# Rules router tests
# ==============================================================================
def test_rules_list_and_search(client, admin, tmp_path):
    client.force_login(admin)
    ruleset = Ruleset.objects.create(name="Community", user=admin, enabled=True)
    rule_file = tmp_path / "detect_test.yar"
    rule_file.write_text("rule Detect_Test { condition: true }")

    Rule.objects.create(
        ruleset=ruleset,
        path=str(rule_file),
        rule="rule Detect_Test { condition: true }",
        enabled=True,
    )

    # 1. List without search
    resp = client.get(
        "/api/rules/",
        {"draw": 1, "start": 0, "length": 10, "order_column": 1, "order_dir": "asc"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "data" in data
    assert len(data["data"]) >= 1

    # 2. Search query
    resp_search = client.get(
        "/api/rules/",
        {
            "draw": 2,
            "start": 0,
            "length": 10,
            "order_column": 1,
            "order_dir": "asc",
            "search": "Detect_Test",
        },
    )
    assert resp_search.status_code == 200
    search_data = resp_search.json()
    assert search_data["recordsFiltered"] == 1
    assert search_data["data"][0]["ruleset_name"] == "Community"
    assert "detect_test.yar" in search_data["data"][0]["path_name"]


def test_rules_edit_same_user(client, admin, tmp_path):
    client.force_login(admin)
    ruleset = Ruleset.objects.create(name="MyUserRules", user=admin, enabled=True)
    rule_file = tmp_path / "edit_test.yar"
    rule_file.write_text("rule BeforeEdit { condition: false }")

    rule = Rule.objects.create(
        ruleset=ruleset,
        path=str(rule_file),
        rule="rule BeforeEdit { condition: false }",
        enabled=True,
    )

    patch_data = {"text": "rule AfterEdit { condition: true }"}
    resp = client.patch(
        f"/api/rules/{rule.pk}",
        data=json.dumps(patch_data),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert "updated" in resp.json()["message"]
    rule.refresh_from_db()
    assert "AfterEdit" in rule.rule
    assert "AfterEdit" in rule_file.read_text()


def test_rules_download_and_delete(client, admin, tmp_path):
    client.force_login(admin)
    ruleset = Ruleset.objects.create(name="DownloadRules", user=admin, enabled=True)
    rule_file = tmp_path / "download_test.yar"
    rule_file.write_text("rule DownloadMe { condition: true }")

    rule = Rule.objects.create(
        ruleset=ruleset,
        path=str(rule_file),
        rule="rule DownloadMe { condition: true }",
        enabled=True,
    )

    # Download
    resp_dl = client.get(f"/api/rules/{rule.pk}/download")
    assert resp_dl.status_code == 200
    assert "DownloadMe" in resp_dl.content.decode()

    # Delete
    del_payload = {"rule_ids": [str(rule.pk)]}
    resp_del = client.delete(
        "/api/rules/",
        data=json.dumps(del_payload),
        content_type="application/json",
    )
    assert resp_del.status_code == 200
    assert not Rule.objects.filter(pk=rule.pk).exists()


def test_rules_upload_and_build(client, admin, tmp_path, monkeypatch):
    client.force_login(admin)
    monkeypatch.setattr(
        "extra_settings.models.Setting.get",
        lambda key, default=None: str(tmp_path),
    )
    ruleset = Ruleset.objects.create(name="UploadRuleset", user=admin, enabled=True)

    # 1. Upload rule
    yar_content = b'rule Uploaded_Rule { strings: $a = "sample" condition: $a }'
    upload_file = SimpleUploadedFile("uploaded_rule.yar", yar_content)

    resp_up = client.post("/api/rules/", data={"files": [upload_file]})
    assert resp_up.status_code == 200
    rules_data = resp_up.json()
    assert len(rules_data) == 1
    rule_id = rules_data[0]["id"]

    # 2. Build compiled rule
    with patch("os.makedirs"):
        with patch("builtins.open", create=True) as mock_open:
            mock_fp = MagicMock()
            mock_fp.read.return_value = (
                'rule Uploaded_Rule { strings: $a = "sample" condition: $a }'
            )
            mock_open.return_value.__enter__.return_value = mock_fp

            build_payload = {
                "rule_ids": [rule_id],
                "rulename": "my_compiled_ruleset",
            }
            resp_build = client.post(
                "/api/rules/build",
                data=json.dumps(build_payload),
                content_type="application/json",
            )
            assert resp_build.status_code == 200
            assert "created" in resp_build.json()["message"]
            assert CustomRule.objects.filter(
                name="my_compiled_ruleset", user=admin
            ).exists()


# ==============================================================================
# Customrules router tests
# ==============================================================================
def test_customrules_crud(client, admin, tmp_path):
    client.force_login(admin)
    cr_file = tmp_path / "custom_test.yar"
    cr_file.write_text("rule Custom_Test { condition: true }")

    cr = CustomRule.objects.create(
        name="CustomRule1",
        user=admin,
        path=str(cr_file),
        public=False,
    )

    # 1. List custom rules
    resp = client.get(
        "/api/customrules/",
        {"draw": 1, "start": 0, "length": 10, "order_column": 1, "order_dir": "asc"},
    )
    assert resp.status_code == 200
    assert any(item["name"] == "CustomRule1" for item in resp.json()["data"])

    # 2. Publish custom rule
    publish_payload = {"rule_ids": [str(cr.pk)], "action": "Publish"}
    resp_pub = client.post(
        "/api/customrules/publish",
        data=json.dumps(publish_payload),
        content_type="application/json",
    )
    assert resp_pub.status_code == 200
    cr.refresh_from_db()
    assert cr.public is True

    # 3. Unpublish custom rule
    unpublish_payload = {"rule_ids": [str(cr.pk)], "action": "Unpublish"}
    resp_unpub = client.post(
        "/api/customrules/publish",
        data=json.dumps(unpublish_payload),
        content_type="application/json",
    )
    assert resp_unpub.status_code == 200
    cr.refresh_from_db()
    assert cr.public is False

    # 4. Set default custom rule
    resp_def = client.post(f"/api/customrules/{cr.pk}/default")
    assert resp_def.status_code == 200
    cr.refresh_from_db()
    assert cr.default is True

    # 5. Download custom rule
    resp_dl = client.get(f"/api/customrules/{cr.pk}/download")
    assert resp_dl.status_code == 200
    assert "Custom_Test" in resp_dl.content.decode()

    # 6. Delete custom rule
    del_payload = {"rule_ids": [str(cr.pk)]}
    resp_del = client.delete(
        "/api/customrules/",
        data=json.dumps(del_payload),
        content_type="application/json",
    )
    assert resp_del.status_code == 200
    assert not CustomRule.objects.filter(pk=cr.pk).exists()


# ==============================================================================
# Plugins router tests
# ==============================================================================
def test_plugins_router_endpoints(client, admin, plugin):
    client.force_login(admin)

    # 1. List plugins
    resp_all = client.get("/api/plugins/")
    assert resp_all.status_code == 200
    assert any(p["name"] == plugin.name for p in resp_all.json())

    resp_os = client.get("/api/plugins/", {"operating_system": "Linux"})
    assert resp_os.status_code == 200

    # 2. Get specific plugin
    resp_get = client.get(f"/api/plugins/{plugin.name}")
    assert resp_get.status_code == 200
    assert resp_get.json()["name"] == plugin.name

    # 3. Get plugin parameters
    resp_params = client.get(f"/api/plugins/{plugin.name}/parameters")
    assert resp_params.status_code == 200

    # 4. Enable / disable plugin for user
    UserPlugin.objects.get_or_create(
        user=admin, plugin=plugin, defaults={"automatic": False}
    )

    resp_enable = client.post(f"/api/plugins/{plugin.name}/enable/true")
    assert resp_enable.status_code == 200
    up = UserPlugin.objects.get(user=admin, plugin=plugin)
    assert up.automatic is True

    resp_disable = client.post(f"/api/plugins/{plugin.name}/enable/false")
    assert resp_disable.status_code == 200
    up.refresh_from_db()
    assert up.automatic is False

    # 5. Update plugin metadata
    update_data = {"disabled": True, "local_dump": True}
    resp_put = client.put(
        f"/api/plugins/{plugin.name}",
        data=json.dumps(update_data),
        content_type="application/json",
    )
    assert resp_put.status_code == 200
    plugin.refresh_from_db()
    assert plugin.disabled is True
    assert plugin.local_dump is True


# ==============================================================================
# Users & Auth router tests
# ==============================================================================
def test_users_and_auth_lifecycle(client, admin):
    # 1. Me endpoint without auth
    resp_me_unauth = client.get("/api/users/me")
    assert resp_me_unauth.status_code == 401

    # 2. Me endpoint with auth
    client.force_login(admin)
    resp_me_auth = client.get("/api/users/me")
    assert resp_me_auth.status_code == 200
    assert resp_me_auth.json()["username"] == admin.username

    # 3. List users
    resp_users = client.get("/api/users/")
    assert resp_users.status_code == 200
    assert "items" in resp_users.json()

    # 4. Create user as superuser
    new_user_payload = {
        "username": "supertestuser",
        "email": "supertestuser@example.com",
        "password": "Password12345!",
        "first_name": "Super",
        "last_name": "Tester",
    }
    resp_create = client.post(
        "/api/users/",
        data=json.dumps(new_user_payload),
        content_type="application/json",
    )
    assert resp_create.status_code == 201
    user_model = get_user_model()
    created_user = user_model.objects.get(username="supertestuser")
    assert created_user.is_active

    # 5. Auth login with new user
    login_client = client.__class__()
    login_resp = login_client.post(
        "/api/auth/",
        data=json.dumps({"username": "supertestuser", "password": "Password12345!"}),
        content_type="application/json",
    )
    assert login_resp.status_code == 200
    assert login_resp.json()["username"] == "supertestuser"

    # 6. Auth logout
    logout_resp = login_client.delete("/api/auth/")
    assert logout_resp.status_code == 204

    # 7. Delete user
    resp_del_user = client.delete(f"/api/users/{created_user.username}")
    assert resp_del_user.status_code == 200
    assert not user_model.objects.filter(username="supertestuser").exists()


# ==============================================================================
# Admin router tests
# ==============================================================================
@patch("django.core.management.call_command")
def test_admin_router_endpoints(mock_call_command, client, admin):
    client.force_login(admin)

    # 1. Update rules
    resp_rules = client.get("/api/admin/rules/update")
    assert resp_rules.status_code == 200
    mock_call_command.assert_any_call("rules_sync", verbosity=0)

    # 2. Generate default rule
    resp_gen = client.get("/api/admin/rules/generate")
    assert resp_gen.status_code == 200
    mock_call_command.assert_any_call("generate_default_rule", verbosity=0)

    # 3. Update plugins
    resp_plug = client.get("/api/admin/plugins/update")
    assert resp_plug.status_code == 200
    mock_call_command.assert_any_call("plugins_sync", verbosity=0)


# ==============================================================================
# Symbols router tests
# ==============================================================================
def test_symbols_list_endpoint(client, admin):
    client.force_login(admin)
    resp = client.get(
        "/api/symbols/",
        {"draw": 1, "start": 0, "length": 10, "order_column": 1, "order_dir": "asc"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "data" in data
