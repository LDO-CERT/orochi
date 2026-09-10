import json

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.website.models import Plugin, Result, UserPlugin
from orochi.website.roles import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_READONLY,
    ROLE_REVIEWER,
    can_execute_plugin,
    get_user_role,
    has_role,
    set_user_role,
)
from orochi.website.templatetags.custom_tags import (
    can_run_plugin_filter,
    has_role_filter,
)
from orochi.website.templatetags.custom_tags import user_role as user_role_filter

User = get_user_model()


@pytest.mark.django_db
def test_role_resolution_and_hierarchy(admin, analyst_user, reviewer_user, readonly_user):
    """Test resolution of roles and hierarchy comparisons."""
    # Default unassigned user
    plain_user = User.objects.create_user("plain", "plain@example.com", "pass")
    assert get_user_role(plain_user) == ROLE_ANALYST

    # Fixture roles
    assert get_user_role(admin) == ROLE_ADMIN
    assert get_user_role(analyst_user) == ROLE_ANALYST
    assert get_user_role(reviewer_user) == ROLE_REVIEWER
    assert get_user_role(readonly_user) == ROLE_READONLY
    assert get_user_role(AnonymousUser()) == ROLE_READONLY
    assert get_user_role(None) == ROLE_READONLY

    # Hierarchy checks
    # Admin satisfies all
    assert has_role(admin, ROLE_ADMIN) is True
    assert has_role(admin, ROLE_ANALYST) is True
    assert has_role(admin, ROLE_REVIEWER) is True
    assert has_role(admin, ROLE_READONLY) is True

    # Analyst
    assert has_role(analyst_user, ROLE_ADMIN) is False
    assert has_role(analyst_user, ROLE_ANALYST) is True
    assert has_role(analyst_user, ROLE_REVIEWER) is True
    assert has_role(analyst_user, ROLE_READONLY) is True

    # Reviewer
    assert has_role(reviewer_user, ROLE_ADMIN) is False
    assert has_role(reviewer_user, ROLE_ANALYST) is False
    assert has_role(reviewer_user, ROLE_REVIEWER) is True
    assert has_role(reviewer_user, ROLE_READONLY) is True

    # ReadOnly
    assert has_role(readonly_user, ROLE_ADMIN) is False
    assert has_role(readonly_user, ROLE_ANALYST) is False
    assert has_role(readonly_user, ROLE_REVIEWER) is False
    assert has_role(readonly_user, ROLE_READONLY) is True


@pytest.mark.django_db
def test_set_user_role():
    """Test transitioning a user across all 4 roles."""
    user = User.objects.create_user("test_transition", "transition@example.com", "pass")
    assert get_user_role(user) == ROLE_ANALYST

    set_user_role(user, ROLE_REVIEWER)
    assert get_user_role(user) == ROLE_REVIEWER
    assert user.is_staff is False

    set_user_role(user, ROLE_ADMIN)
    assert get_user_role(user) == ROLE_ADMIN
    assert user.is_staff is True

    set_user_role(user, ROLE_READONLY)
    assert get_user_role(user) == ROLE_READONLY
    assert user.is_staff is False

    with pytest.raises(ValueError):
        set_user_role(user, "NonExistentRole")


@pytest.mark.django_db
def test_plugin_execution_permissions(admin, analyst_user, reviewer_user, readonly_user):
    """Test per-plugin execution permissions across role tiers."""
    admin_plugin = Plugin.objects.create(
        name="windows.dumpfiles.DumpFiles",
        operating_system="Windows",
        min_role=ROLE_ADMIN,
    )
    analyst_plugin = Plugin.objects.create(
        name="windows.pslist.PsList",
        operating_system="Windows",
        min_role=ROLE_ANALYST,
    )
    reviewer_plugin = Plugin.objects.create(
        name="windows.info.Info",
        operating_system="Windows",
        min_role=ROLE_REVIEWER,
    )
    disabled_plugin = Plugin.objects.create(
        name="windows.disabled.Test",
        operating_system="Windows",
        min_role=ROLE_REVIEWER,
        disabled=True,
    )

    # Admin execution
    assert can_execute_plugin(admin, admin_plugin) is True
    assert can_execute_plugin(admin, analyst_plugin) is True
    assert can_execute_plugin(admin, reviewer_plugin) is True
    assert can_execute_plugin(admin, disabled_plugin) is False

    # Analyst execution
    assert can_execute_plugin(analyst_user, admin_plugin) is False
    assert can_execute_plugin(analyst_user, analyst_plugin) is True
    assert can_execute_plugin(analyst_user, reviewer_plugin) is True
    assert can_execute_plugin(analyst_user, disabled_plugin) is False

    # Reviewer execution
    assert can_execute_plugin(reviewer_user, admin_plugin) is False
    assert can_execute_plugin(reviewer_user, analyst_plugin) is False
    assert can_execute_plugin(reviewer_user, reviewer_plugin) is True

    # ReadOnly execution
    assert can_execute_plugin(readonly_user, admin_plugin) is False
    assert can_execute_plugin(readonly_user, analyst_plugin) is False
    assert can_execute_plugin(readonly_user, reviewer_plugin) is False

    # User-level overrides
    up_reviewer, _ = UserPlugin.objects.get_or_create(user=reviewer_user, plugin=analyst_plugin)
    assert can_execute_plugin(reviewer_user, analyst_plugin) is False
    # Explicit grant override
    up_reviewer.can_execute = True
    up_reviewer.save()
    assert can_execute_plugin(reviewer_user, analyst_plugin) is True

    # Explicit deny override on Analyst
    up_analyst, _ = UserPlugin.objects.get_or_create(user=analyst_user, plugin=analyst_plugin)
    up_analyst.can_execute = False
    up_analyst.save()
    assert can_execute_plugin(analyst_user, analyst_plugin) is False

    # Reset override to None -> follows role default
    up_analyst.can_execute = None
    up_analyst.save()
    assert can_execute_plugin(analyst_user, analyst_plugin) is True


@pytest.mark.django_db
def test_parameters_view_permission_check(client, admin, reviewer_user, dump):
    """Test parameters view enforces can_execute_plugin."""
    admin_plugin = Plugin.objects.create(
        name="windows.dumpfiles.DumpFiles",
        operating_system="Windows",
        min_role=ROLE_ADMIN,
    )
    assign_perm("can_see", reviewer_user, dump)

    # Reviewer attempting to access parameters for Admin-only plugin -> 403
    client.force_login(reviewer_user)
    resp = client.get(
        reverse("website:parameters"),
        {"selected_plugin": admin_plugin.name, "selected_indexes[]": [dump.index]},
    )
    assert resp.status_code == 403

    # Admin accessing parameters for Admin plugin -> 200
    client.force_login(admin)
    resp = client.get(
        reverse("website:parameters"),
        {"selected_plugin": admin_plugin.name, "selected_indexes[]": [dump.index]},
    )
    assert resp.status_code == 200


@pytest.mark.django_db
def test_api_dumps_plugins_exposes_permissions(client, admin, reviewer_user, dump):
    """Test /api/dumps/{pks}/plugins outputs can_execute and min_role."""
    assign_perm("can_see", reviewer_user, dump)
    p_admin = Plugin.objects.create(
        name="windows.dumpfiles.DumpFiles",
        operating_system="Windows",
        min_role=ROLE_ADMIN,
    )
    p_reviewer = Plugin.objects.create(
        name="windows.info.Info",
        operating_system="Windows",
        min_role=ROLE_REVIEWER,
    )
    Result.objects.create(dump=dump, plugin=p_admin)
    Result.objects.create(dump=dump, plugin=p_reviewer)

    # Reviewer perspective
    client.force_login(reviewer_user)
    resp = client.get(f"/api/dumps/{dump.index}/plugins")
    assert resp.status_code == 200
    data = resp.json()

    plugin_map = {item["name"]: item for item in data}
    assert plugin_map[p_admin.name]["can_execute"] is False
    assert plugin_map[p_admin.name]["min_role"] == ROLE_ADMIN
    assert plugin_map[p_reviewer.name]["can_execute"] is True
    assert plugin_map[p_reviewer.name]["min_role"] == ROLE_REVIEWER

    # Admin perspective
    client.force_login(admin)
    resp = client.get(f"/api/dumps/{dump.index}/plugins")
    assert resp.status_code == 200
    admin_data = resp.json()
    admin_plugin_map = {item["name"]: item for item in admin_data}
    assert admin_plugin_map[p_admin.name]["can_execute"] is True


@pytest.mark.django_db
def test_api_dumps_plugin_execute_enforcement(client, admin, reviewer_user, dump):
    """Test /api/dumps/{pks}/plugin/{plugin}/execute endpoint blocks unauthorized roles."""
    assign_perm("can_see", reviewer_user, dump)
    p_admin = Plugin.objects.create(
        name="windows.dumpfiles.DumpFiles",
        operating_system="Windows",
        min_role=ROLE_ADMIN,
    )
    UserPlugin.objects.create(user=reviewer_user, plugin=p_admin)
    Result.objects.create(dump=dump, plugin=p_admin)

    client.force_login(reviewer_user)
    resp = client.post(
        f"/api/dumps/{dump.index}/plugin/{p_admin.name}/execute",
        data={"payload": json.dumps({})},
    )
    assert resp.status_code == 403
    assert "Permission Denied" in resp.json()["errors"]


@pytest.mark.django_db
def test_api_plugin_install_and_update_admin_only(client, admin, analyst_user):
    """Test plugin installation and modification requires Admin role."""
    client.force_login(analyst_user)
    resp = client.post(
        "/api/plugins/install",
        data=json.dumps({"plugin_url": "https://example.com/p.zip", "operating_system": "Windows"}),
        content_type="application/json",
    )
    assert resp.status_code == 403

    p = Plugin.objects.create(name="test.perm.update", operating_system="Windows")
    resp_put = client.put(
        f"/api/plugins/{p.name}",
        data=json.dumps({"operating_system": "Linux", "disabled": True}),
        content_type="application/json",
    )
    assert resp_put.status_code == 403


@pytest.mark.django_db
def test_api_user_role_management(client, admin):
    """Test API endpoint to create user with role and update user role."""
    client.force_login(admin)

    # Create user with Reviewer role
    resp = client.post(
        "/api/users/",
        data=json.dumps(
            {
                "username": "api_reviewer",
                "email": "reviewer@api.com",
                "first_name": "API",
                "last_name": "Reviewer",
                "password": "Password123!",
                "role": ROLE_REVIEWER,
            }
        ),
        content_type="application/json",
    )
    assert resp.status_code == 201
    created_user = User.objects.get(username="api_reviewer")
    assert get_user_role(created_user) == ROLE_REVIEWER

    # Update role to Admin via API
    resp_update = client.post(f"/api/users/{created_user.username}/role?role={ROLE_ADMIN}")
    assert resp_update.status_code == 200
    created_user.refresh_from_db()
    assert get_user_role(created_user) == ROLE_ADMIN
    assert created_user.is_staff is True


@pytest.mark.django_db
def test_template_tags_roles():
    """Test role and permission template filters."""
    user = User.objects.create_user("tpl_user", "tpl@example.com", "pass")
    set_user_role(user, ROLE_ANALYST)

    p_allowed = Plugin.objects.create(name="allowed.plugin", min_role=ROLE_ANALYST)
    p_blocked = Plugin.objects.create(name="blocked.plugin", min_role=ROLE_ADMIN)

    assert user_role_filter(user) == ROLE_ANALYST
    assert has_role_filter(user, ROLE_REVIEWER) is True
    assert has_role_filter(user, ROLE_ADMIN) is False

    assert can_run_plugin_filter(user, p_allowed) is True
    assert can_run_plugin_filter(user, p_allowed.name) is True
    assert can_run_plugin_filter(user, p_blocked) is False
    assert can_run_plugin_filter(user, p_blocked.name) is False
