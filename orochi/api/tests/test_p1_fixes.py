import pytest
import yara_x
from django.core.management import call_command
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.users.models import APIToken
from orochi.website.models import Case, Dump, Folder
from orochi.ya.models import Rule, Ruleset
from orochi.ya.rules_sync import _verify_worker_rules, compile_default_yara_rule

pytestmark = pytest.mark.django_db


def test_p1_role_required_returns_403_not_redirect_loop(client, analyst_user, readonly_user):
    """Authenticated users lacking the required role get HTTP 403, avoiding login redirect loops."""
    # Anonymous user still redirects to login
    anon_resp = client.get(reverse("website:list_symbols"))
    assert anon_resp.status_code == 302

    # Analyst cannot access Admin-only symbol management -> 403 (not 302 loop)
    client.force_login(analyst_user)
    analyst_symbols = client.get(reverse("website:list_symbols"), follow=False)
    assert analyst_symbols.status_code == 403
    assert 'href="/symbols/"' not in client.get(reverse("website:index")).content.decode()

    # ReadOnly user gets 403 on write views
    client.force_login(readonly_user)
    for url_name in ("website:case_create", "website:folder_create", "website:index_create"):
        assert client.get(reverse(url_name)).status_code == 403


def test_p1_readonly_context_and_case_related_dumps_isolation(client, admin, analyst_user, readonly_user):
    """Verify readonly context parity and website.can_see filtering for case_detail related_dumps."""
    shared_folder = Folder.objects.create(name="Incident-Shared", user=admin)
    secret_dump = Dump.objects.create(name="Private-Dump", index="idx_priv_case", author=admin, folder=shared_folder)
    visible_dump = Dump.objects.create(name="Shared-Dump", index="idx_pub_case", author=admin, folder=shared_folder)
    assign_perm("website.can_see", analyst_user, visible_dump)

    case = Case.objects.create(name="Collab Case", user=admin, folder=shared_folder)
    case.collaborators.add(analyst_user)

    client.force_login(readonly_user)
    resp_ro_idx = client.get(reverse("website:indices"))
    assert resp_ro_idx.status_code == 200
    assert resp_ro_idx.context["readonly"] is True

    client.force_login(analyst_user)
    resp_an_idx = client.get(reverse("website:indices"))
    assert resp_an_idx.context["readonly"] is False

    resp_case = client.get(reverse("website:case_detail", kwargs={"pk": case.pk}))
    assert resp_case.status_code == 200
    related = list(resp_case.context["related_dumps"])
    assert visible_dump in related
    assert secret_dump not in related


def test_p1_bearer_token_works_across_upgraded_dual_auth_routers(client, admin):
    """Verify Bearer API tokens authenticate consistently on all dual_auth endpoints."""
    _, raw_token = APIToken.generate_token(user=admin, name="P1 Full API Token")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}

    for endpoint in (
        "/api/dumps/",
        "/api/playbooks/",
        "/api/plugins/",
        "/api/bookmarks/",
        "/api/rules/?draw=1&start=0&length=10",
        "/api/customrules/?draw=1&start=0&length=10",
        "/api/symbols/?draw=1&start=0&length=10",
        "/api/tasks/summary",
        "/api/users/",
        "/api/search/?q=test",
    ):
        resp = client.get(endpoint, **headers)
        assert resp.status_code == 200, f"Expected 200 with Bearer token for {endpoint}, got {resp.status_code}"


def test_p1_compile_default_yara_rule_namespaces_and_skips_broken_rules(admin, tmp_path, monkeypatch):
    """Duplicate rule names across rulesets get isolated namespaces and broken community rules do not abort build."""
    out_path = tmp_path / "default_compiled.yara"
    monkeypatch.setattr("extra_settings.models.Setting.get", lambda key, default=None: str(out_path))

    rs1 = Ruleset.objects.create(name="FeedA", user=None, enabled=True)
    rs2 = Ruleset.objects.create(name="FeedB", user=None, enabled=True)
    f1 = tmp_path / "a.yar"
    f2 = tmp_path / "b.yar"
    f_bad = tmp_path / "bad.yar"
    f1.write_text("rule lightdart { condition: true }")
    f2.write_text("rule lightdart { condition: false }")
    f_bad.write_text("rule broken_community { condition: unknown_identifier_xyz }")

    Rule.objects.create(ruleset=rs1, path=str(f1), rule=f1.read_text(), enabled=True)
    Rule.objects.create(ruleset=rs2, path=str(f2), rule=f2.read_text(), enabled=True)
    Rule.objects.create(ruleset=rs2, path=str(f_bad), rule=f_bad.read_text(), enabled=True)

    summary = compile_default_yara_rule()
    assert summary["rules_count"] == 2
    assert summary["skipped_count"] == 1
    assert out_path.exists()
    with out_path.open("rb") as fp:
        compiled = yara_x.Rules.deserialize_from(fp)
    assert compiled is not None
    assert _verify_worker_rules(str(out_path))["status"] == "ok"

    # Command delegates cleanly without crashing
    call_command("generate_default_rule", verbosity=0)


def test_p1_rule_list_provides_preview_when_not_searching(client, analyst_user, tmp_path):
    """GET /api/rules/ populates safe escaped rule preview snippet when filters.search is empty."""
    rs = Ruleset.objects.create(name="PreviewFeed", user=None, enabled=True)
    yar_file = tmp_path / "preview.yar"
    yar_text = 'rule PreviewRule <tag> { strings: $a = "evil" condition: $a }'
    yar_file.write_text(yar_text)
    Rule.objects.create(ruleset=rs, path=str(yar_file), rule=yar_text, enabled=True)

    client.force_login(analyst_user)
    resp = client.get("/api/rules/?draw=1&start=0&length=10")
    assert resp.status_code == 200
    rows = resp.json()["data"]
    assert len(rows) == 1
    assert "PreviewRule" in rows[0]["headline"]
    assert "&lt;tag&gt;" in rows[0]["headline"]


def test_p1_auth_pages_ui_and_conditional_ldap_backend(client, settings):
    """Verify anonymous auth templates omit internal drawers, show login errors, and skip unused LDAPBackend."""
    assert "django_auth_ldap.backend.LDAPBackend" not in settings.AUTHENTICATION_BACKENDS

    login_get = client.get(reverse("account_login"))
    assert login_get.status_code == 200
    html = login_get.content.decode()
    assert 'id="theme-toggle"' in html
    assert 'autocomplete="username"' in html
    assert 'autocomplete="current-password"' in html
    for leaked_id in ('id="sidemenu"', 'id="activityDrawer"', 'id="changelogDrawer"', 'id="globalSearchModal"'):
        assert leaked_id not in html

    bad_login = client.post(reverse("account_login"), {"login": "nobody", "password": "wrong"})
    assert bad_login.status_code == 200
    assert 'role="alert"' in bad_login.content.decode()

    signup_get = client.get(reverse("account_signup"))
    assert signup_get.status_code == 200
    signup_html = signup_get.content.decode()
    assert "Email (optional)" not in signup_html
    assert '$("label"' not in signup_html
