"""Regression tests for all P0, P1, P2 bugs and enhancements identified during the full swarm QA."""

from unittest.mock import MagicMock, patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from guardian.shortcuts import assign_perm

from orochi.users.models import APIToken
from orochi.website import ctf
from orochi.website.forms import PluginCreateAdminForm
from orochi.website.models import Bookmark, Case, Dump, Evidence, Plugin, Result
from orochi.website.roles import ROLE_ANALYST, ROLE_READONLY, set_user_role

User = get_user_model()


@pytest.mark.django_db
def test_p0_bearer_token_mutating_endpoints_bypass_csrf(client, admin):
    """P0 #1: Authorization: Bearer must succeed on POST/DELETE without CSRF cookie."""
    _, raw_token = APIToken.generate_token(user=admin, name="ci-bearer")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}

    # Mutating POST /api/cases/ with description (also verifies P2 description persistence)
    resp = client.post(
        "/api/cases/",
        data={"name": "Bearer Mutating Case", "description": "Created via Bearer"},
        content_type="application/json",
        **headers,
    )
    assert resp.status_code == 201, resp.content
    body = resp.json()
    assert body["name"] == "Bearer Mutating Case"
    assert body["description"] == "Created via Bearer"

    # Superuser Bearer works on /api/admin/settings and /api/auth/tokens/
    resp_settings = client.get("/api/admin/settings", **headers)
    assert resp_settings.status_code == 200

    resp_bad_tok = client.post(
        "/api/auth/tokens/",
        data={"name": "   "},
        content_type="application/json",
        **headers,
    )
    assert resp_bad_tok.status_code == 400


@pytest.mark.django_db
def test_p0_admin_add_user_and_logout_post_form(client, admin):
    """P0 #2 & P1 #8: /admin/users/user/add/ renders 200 (AdminUserCreationForm) and header uses POST logout."""
    client.force_login(admin)
    resp = client.get("/admin/users/user/add/")
    assert resp.status_code == 200
    html = resp.content.decode()
    assert 'method="post" action="/admin/logout/"' in html
    assert "theme-toggle" in html


@pytest.mark.django_db
def test_p0_admin_plugin_form_rejects_non_zip_cleanly():
    """P0 #3: PluginCreateAdminForm validates non-zip files cleanly instead of returning None in save()."""
    bad_file = SimpleUploadedFile("bad_plugin.py", b"def broken(:\n", content_type="text/x-python")
    form = PluginCreateAdminForm(
        data={"operating_system": "Linux", "comment": "bad"},
        files={"plugin": bad_file},
    )
    assert not form.is_valid()
    assert "plugin" in form.errors


@pytest.mark.django_db
def test_p1_readonly_rbac_playbooks_rules_symbols_dumps(client, dump):
    """P1 #4: ReadOnly users receive 403 on playbook launch, YARA upload, symbol downloads/dwarf, and dump create."""
    ro = User.objects.create_user(username="qa_ro_rbac", email="ro@example.com", password="pw")
    set_user_role(ro, ROLE_READONLY)
    assign_perm("website.can_see", ro, dump)
    _, raw_token = APIToken.generate_token(user=ro, name="ro-tok")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}

    # Playbook launch
    resp_pb = client.post(f"/api/playbooks/linux_triage/launch/{dump.index}", **headers)
    assert resp_pb.status_code == 403

    # YARA upload
    yar = SimpleUploadedFile("ok.yar", b"rule ok { condition: true }", content_type="text/plain")
    resp_yar = client.post("/api/rules/", data={"files": yar}, **headers)
    assert resp_yar.status_code == 403

    # Symbols isf_download & dwarf_generate
    resp_isf = client.post(
        "/api/symbols/isf_download",
        data={"path": "https://example.com/banners.json"},
        content_type="application/json",
        **headers,
    )
    assert resp_isf.status_code == 403

    resp_dwarf = client.post(
        "/api/symbols/dwarf_generate",
        data={"elf_path": "/tmp/vmlinux"},
        content_type="application/json",
        **headers,
    )
    assert resp_dwarf.status_code == 403

    # Create dump returns 403 (not 400) for ReadOnly
    resp_dump = client.post(
        "/api/dumps/",
        data={"payload": '{"name": "ro_dump", "operating_system": "Linux"}'},
        **headers,
    )
    assert resp_dump.status_code == 403


@pytest.mark.django_db
def test_p1_yara_syntax_validation_and_symbol_validation_and_ssrf(client, admin):
    """P1 #6, #7: Invalid YARA rejected on upload, bad_symbol.txt rejected, SSRF blocked, delete traversal returns 400."""
    _, raw_token = APIToken.generate_token(user=admin, name="adm-tok")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}

    # Invalid YARA upload -> 400 with yara_x error
    bad_yar = SimpleUploadedFile("bad.yar", b"rule broken { syntax error !!!", content_type="text/plain")
    resp_yar = client.post("/api/rules/", data={"files": bad_yar}, **headers)
    assert resp_yar.status_code == 400
    assert "Invalid YARA syntax" in resp_yar.json()["errors"]

    # Malformed symbol upload -> 400
    bad_sym = SimpleUploadedFile("bad_symbol.txt", b"not json at all", content_type="text/plain")
    resp_sym = client.post("/api/symbols/upload", data={"symbols": bad_sym}, **headers)
    assert resp_sym.status_code == 400

    # Delete symbol traversal -> 400 (never 500)
    resp_del = client.delete("/api/symbols/delete?path=../../../../etc/passwd", **headers)
    assert resp_del.status_code in (400, 404)

    # SSRF private IP blocked on isf_download and install_plugin
    resp_ssrf_isf = client.post(
        "/api/symbols/isf_download",
        data={"path": "http://127.0.0.1:8000/secret"},
        content_type="application/json",
        **headers,
    )
    assert resp_ssrf_isf.status_code == 400

    resp_ssrf_plug = client.post(
        "/api/plugins/install",
        data={"plugin_url": "https://127.0.0.1/evil.zip", "operating_system": "Linux"},
        content_type="application/json",
        **headers,
    )
    assert resp_ssrf_plug.status_code == 400

    # Multipart dwarf_generate does not crash with RawPostDataException
    fake_elf = SimpleUploadedFile("vmlinux", b"\x7fELFdummy", content_type="application/octet-stream")
    mock_task = MagicMock()
    mock_task.enqueue.return_value = MagicMock(id="task-123")
    with patch("orochi.api.routers.symbols.generate_dwarf_isf_task", mock_task):
        resp_dwarf = client.post("/api/symbols/dwarf_generate", data={"elf": fake_elf}, **headers)
    assert resp_dwarf.status_code == 200


@pytest.mark.django_db
def test_p1_dask_kill_wraps_futures_and_scopes_plugin_key(client, admin, dump):
    """P1 #5: Killing result_<pk> wraps keys in Future and only cancels the targeted result_pk."""
    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", operating_system="Linux")
    res_target = Result.objects.create(dump=dump, plugin=plugin, result=1)
    _, raw_token = APIToken.generate_token(user=admin, name="dask-tok")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}

    mock_client = MagicMock()
    mock_client.processing.return_value = {
        "tcp://w1:1": [f"run_plugin_{res_target.pk}", "run_plugin_999999"],
    }
    created_futures = []

    def fake_future(k, client=None):
        f = MagicMock(key=k)
        created_futures.append(k)
        return f

    with (
        patch("orochi.api.routers.utils._get_dask_client", return_value=mock_client),
        patch("orochi.api.routers.utils.Future", side_effect=fake_future),
    ):
        resp = client.post(f"/api/utils/tasks/kill/result_{res_target.pk}", **headers)

    assert resp.status_code == 200
    assert created_futures == [f"run_plugin_{res_target.pk}"]
    mock_client.cancel.assert_called_once()


@pytest.mark.django_db
def test_p1_cases_duplicate_savepoint_idor_and_global_search_non_uuid(client, admin):
    """P1 #9: Duplicate case name uses savepoint & keeps hx-post url; finding_create blocks IDOR; global_search safe."""
    owner = User.objects.create_user(username="case_owner_qa", email="o@example.com", password="pw")
    intruder = User.objects.create_user(username="case_intruder_qa", email="i@example.com", password="pw")
    set_user_role(owner, ROLE_ANALYST)
    set_user_role(intruder, ROLE_ANALYST)

    existing = Case.objects.create(name="Dup Case QA", user=owner)
    ev = Evidence.objects.create(case=existing, name="Secret Ev")

    # Duplicate case_create -> 200 with form error AND preserved hx-post URL (no TransactionManagementError)
    client.force_login(owner)
    resp_dup = client.post(reverse("website:case_create"), data={"name": "Dup Case QA"})
    assert resp_dup.status_code == 200
    html = resp_dup.content.decode()
    assert "Case already exists" in html
    assert f'hx-post="{reverse("website:case_create")}"' in html

    # IDOR on finding_create -> 404 for non-collaborator
    client.force_login(intruder)
    resp_idor = client.get(reverse("website:finding_create", args=[ev.pk]))
    assert resp_idor.status_code == 404

    # global_search with non-UUID dump index does not crash with NoReverseMatch
    non_uuid_dump = Dump.objects.create(
        name="NonUUID",
        index="qa-non-uuid-index-1",
        operating_system="Linux",
        author=owner,
    )
    assign_perm("website.can_see", owner, non_uuid_dump)
    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", operating_system="Linux")
    res = Result.objects.create(dump=non_uuid_dump, plugin=plugin, result=2)
    from orochi.website.models import Value

    Value.objects.create(result=res, value={"PID": 424242, "COMM": "unique_nonuuid_proc"})
    client.force_login(owner)
    resp_search = client.get(reverse("website:global_search"), {"q": "unique_nonuuid_proc"})
    assert resp_search.status_code == 200


@pytest.mark.django_db
def test_p1_p2_changelog_users_bookmarks_and_login_redirect(client, admin, dump):
    """P1 #10 & P2 API polish: changelog 200, duplicate user 400, AnonymousUser hidden, bookmark 404/200, redirect."""
    _, raw_token = APIToken.generate_token(user=admin, name="polish-tok")
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}

    assert settings.LOGIN_REDIRECT_URL == "website:index"

    resp_cl = client.get("/api/utils/changelog", **headers)
    assert resp_cl.status_code == 200

    # Duplicate username -> 400 (not 500)
    payload = {
        "username": "dup_api_user",
        "email": "dup@example.com",
        "password": "StrongPassword!123",
    }
    r1 = client.post("/api/users/", data=payload, content_type="application/json", **headers)
    assert r1.status_code == 201
    r2 = client.post("/api/users/", data=payload, content_type="application/json", **headers)
    assert r2.status_code == 400

    # GET /api/users/ excludes AnonymousUser
    r_list = client.get("/api/users/", **headers)
    assert r_list.status_code == 200
    usernames = [u["username"] for u in r_list.json()["items"]]
    assert "AnonymousUser" not in usernames

    # Bookmarks 404 on missing & 200 on PATCH
    r_bm_missing = client.get("/api/bookmarks/999999", **headers)
    assert r_bm_missing.status_code == 404

    plugin, _ = Plugin.objects.get_or_create(name="linux.pslist.PsList", operating_system="Linux")
    bm = Bookmark.objects.create(user=admin, plugin=plugin, name="bm_patch_test", query="init")
    bm.indexes.add(dump)
    r_bm_patch = client.patch(
        f"/api/bookmarks/{bm.pk}",
        data={"name": "bm_patched", "icon": "ss-ala", "star": True},
        content_type="application/json",
        **headers,
    )
    assert r_bm_patch.status_code == 200


@pytest.mark.django_db
def test_ctf_edit_question_and_reset_submissions(client, admin):
    """CTF enhancements: Instructor can edit question/hints and reset all submissions; Solver gets 403."""
    solver = User.objects.create_user(username="ctf_solver_enh", email="s@example.com", password="pw")
    set_user_role(solver, ROLE_READONLY)
    case = Case.objects.create(name="CTF Edit & Reset Case", user=admin, is_ctf=True)
    case.collaborators.add(solver)

    q = ctf.create_question(case, "Original Q?", "flag1", points=100, order=1, hints=[("old hint", 15)])
    ctf.submit_answer(q, solver, "wrong")
    ctf.submit_answer(q, solver, "flag1")
    assert len(ctf.leaderboard(case)) == 1

    # Solver gets 403 on edit & reset
    client.force_login(solver)
    assert client.post(reverse("website:case_ctf_question_edit", args=[case.pk, q.pk]), {}).status_code == 403
    assert client.post(reverse("website:case_ctf_reset", args=[case.pk])).status_code == 403

    # Instructor edits question text, points, and hints
    client.force_login(admin)
    resp_edit = client.post(
        reverse("website:case_ctf_question_edit", args=[case.pk, q.pk]),
        data={
            "question_text": "Updated Q?",
            "points": 150,
            "order": 1,
            "answer": "flag2",
            "hints": "20 | new hint",
        },
    )
    assert resp_edit.status_code == 200
    q.refresh_from_db()
    assert q.question_text == "Updated Q?"
    assert q.points == 150
    assert q.check_answer("flag2")
    assert list(q.hints.values_list("hint_text", "cost")) == [("new hint", 20)]

    # Instructor resets submissions
    resp_reset = client.post(reverse("website:case_ctf_reset", args=[case.pk]))
    assert resp_reset.status_code == 200
    assert ctf.leaderboard(case) == []
