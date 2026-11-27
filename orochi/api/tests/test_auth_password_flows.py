"""Session login, password reset and password change through /api/auth/."""

import json

import pytest
from django.contrib.auth.tokens import default_token_generator
from django.core import mail

from orochi.users.models import User

STRONG = "Correct-Horse-Battery-42"


def _post(client, path, payload):
    return client.post(path, data=json.dumps(payload), content_type="application/json")


@pytest.fixture
def account(db):
    return User.objects.create_user("alice", "alice@example.com", "Old-Password-123")


def test_login_ok_and_wrong_password(client, account):
    assert _post(client, "/api/auth/", {"username": "alice", "password": "nope"}).status_code == 403
    res = _post(client, "/api/auth/", {"username": "alice", "password": "Old-Password-123"})
    assert res.status_code == 200
    assert res.json()["username"] == "alice"
    assert client.get("/api/auth/tokens/").status_code == 200


def test_login_inactive_user_is_refused(client, account):
    account.is_active = False
    account.save()
    assert _post(client, "/api/auth/", {"username": "alice", "password": "Old-Password-123"}).status_code == 403


def test_logout_closes_the_session(client, account):
    client.force_login(account)
    assert client.delete("/api/auth/").status_code == 204
    assert client.get("/api/auth/tokens/").status_code == 401


def test_request_password_reset_answers_the_same_for_unknown_addresses(client, account):
    assert _post(client, "/api/auth/request_password_reset", {"email": "nobody@example.com"}).status_code == 204
    assert len(mail.outbox) == 0
    assert _post(client, "/api/auth/request_password_reset", {"email": "alice@example.com"}).status_code == 204
    assert len(mail.outbox) == 1
    body = mail.outbox[0].body
    assert "username: alice" in body
    assert "/accounts/password/reset/" in body


def test_token_from_the_reset_email_completes_the_reset(client, account):
    _post(client, "/api/auth/request_password_reset", {"email": "alice@example.com"})
    token = next(line.split(":", 1)[1].strip() for line in mail.outbox[0].body.splitlines() if "token:" in line)
    payload = {"username": "alice", "new_password1": STRONG, "new_password2": STRONG, "token": token}
    assert _post(client, "/api/auth/reset_password", payload).status_code == 200
    account.refresh_from_db()
    assert account.check_password(STRONG)


def test_reset_password_rejects_bad_token_and_unknown_user(client, account):
    payload = {"username": "alice", "new_password1": STRONG, "new_password2": STRONG, "token": "bad-token"}
    assert _post(client, "/api/auth/reset_password", payload).status_code == 422
    payload["username"] = "ghost"
    assert _post(client, "/api/auth/reset_password", payload).status_code == 422
    account.refresh_from_db()
    assert account.check_password("Old-Password-123")


def test_reset_password_mismatch_then_success(client, account):
    token = default_token_generator.make_token(account)
    bad = {"username": "alice", "new_password1": STRONG, "new_password2": STRONG + "x", "token": token}
    res = _post(client, "/api/auth/reset_password", bad)
    assert res.status_code == 403
    assert "new_password2" in res.json()["errors"]

    ok = {"username": "alice", "new_password1": STRONG, "new_password2": STRONG, "token": token}
    assert _post(client, "/api/auth/reset_password", ok).status_code == 200
    account.refresh_from_db()
    assert account.check_password(STRONG)
    # The token is single use: the password hash changed
    assert _post(client, "/api/auth/reset_password", ok).status_code == 422


def test_change_password_requires_the_old_one(client, account):
    client.force_login(account)
    bad = {"old_password": "wrong", "new_password1": STRONG, "new_password2": STRONG}
    res = _post(client, "/api/auth/change_password", bad)
    assert res.status_code == 403
    assert "old_password" in res.json()["errors"]

    ok = {"old_password": "Old-Password-123", "new_password1": STRONG, "new_password2": STRONG}
    assert _post(client, "/api/auth/change_password", ok).status_code == 200
    account.refresh_from_db()
    assert account.check_password(STRONG)
    # update_session_auth_hash keeps the current session valid
    assert client.get("/api/auth/tokens/").status_code == 200


def test_change_password_needs_authentication(client, account):
    ok = {"old_password": "Old-Password-123", "new_password1": STRONG, "new_password2": STRONG}
    assert _post(client, "/api/auth/change_password", ok).status_code == 401
