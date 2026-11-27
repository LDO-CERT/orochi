"""Django messages reach the page the user lands on: as toasts, or inline where the page has messages.html."""

from django.urls import reverse


def _toast_calls(response):
    return response.content.decode().count("toast({ type: '")


def test_login_message_is_shown_on_the_home_page(client, analyst_user):
    res = client.post(reverse("account_login"), {"login": "analyst", "password": "password"}, follow=True)
    assert res.status_code == 200
    assert res.request["PATH_INFO"] in ("/", "/index")
    assert _toast_calls(res) == 1
    assert "Successfully signed in as analyst." in res.content.decode()
    # Consumed: it does not pop up again on the next page
    assert _toast_calls(client.get(reverse("users:plugins", kwargs={"username": "analyst"}))) == 0


def test_notification_preferences_message_stays_inline(client, analyst_user):
    client.force_login(analyst_user)
    res = client.post(reverse("users:notifications"), {"enable_notifications": "on"}, follow=True)
    assert res.status_code == 200
    assert res.redirect_chain[-1][0] == reverse("users:notifications")
    assert "Notification preferences updated." in res.content.decode()
    assert _toast_calls(res) == 0


def test_pages_with_inline_messages_do_not_duplicate_them(client, analyst_user):
    client.force_login(analyst_user)
    assert _toast_calls(client.get(reverse("users:plugins", kwargs={"username": "analyst"}))) == 0
    # Queue a message, then open a page that renders messages.html inline
    client.post(reverse("account_logout"))
    res = client.post(reverse("account_login"), {"login": "analyst", "password": "password"})
    assert res.status_code == 302
    page = client.get(reverse("users:plugins", kwargs={"username": "analyst"}))
    body = page.content.decode()
    assert "Successfully signed in as analyst." in body
    assert _toast_calls(page) == 0
