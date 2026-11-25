"""WebSocket toast helper: format, escaping and best-effort delivery."""

from unittest.mock import MagicMock, patch

import pytest

from orochi.website import notifier

pytestmark = pytest.mark.django_db


def _sent(layer):
    return [call.args for call in layer.group_send.call_args_list]


@pytest.fixture
def layer():
    mock = MagicMock()
    with (
        patch("orochi.website.notifier.get_channel_layer", return_value=mock),
        patch("orochi.website.notifier.async_to_sync", side_effect=lambda fn: fn),
    ):
        yield mock


def test_plain_text_is_escaped_and_timestamped(layer, admin):
    notifier.notify_user(admin, "kernel <script>alert(1)</script>")
    ((group, payload),) = _sent(layer)
    assert group == f"chat_{admin.pk}"
    assert payload["type"] == "chat_message"
    timestamp, text = payload["message"].split(" || ", 1)
    assert timestamp and text == "kernel &lt;script&gt;alert(1)&lt;/script&gt;"


def test_html_messages_keep_markup_and_bold_escapes_values(layer, admin):
    notifier.notify_user(admin.pk, f"Dump {notifier.bold('<img src=x>')} ready", html=True)
    text = _sent(layer)[0][1]["message"].split(" || ", 1)[1]
    assert text == "Dump <b>&lt;img src=x&gt;</b> ready"


def test_dump_users_get_the_dump_name_prefix(layer, admin, dump):
    dump.name = "evil<b>"
    notifier.notify_dump_users(dump, "symbols missing", user=admin)
    # The dump fixture already triggered a status toast: check the last message
    text = _sent(layer)[-1][1]["message"].split(" || ", 1)[1]
    assert text == "<b>evil&lt;b&gt;</b>: symbols missing"


def test_delivery_errors_are_swallowed(admin):
    with patch("orochi.website.notifier.get_channel_layer", side_effect=RuntimeError("redis down")):
        notifier.notify_user(admin, "hello")  # must not raise
    with patch("orochi.website.notifier.get_channel_layer", return_value=None):
        notifier.notify_user(admin, "hello")


def test_kind_travels_with_the_toast(layer, admin, dump):
    notifier.notify_user(admin, "plugin ended", kind="plugin")
    notifier.notify_user(admin, "weird", kind="not-a-kind")
    notifier.notify_dump_users(dump, "symbols missing", user=admin, kind="symbols")
    kinds = [args[1]["kind"] for args in _sent(layer)[-3:]]
    assert kinds == ["plugin", "info", "symbols"]


def test_consumer_forwards_the_kind():
    import json

    from asgiref.sync import async_to_sync

    from orochi.website.consumers import NotifyConsumer

    consumer = NotifyConsumer()
    sent = []

    async def fake_send(text_data):
        sent.append(json.loads(text_data))

    consumer.send = fake_send
    async_to_sync(consumer.chat_message)({"type": "chat_message", "message": "d || m", "kind": "task"})
    async_to_sync(consumer.chat_message)({"type": "chat_message", "message": "d || old"})
    assert sent == [{"message": "d || m", "kind": "task"}, {"message": "d || old", "kind": "info"}]
