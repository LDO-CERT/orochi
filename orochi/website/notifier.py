"""User toasts over WebSocket (``ws/notify/<user_id>/``, consumed by ``NotifyConsumer``).

Single place for the group name, the ``"<timestamp> || <message>"`` format the front-end splits on, and escaping:
plain-text messages are escaped; callers that build HTML pass ``html=True`` and wrap every dynamic value with
:func:`bold` or :func:`django.utils.html.escape` (dump names, plugin names and kernel strings come from users and from
the analysed memory). Sending never raises: a missing channel layer or Redis must not break saves or tasks.
External channels (email, webhook, Slack, SIEM) stay in ``orochi.website.notifications``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.utils.html import escape, format_html

logger = logging.getLogger(__name__)


def group_name(user_pk: int) -> str:
    """Channel group of a user's notification socket."""
    return f"chat_{user_pk}"


def bold(value) -> str:
    """Escaped value wrapped in ``<b>`` for HTML messages."""
    return format_html("<b>{}</b>", value)


def format_toast(message: str, *, html: bool = False) -> str:
    """Prefix the timestamp expected by the front-end and escape plain-text messages."""
    return f"{datetime.now()} || {message if html else escape(message)}"


KINDS = ("dump", "plugin", "task", "symbols", "playbook", "finding", "info")


def notify_user(user, message: str, *, html: bool = False, kind: str = "info") -> None:
    """Send a toast to one user (a ``User`` or a primary key).

    ``kind`` (one of :data:`KINDS`) selects the icon and title of the toast and of the History Log entry.
    """
    kind = kind if kind in KINDS else "info"
    user_pk = getattr(user, "pk", user)
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return
        async_to_sync(channel_layer.group_send)(
            group_name(user_pk), {"type": "chat_message", "message": format_toast(message, html=html), "kind": kind}
        )
    except Exception as exc:
        logger.warning("WebSocket notification to %s not sent: %s", group_name(user_pk), exc)


def notify_users(users: Iterable, message: str, *, html: bool = False, kind: str = "info") -> None:
    """Send the same toast to several users."""
    for user in users:
        notify_user(user, message, html=html, kind=kind)


def notify_dump_users(dump, message: str, *, user=None, html: bool = False, kind: str = "dump") -> None:
    """Toast about ``dump`` (prefixed with its name) to ``user``, or to every user who can see the dump."""
    if user is not None:
        recipients = [user]
    else:
        from guardian.shortcuts import get_users_with_perms

        recipients = list(get_users_with_perms(dump, only_with_perms_in=["can_see"]))
    body = message if html else escape(message)
    notify_users(recipients, f"{bold(dump.name)}: {body}", html=True, kind=kind)
