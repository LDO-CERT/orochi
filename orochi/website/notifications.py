import html
import logging
import re

import requests
from django.conf import settings
from django.core.mail import EmailMultiAlternatives

from orochi.website.defaults import (
    SERVICE_EMAIL,
    SERVICE_SIEM,
    SERVICE_SLACK,
    SERVICE_WEBHOOK,
)
from orochi.website.integrations import forward_to_siem
from orochi.website.models import Service

logger = logging.getLogger(__name__)

_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_BOLD_RE = re.compile(r"<(?:b|strong)(?:\s[^>]*)?>(.*?)</(?:b|strong)>", re.IGNORECASE | re.DOTALL)
_ITALIC_RE = re.compile(r"<(?:i|em)(?:\s[^>]*)?>(.*?)</(?:i|em)>", re.IGNORECASE | re.DOTALL)
_CODE_RE = re.compile(r"<code(?:\s[^>]*)?>(.*?)</code>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")


def html_to_slack_mrkdwn(text: str) -> str:
    """Convert HTML notification text to Slack mrkdwn with no raw HTML tags (Issue #1664)."""
    if not text:
        return ""
    out = _BR_RE.sub("\n", str(text))
    out = _BOLD_RE.sub(r"*\1*", out)
    out = _ITALIC_RE.sub(r"_\1_", out)
    out = _CODE_RE.sub(r"`\1`", out)
    out = _TAG_RE.sub("", out)
    return html.unescape(out).strip()


def html_to_plain_text(text: str) -> str:
    """Strip HTML tags for plain-text email bodies."""
    if not text:
        return ""
    out = _BR_RE.sub("\n", str(text))
    out = _TAG_RE.sub("", out)
    return html.unescape(out).strip()


def send_external_notifications(user, title, message, event_type="dump"):
    """
    Dispatch notifications to external services based on user preferences.
    event_type can be 'dump', 'task', or 'finding'.
    """
    # SIEM forwarding (#1568) is an organisation level audit stream configured by the
    # administrators: it does not depend on the personal notification preferences.
    if siem := Service.objects.filter(name=SERVICE_SIEM).first():
        try:
            forward_to_siem(
                {"event": event_type, "title": title, "message": html_to_plain_text(message), "user": user.username},
                service=siem,
            )
        except Exception as e:
            logger.error(f"Failed to forward notification to SIEM: {e}")

    if not user.enable_notifications:
        return

    if event_type == "dump" and not user.notify_on_dump_completion:
        return
    if event_type == "task" and not user.notify_on_task_completion:
        return

    plain_message = html_to_plain_text(message)
    slack_message = html_to_slack_mrkdwn(message)

    # Webhook
    if user.notify_via_webhook:
        webhooks = Service.objects.filter(name=SERVICE_WEBHOOK)
        for webhook in webhooks:
            try:
                headers = {"Content-Type": "application/json"}
                token = webhook.decrypted_key
                if token:
                    headers["Authorization"] = f"Bearer {token}"

                payload = {
                    "event": event_type,
                    "title": title,
                    "message": plain_message,
                    "user": user.username,
                }

                requests.post(webhook.url, json=payload, headers=headers, timeout=5)
            except Exception as e:
                logger.error(f"Failed to send webhook notification: {e}")

    # Slack
    if user.notify_via_slack:
        slacks = Service.objects.filter(name=SERVICE_SLACK)
        for slack in slacks:
            try:
                payload = {"text": f"*{title}*\n{slack_message}\n_User: {user.username}_"}
                requests.post(slack.url, json=payload, timeout=5)
            except Exception as e:
                logger.error(f"Failed to send Slack notification: {e}")

    # Email
    if user.notify_via_email:
        emails = Service.objects.filter(name=SERVICE_EMAIL)
        for email_svc in emails:
            try:
                if recipient := email_svc.url or user.email:
                    msg = EmailMultiAlternatives(
                        subject=f"[Orochi] {title}",
                        body=plain_message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[recipient],
                    )
                    msg.send()
            except Exception as e:
                logger.error(f"Failed to send Email notification: {e}")
