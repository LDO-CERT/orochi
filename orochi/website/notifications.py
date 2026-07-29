import logging

import requests
from django.conf import settings
from django.core.mail import send_mail

from orochi.website.defaults import SERVICE_EMAIL, SERVICE_SLACK, SERVICE_WEBHOOK
from orochi.website.models import Service

logger = logging.getLogger(__name__)


def send_external_notifications(user, title, message, event_type="dump"):
    """
    Dispatch notifications to external services based on user preferences.
    event_type can be 'dump' or 'task'
    """
    if not user.enable_notifications:
        return

    if event_type == "dump" and not user.notify_on_dump_completion:
        return
    if event_type == "task" and not user.notify_on_task_completion:
        return

    # Webhook
    if user.notify_via_webhook:
        webhooks = Service.objects.filter(name=SERVICE_WEBHOOK)
        for webhook in webhooks:
            try:
                headers = {"Content-Type": "application/json"}
                if webhook.key:
                    headers["Authorization"] = f"Bearer {webhook.key}"

                payload = {
                    "event": event_type,
                    "title": title,
                    "message": message,
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
                payload = {"text": f"*{title}*\n{message}\n_User: {user.username}_"}
                requests.post(slack.url, json=payload, timeout=5)
            except Exception as e:
                logger.error(f"Failed to send Slack notification: {e}")

    # Email
    if user.notify_via_email:
        emails = Service.objects.filter(name=SERVICE_EMAIL)
        for email_svc in emails:
            try:
                # We use the service URL as the target email address for notifications
                # if it's set, otherwise fallback to the user's email
                recipient = email_svc.url if email_svc.url else user.email
                if recipient:
                    send_mail(
                        subject=f"[Orochi] {title}",
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[recipient],
                        fail_silently=True,
                    )
            except Exception as e:
                logger.error(f"Failed to send Email notification: {e}")
