import logging
import os
import threading
from datetime import datetime

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import OperationalError, ProgrammingError, close_old_connections, transaction
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm, get_users_with_perms

from orochi.website.defaults import (
    DEFAULT_YARA_PATH,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
    SERVICE_SIEM,
    TOAST_DUMP_COLORS,
    TOAST_RESULT_COLORS,
)
from orochi.website.models import CustomRule, Dump, Plugin, Result, Service, TaskLog, UserPlugin
from orochi.website.notifications import send_external_notifications
from orochi.ya.models import Ruleset

logger = logging.getLogger(__name__)


def _send_ws_notification(user_pk: int, message: str) -> None:
    """Best-effort WebSocket broadcast; never fail DB saves if channel layer/Redis is unavailable."""
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return
        async_to_sync(channel_layer.group_send)(
            f"chat_{user_pk}",
            {
                "type": "chat_message",
                "message": message,
            },
        )
    except Exception as exc:
        logger.warning("Failed to send WebSocket notification to chat_%s: %s", user_pk, exc)


def _safe_async_external_notifications(user, title, message, event_type="dump"):
    """Run external notifications asynchronously with strict DB connection cleanup."""
    has_siem = Service.objects.filter(name=SERVICE_SIEM).exists()
    event_enabled = (event_type == "dump" and user.notify_on_dump_completion) or (
        event_type == "task" and user.notify_on_task_completion
    )
    has_user_channel = user.notify_via_email or user.notify_via_webhook or user.notify_via_slack
    if not (has_siem or (user.enable_notifications and event_enabled and has_user_channel)):
        return

    def _runner():
        """Send email / webhook / Slack / SIEM notifications in a thread with fresh DB connections."""
        close_old_connections()
        try:
            send_external_notifications(user, title, message, event_type)
        except Exception as e:
            logger.error("Error sending external notifications: %s", e)
        finally:
            close_old_connections()

    threading.Thread(target=_runner, daemon=True).start()


@receiver(post_save, sender=Dump)
def set_permission(sender, instance, created, **kwargs):
    """Add object specific permission to the author"""
    if created and instance.author and not getattr(instance.author, "is_anonymous", False):
        assign_perm(
            "website.can_see",
            instance.author,
            instance,
        )


@receiver(post_save, sender=get_user_model())
def get_plugins(sender, instance, created, **kwargs):
    """Give every new user a UserPlugin row for each installed plugin (fixture loads and the anonymous user are skipped)."""
    if not created or kwargs.get("raw"):
        return
    if instance.username == getattr(settings, "ANONYMOUS_USER_NAME", "AnonymousUser"):
        return
    try:
        with transaction.atomic():
            UserPlugin.objects.bulk_create(
                [UserPlugin(user=instance, plugin=plugin) for plugin in Plugin.objects.all()],
                ignore_conflicts=True,
            )
            Ruleset.objects.get_or_create(
                name=f"{instance.username}-Ruleset",
                defaults={"user": instance, "description": "Your crafted ruleset"},
            )
            if os.path.exists(DEFAULT_YARA_PATH):
                CustomRule.objects.get_or_create(
                    user=instance,
                    path=DEFAULT_YARA_PATH,
                    defaults={
                        "default": not CustomRule.objects.filter(user=instance, default=True).exists(),
                        "name": "DEFAULT",
                    },
                )
    except (OperationalError, ProgrammingError) as exc:
        logger.debug("Skipping user bootstrap signals before migrations complete: %s", exc)


@receiver(post_save, sender=Plugin)
def new_plugin(sender, instance, created, **kwargs):
    """Sync new Plugin to UserPlugin entries without colliding with bulk Result creation."""
    if not created or kwargs.get("raw"):
        return
    try:
        with transaction.atomic():
            existing_user_ids = set(UserPlugin.objects.filter(plugin=instance).values_list("user_id", flat=True))
            new_user_plugins = [
                UserPlugin(user=user, plugin=instance)
                for user in get_user_model().objects.all()
                if user.pk not in existing_user_ids
            ]
            if new_user_plugins:
                UserPlugin.objects.bulk_create(new_user_plugins, ignore_conflicts=True)
    except (OperationalError, ProgrammingError) as exc:
        logger.debug("Skipping UserPlugin sync before migrations complete: %s", exc)


@receiver(pre_save, sender=Dump)
def cache_previous_status(sender, instance, *args, **kwargs):
    """Remember the stored dump status so ``dump_saved`` notifies only on real changes."""
    original_status = None
    if instance.id:
        original_status = Dump.objects.filter(pk=instance.id).values_list("status", flat=True).first()
    instance.__original_status = original_status


@receiver(post_save, sender=Dump)
def dump_saved(sender, instance, created, **kwargs):
    """Notify users who can see the dump when it is created or its status changes (WebSocket toast + external channels)."""
    users = get_users_with_perms(instance, only_with_perms_in=["can_see"])
    if created or getattr(instance, "__original_status", None) != instance.status:
        message = f"Dump <b>{instance.name}</b> has been updated"
    else:
        return

    message = f"{datetime.now()} || {message}<br>Status: <b style='color:{TOAST_DUMP_COLORS[instance.status]}'>{instance.get_status_display()}</b>"

    for user in users:
        _send_ws_notification(user.pk, message)

        # Trigger external notifications asynchronously
        _safe_async_external_notifications(user, "Dump Updated", message, "dump")


@receiver(pre_save, sender=Result)
def cache_previous_result(sender, instance, *args, **kwargs):
    """Remember the stored plugin result status so ``result_saved`` notifies only on real changes."""
    original_result = None
    if instance.id:
        original_result = Result.objects.filter(pk=instance.id).values_list("result", flat=True).first()
    instance.__original_result = original_result


@receiver(post_save, sender=Result)
def result_saved(sender, instance, created, **kwargs):
    """Notify users who can see the dump when a plugin result changes (not for disabled / not started results)."""
    dump = instance.dump
    users = get_users_with_perms(dump, only_with_perms_in=["can_see"])
    if instance.result in [RESULT_STATUS_DISABLED, RESULT_STATUS_NOT_STARTED]:
        return
    if created or getattr(instance, "__original_result", None) != instance.result:
        message = f"Plugin <b>{instance.plugin.name}</b> on <b>{instance.dump.name}</b> has been updated"
    else:
        return

    message = f"{datetime.now()} || {message}<br>Status: <b style='color:{TOAST_RESULT_COLORS[instance.result]}'>{instance.get_result_display()}</b>"

    for user in users:
        _send_ws_notification(user.pk, message)

        # Trigger external notifications asynchronously
        _safe_async_external_notifications(user, "Plugin Updated", message, "dump")


@receiver(pre_save, sender=TaskLog)
def cache_previous_tasklog_status(sender, instance, *args, **kwargs):
    """Remember the stored TaskLog status so ``tasklog_saved`` notifies only on real changes."""
    original_status = None
    if instance.id:
        original_status = TaskLog.objects.filter(pk=instance.id).values_list("status", flat=True).first()
    instance.__original_status = original_status


@receiver(post_save, sender=TaskLog)
def tasklog_saved(sender, instance, created, **kwargs):
    """Notify the task owner when a background task ends (Completed or Failed)."""
    if instance.status not in ["Completed", "Failed"]:
        return
    if created or getattr(instance, "__original_status", None) != instance.status:
        color = "#10b981" if instance.status == "Completed" else "#ef4444"
        message = f"{datetime.now()} || Task <b>{instance.name}</b> ended<br>Status: <b style='color:{color}'>{instance.status}</b>"
        if instance.result:
            message += f"<br>Result: {instance.result}"
        if instance.error:
            message += f"<br>Error: {instance.error}"

        users = get_user_model().objects.filter(is_superuser=True)
        for user in users:
            _send_ws_notification(user.pk, message)

            # Trigger external notifications asynchronously
            _safe_async_external_notifications(user, "Task Ended", message, "task")
