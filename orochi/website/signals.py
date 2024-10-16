import os
from datetime import datetime

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm, get_users_with_perms

from orochi.website.defaults import (
    DEFAULT_YARA_PATH,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
    TOAST_DUMP_COLORS,
    TOAST_RESULT_COLORS,
)
from orochi.website.models import CustomRule, Dump, Plugin, Result, UserPlugin
from orochi.ya.models import Ruleset


@receiver(post_save, sender=Dump)
def set_permission(sender, instance, created, **kwargs):
    """Add object specific permission to the author"""
    if created:
        assign_perm(
            "website.can_see",
            instance.author,
            instance,
        )


@receiver(post_save, sender=get_user_model())
def get_plugins(sender, instance, created, **kwargs):
    if created:
        UserPlugin.objects.bulk_create(
            [
                UserPlugin(user=instance, plugin=plugin)
                for plugin in Plugin.objects.all()
            ]
        )
        Ruleset.objects.create(
            name=f"{instance.username}-Ruleset",
            user=instance,
            description="Your crafted ruleset",
        )
        if os.path.exists(DEFAULT_YARA_PATH):
            CustomRule.objects.create(
                user=instance,
                path=DEFAULT_YARA_PATH,
                default=True,
                name="DEFAULT",
            )


@receiver(post_save, sender=Plugin)
def new_plugin(sender, instance, created, **kwargs):
    if created:
        # Add new plugin in old dump
        for dump in Dump.objects.all():
            if instance.operating_system in [dump.operating_system, "Other"]:
                up, created = Result.objects.get_or_create(dump=dump, plugin=instance)
                up.result = RESULT_STATUS_NOT_STARTED
                up.save()

        # Add new plugin to user
        for user in get_user_model().objects.all():
            up, created = UserPlugin.objects.get_or_create(user=user, plugin=instance)


@staticmethod
@receiver(pre_save, sender=Dump)
def cache_previous_status(sender, instance, *args, **kwargs):
    original_status = None
    if instance.id:
        original_status = Dump.objects.get(pk=instance.id).status
    instance.__original_status = original_status


@staticmethod
@receiver(post_save, sender=Dump)
def dump_saved(sender, instance, created, **kwargs):
    users = get_users_with_perms(instance, only_with_perms_in=["can_see"])
    if created:
        message = f"Dump <b>{instance.name}</b> has been created"
    elif instance.__original_status != instance.status:
        message = f"Dump <b>{instance.name}</b> has been updated."
    else:
        return

    message = f"{datetime.now()} || {message}<br>Status: <b style='color:{TOAST_DUMP_COLORS[instance.status]}'>{instance.get_status_display()}</b>"

    for user in users:
        # Send message to room group
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"chat_{user.pk}",
            {
                "type": "chat_message",
                "message": message,
            },
        )


@staticmethod
@receiver(pre_save, sender=Result)
def cache_previous_result(sender, instance, *args, **kwargs):
    original_result = None
    if instance.id:
        original_result = Result.objects.get(pk=instance.id).result
    instance.__original_result = original_result


@staticmethod
@receiver(post_save, sender=Result)
def result_saved(sender, instance, created, **kwargs):
    dump = instance.dump
    users = get_users_with_perms(dump, only_with_perms_in=["can_see"])
    if instance.result in [RESULT_STATUS_DISABLED, RESULT_STATUS_NOT_STARTED]:
        return
    if created:
        message = (
            f"Plugin {instance.plugin.name} on {instance.dump.name} has been created"
        )
    elif instance.__original_result != instance.result:
        message = (
            f"Plugin {instance.plugin.name} on {instance.dump.name} has been updated"
        )
    else:
        return

    message = f"{datetime.now()} || {message}<br>Status: <b style='color:{TOAST_RESULT_COLORS[instance.result]}'>{instance.get_result_display()}</b>"

    for user in users:
        # Send message to room group
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"chat_{user.pk}",
            {
                "type": "chat_message",
                "message": message,
            },
        )
