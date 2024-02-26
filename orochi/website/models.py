import os
from datetime import datetime

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from colorfield.fields import ColorField
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm, get_users_with_perms

from orochi.website.defaults import (
    DEFAULT_YARA_PATH,
    ICONS,
    OPERATING_SYSTEM,
    RESULT,
    RESULT_STATUS_NOT_STARTED,
    SERVICES,
    STATUS,
    TOAST_DUMP_COLORS,
    TOAST_RESULT_COLORS,
)
from orochi.ya.models import Ruleset


class Service(models.Model):
    name = models.PositiveIntegerField(choices=SERVICES, unique=True)
    url = models.CharField(max_length=250)
    key = models.CharField(max_length=250)
    proxy = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.get_name_display()}"


class Plugin(models.Model):
    name = models.CharField(max_length=250, unique=True)
    operating_system = models.CharField(
        choices=OPERATING_SYSTEM, default="Linux", max_length=10
    )
    disabled = models.BooleanField(default=False)
    comment = models.TextField(blank=True, null=True)
    local_dump = models.BooleanField(default=False)
    vt_check = models.BooleanField(default=False)
    clamav_check = models.BooleanField(default=False)
    regipy_check = models.BooleanField(default=False)
    yara_check = models.BooleanField(default=False)
    maxmind_check = models.BooleanField(default=False)
    local = models.BooleanField(default=False)
    local_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return self.name


class UserPlugin(models.Model):
    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="plugins"
    )
    automatic = models.BooleanField(default=False)

    class Meta:
        ordering = ("plugin__name",)

    def __str__(self):
        return self.plugin.name


class Folder(models.Model):
    name = models.CharField(max_length=250)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="folders"
    )

    class Meta:
        unique_together = ["name", "user"]

    def __str__(self):
        return self.name


class Dump(models.Model):
    operating_system = models.CharField(
        choices=OPERATING_SYSTEM, default="Linux", max_length=10
    )
    banner = models.CharField(max_length=500, blank=True, null=True)
    upload = models.FileField(upload_to="uploads")
    folder = models.ForeignKey(Folder, on_delete=models.SET_NULL, blank=True, null=True)
    comment = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=250)
    index = models.CharField(max_length=250, unique=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    color = ColorField(default="#FF0000")
    status = models.PositiveSmallIntegerField(choices=STATUS, default=1)
    plugins = models.ManyToManyField(Plugin, through="Result")
    md5 = models.CharField(max_length=32, blank=True, null=True)
    sha256 = models.CharField(max_length=64, blank=True, null=True)
    size = models.BigIntegerField(null=True)
    suggested_symbols_path = ArrayField(
        models.CharField(max_length=1000, blank=True, null=True), blank=True, null=True
    )

    def __str__(self):
        return self.name

    class Meta:
        permissions = (("can_see", "Can See"),)
        verbose_name_plural = "Dumps"
        unique_together = ["name", "author"]


class Result(models.Model):
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE)
    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    result = models.PositiveSmallIntegerField(choices=RESULT, default=0)
    description = models.TextField(blank=True, null=True)
    parameter = models.JSONField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (
            "dump",
            "plugin",
        )

    def __str__(self):
        return f"{self.dump.name} [{self.plugin.name}]"


class Bookmark(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="bookmarks"
    )
    indexes = models.ManyToManyField(Dump)
    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    name = models.CharField(max_length=250)
    icon = models.CharField(choices=ICONS, default="ss-ori", max_length=50)
    star = models.BooleanField(default=False)
    query = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        unique_together = ["name", "user"]

    @property
    def indexes_list(self):
        return ",".join([p.index for p in self.indexes.all()])

    @property
    def indexes_names_list(self):
        return ", ".join([p.name for p in self.indexes.all()])

    def __str__(self):
        return f"{self.name}"


def user_directory_path(instance, filename):
    return "user_{0}/{1}"


class CustomRule(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="rules"
    )
    name = models.CharField(max_length=250)
    public = models.BooleanField(default=False)
    path = models.CharField(max_length=255)
    default = models.BooleanField(default=False)


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
@receiver(post_save, sender=Dump)
def dump_saved(sender, instance, created, **kwargs):
    users = get_users_with_perms(instance, only_with_perms_in=["can_see"])
    if created:
        message = f"Dump <b>{instance.name}</b> has been created"
    else:
        message = f"Dump <b>{instance.name}</b> has been updated."

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
@receiver(post_save, sender=Result)
def result_saved(sender, instance, created, **kwargs):
    dump = instance.dump
    users = get_users_with_perms(dump, only_with_perms_in=["can_see"])
    if created:
        message = (
            f"Plugin {instance.plugin.name} on {instance.dump.name} has been created"
        )
    else:
        message = (
            f"Plugin {instance.plugin.name} on {instance.dump.name} has been updated"
        )

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
