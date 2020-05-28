import pathlib
from django.db import models
from django.conf import settings
from colorfield.fields import ColorField
from django.db.models.signals import post_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm

import volatility.plugins
import volatility.symbols
from volatility import framework
from volatility.cli.text_renderer import JsonRenderer
from volatility.framework import (
    automagic,
    contexts,
    exceptions,
    interfaces,
    plugins,
)

from dask import delayed
from zipfile import ZipFile, is_zipfile
from dask.distributed import Client, fire_and_forget
from orochi.utils.volatility_dask_elk import run_plugin


class Analysis(models.Model):
    STATUS = ((1, "Created"), (2, "Completed"), (3, "Deleted"))
    OPERATING_SYSTEM = ((1, "Linux"), (2, "Windows"), (3, "Mac"), (4, "Other"))

    operating_system = models.PositiveSmallIntegerField(
        choices=OPERATING_SYSTEM, default=1
    )
    upload = models.FileField(upload_to="uploads")
    name = models.CharField(max_length=250)
    index = models.CharField(max_length=250, null=True, blank=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    color = ColorField(default="#FF0000")
    status = models.PositiveSmallIntegerField(choices=STATUS, default=1)

    def __str__(self):
        return self.name

    class Meta:
        permissions = (("can_see", "Can See"),)
        verbose_name_plural = "Analyses"


@receiver(post_save, sender=Analysis)
def launch_dask(sender, instance, **kwargs):
    # Ok, let's run plugin in dask
    ctx = contexts.Context()
    failures = framework.import_files(volatility.plugins, True)

    dask_client = Client(settings.DASK_SCHEDULER_URL)

    if is_zipfile(instance.upload.path):
        with ZipFile(instance.upload.path, "r") as zipObj:
            objs = zipObj.namelist()
            if len(objs) == 1:
                newpath = zipObj.extract(
                    objs[0], pathlib.Path(instance.upload.path).parent
                )
    else:
        newpath = instance.upload.path

    for plugin_name in framework.list_plugins():
        if (
            plugin_name.startswith(instance.get_operating_system_display().lower())
            and plugin_name not in settings.DISABLED_PLUGIN
        ):
            a = dask_client.compute(
                delayed(run_plugin)(
                    plugin_name, newpath, instance.index, settings.ELASTICSEARCH_URL,
                )
            )
            fire_and_forget(a)


@receiver(post_save, sender=Analysis)
def set_permission(sender, instance, **kwargs):
    """Add object specific permission to the author"""
    assign_perm(
        "can_see", instance.author, instance,
    )
