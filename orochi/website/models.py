from django.db import models
from django.conf import settings
from colorfield.fields import ColorField
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm

OPERATING_SYSTEM = (
    ("Linux", "Linux"),
    ("Windows", "Windows"),
    ("Mac", "Mac"),
    ("Other", "Other"),
)
SERVICES = ((1, "VirusTotal"),)


class Service(models.Model):
    name = models.PositiveIntegerField(choices=SERVICES, unique=True)
    url = models.CharField(max_length=250)
    key = models.CharField(max_length=250)
    proxy = models.JSONField(null=True, blank=True)

    def __str__(self):
        return "{}".format(self.get_name_display())


class Plugin(models.Model):
    name = models.CharField(max_length=250, unique=True)
    operating_system = models.CharField(
        choices=OPERATING_SYSTEM, default="Linux", max_length=10
    )
    disabled = models.BooleanField(default=False)
    local_dump = models.BooleanField(default=False)
    vt_check = models.BooleanField(default=False)
    clamav_check = models.BooleanField(default=False)
    regipy_check = models.BooleanField(default=False)

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


class Dump(models.Model):
    STATUS = ((1, "Created"), (2, "Completed"), (3, "Deleted"), (4, "Error"))

    operating_system = models.CharField(
        choices=OPERATING_SYSTEM, default="Linux", max_length=10
    )
    banner = models.CharField(max_length=500, blank=True, null=True)
    upload = models.FileField(upload_to="uploads")
    name = models.CharField(max_length=250, unique=True)
    index = models.CharField(max_length=250, unique=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    color = ColorField(default="#FF0000")
    status = models.PositiveSmallIntegerField(choices=STATUS, default=1)
    plugins = models.ManyToManyField(Plugin, through="Result")
    missing_symbols = models.BooleanField(default=False)
    suggested_symbols_path = models.CharField(max_length=1000, blank=True, null=True)

    def __str__(self):
        return self.name

    class Meta:
        permissions = (("can_see", "Can See"),)
        verbose_name_plural = "Dumps"


class Result(models.Model):
    RESULT = (
        (0, "Running"),
        (1, "Empty"),
        (2, "Success"),
        (3, "Unsatisfied"),
        (4, "Error"),
        (5, "Disabled"),
    )

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
        return "{} [{}]".format(self.dump.name, self.plugin.name)


class ExtractedDump(models.Model):
    path = models.CharField(max_length=250, unique=True)
    result = models.ForeignKey(Result, on_delete=models.CASCADE)
    sha256 = models.CharField(max_length=64, blank=True, null=True)
    clamav = models.CharField(max_length=250, blank=True, null=True)
    vt_report = models.JSONField(blank=True, null=True)
    reg_array = models.JSONField(blank=True, null=True)


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
