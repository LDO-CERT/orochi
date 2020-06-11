from django.db import models
from django.conf import settings
from colorfield.fields import ColorField
from django.db.models.signals import post_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm

OPERATING_SYSTEM = ((1, "Linux"), (2, "Windows"), (3, "Mac"), (4, "Other"))


class Plugin(models.Model):
    name = models.CharField(max_length=250, unique=True)
    operating_system = models.PositiveSmallIntegerField(
        choices=OPERATING_SYSTEM, default=1
    )
    disabled = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Dump(models.Model):
    STATUS = ((1, "Created"), (2, "Completed"), (3, "Deleted"))

    operating_system = models.PositiveSmallIntegerField(
        choices=OPERATING_SYSTEM, default=1
    )
    upload = models.FileField(upload_to="uploads")
    name = models.CharField(max_length=250, unique=True)
    index = models.CharField(max_length=250, null=True, blank=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    color = ColorField(default="#FF0000")
    status = models.PositiveSmallIntegerField(choices=STATUS, default=1)
    plugins = models.ManyToManyField(Plugin, through="Result")

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


@receiver(post_save, sender=Dump)
def set_permission(sender, instance, **kwargs):
    """Add object specific permission to the author"""
    assign_perm(
        "can_see", instance.author, instance,
    )
