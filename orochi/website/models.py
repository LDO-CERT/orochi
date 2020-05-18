from django.db import models
from django.conf import settings
from colorfield.fields import ColorField
from django.db.models.signals import post_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm


class Analysis(models.Model):
    STATUS = ((1, "Created"), (2, "Completed"), (3, "Deleted"))

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
def set_permission(sender, instance, **kwargs):
    """Add object specific permission to the author"""
    assign_perm(
        "can_see", instance.author, instance,
    )
