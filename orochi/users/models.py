from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import CharField
from django.urls import reverse
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    name = CharField(_("Name of User"), blank=True, max_length=255)

    # Notification Settings
    enable_notifications = models.BooleanField(default=True)
    notify_via_email = models.BooleanField(default=False)
    notify_via_webhook = models.BooleanField(default=False)
    notify_via_slack = models.BooleanField(default=False)

    notify_on_dump_completion = models.BooleanField(default=True)
    notify_on_task_completion = models.BooleanField(default=True)

    def get_absolute_url(self):
        return reverse("users:bookmarks", kwargs={"username": self.username})
