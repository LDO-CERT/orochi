import hashlib
import secrets

from django.conf import settings
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


class APIToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_tokens",
    )
    name = models.CharField(max_length=100)
    token_prefix = models.CharField(max_length=8)  # for safe UI display (e.g. oro_abc1)
    hashed_token = models.CharField(max_length=128, unique=True)  # SHA-256 hash of token
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = _("API Token")
        verbose_name_plural = _("API Tokens")

    def __str__(self):
        return f"{self.user.username} - {self.name} ({self.token_prefix}...)"

    @classmethod
    def generate_token(cls, user, name: str) -> tuple["APIToken", str]:
        raw_token = f"oro_{secrets.token_urlsafe(32)}"
        prefix = raw_token[:8]
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        instance = cls.objects.create(
            user=user,
            name=name,
            token_prefix=prefix,
            hashed_token=token_hash,
        )
        return instance, raw_token
