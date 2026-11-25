from django import forms as django_forms
from django.contrib.auth import forms, get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

User = get_user_model()


class UserChangeForm(forms.UserChangeForm):
    """Admin change form bound to the custom User model."""

    class Meta(forms.UserChangeForm.Meta):
        model = User


class UserCreationForm(forms.AdminUserCreationForm):
    # Copy instead of update(): update() returns None and would mutate AdminUserCreationForm for every form.
    """Admin creation form with a clear duplicate-username error."""

    error_messages = {
        **forms.AdminUserCreationForm.error_messages,
        "duplicate_username": _("This username has already been taken."),
    }

    class Meta(forms.AdminUserCreationForm.Meta):
        model = User

    def clean_username(self):
        """Reject usernames that already exist."""
        username = self.cleaned_data["username"]

        try:
            User.objects.get(username=username)
        except User.DoesNotExist:
            return username

        raise ValidationError(self.error_messages["duplicate_username"])


class UserNotificationsForm(django_forms.ModelForm):
    """Notification preferences: events to notify and channels (email, webhook, Slack)."""

    class Meta:
        model = User
        fields = [
            "enable_notifications",
            "notify_via_email",
            "notify_via_webhook",
            "notify_via_slack",
            "notify_on_dump_completion",
            "notify_on_task_completion",
        ]
