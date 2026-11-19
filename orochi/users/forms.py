from django import forms as django_forms
from django.contrib.auth import forms, get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

User = get_user_model()


class UserChangeForm(forms.UserChangeForm):
    class Meta(forms.UserChangeForm.Meta):
        model = User


class UserCreationForm(forms.UserCreationForm):
    # Copy instead of update(): update() returns None and would mutate UserCreationForm for every form.
    error_messages = {
        **forms.UserCreationForm.error_messages,
        "duplicate_username": _("This username has already been taken."),
    }

    class Meta(forms.UserCreationForm.Meta):
        model = User

    def clean_username(self):
        username = self.cleaned_data["username"]

        try:
            User.objects.get(username=username)
        except User.DoesNotExist:
            return username

        raise ValidationError(self.error_messages["duplicate_username"])


class UserNotificationsForm(django_forms.ModelForm):
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
