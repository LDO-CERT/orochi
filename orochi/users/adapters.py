from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings


class AccountAdapter(DefaultAccountAdapter):
    """allauth adapter that closes self-registration unless ``ACCOUNT_ALLOW_REGISTRATION`` is set."""

    def is_open_for_signup(self, request):
        """Self-registration is allowed only with ``DJANGO_ACCOUNT_ALLOW_REGISTRATION=True``."""
        return getattr(settings, "ACCOUNT_ALLOW_REGISTRATION", False)
