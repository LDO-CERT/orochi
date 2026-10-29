import hashlib
import logging

from django.utils import timezone
from ninja.security import HttpBearer, django_auth

from orochi.users.models import APIToken

logger = logging.getLogger(__name__)


class APIKeyBearer(HttpBearer):
    def authenticate(self, request, token):
        if not token:
            return None
        token_hash = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
        try:
            api_token = (
                APIToken.objects.select_related("user")
                .filter(is_active=True, user__is_active=True)
                .get(hashed_token=token_hash)
            )
            api_token.last_used_at = timezone.now()
            api_token.save(update_fields=["last_used_at"])
            request.user = api_token.user
            return api_token.user
        except APIToken.DoesNotExist:
            logger.debug("API token authentication failed: token not found or inactive")
            return None


# Dual authentication schema: allows either Django session cookies OR Bearer API tokens
dual_auth = [django_auth, APIKeyBearer()]
