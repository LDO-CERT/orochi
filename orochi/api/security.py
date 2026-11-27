import hashlib
import ipaddress
import logging
import socket
from urllib.parse import urlparse

from django.utils import timezone
from ninja.errors import HttpError
from ninja.security import HttpBearer, django_auth
from ninja.security.session import SessionAuthSuperUser

from orochi.users.models import APIToken

logger = logging.getLogger(__name__)


def validate_public_https_url(url: str) -> str:
    """Validate an outbound URL against SSRF (HTTPS only, no private/loopback/link-local hosts)."""
    cleaned = (url or "").strip()
    parsed = urlparse(cleaned)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Only public https:// URLs are allowed.")
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ValueError("Localhost and internal hostnames are not allowed.")
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Private or internal IP addresses are not allowed.")
    except ValueError as exc:
        if "not allowed" in str(exc):
            raise
        # Hostname: best-effort DNS check if resolvable
        try:
            infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
            for info in infos:
                addr = ipaddress.ip_address(info[4][0])
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
                    raise ValueError("URL resolves to a private or internal IP address.")
        except socket.gaierror:
            pass
    return cleaned


class APIKeyBearer(HttpBearer):
    """Bearer authentication with Orochi API tokens (``Authorization: Bearer oro_...``)."""

    def authenticate(self, request, token):
        """Look up the SHA-256 of the token among active tokens of active users and return the user, or None."""
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


SUPERUSER_REQUIRED = "Permission Denied: superuser required"


class APIKeyBearerSuperuser(APIKeyBearer):
    """Bearer authentication accepting only tokens that belong to superusers.

    A valid token of another user is a 403 (authenticated, not allowed), an unknown token stays a 401.
    """

    def authenticate(self, request, token):
        """Authenticate the token and return the user only when it is a superuser."""
        user = super().authenticate(request, token)
        if user and user.is_superuser:
            return user
        if user:
            raise HttpError(403, SUPERUSER_REQUIRED)
        return None


class SessionAuthSuperuser403(SessionAuthSuperUser):
    """Session authentication for superusers: a signed-in non-superuser gets 403 instead of 401."""

    def authenticate(self, request, key):
        """Return the superuser, raise 403 for other signed-in users, None (401) for anonymous requests."""
        user = super().authenticate(request, key)
        if user is None and request.user.is_authenticated:
            raise HttpError(403, SUPERUSER_REQUIRED)
        return user


# Dual authentication schemas: evaluate Bearer token BEFORE SessionAuth(csrf=True)
# so API clients using Authorization: Bearer are not blocked by Django CSRF checks.
dual_auth = [APIKeyBearer(), django_auth]
dual_auth_superuser = [APIKeyBearerSuperuser(), SessionAuthSuperuser403()]
