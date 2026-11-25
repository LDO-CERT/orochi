"""Production settings: used by the Docker images, WSGI/ASGI servers and Dask workers."""

from .base import *  # noqa: F403
from .base import env

# GENERAL
# ------------------------------------------------------------------------------
DEBUG = False
# No default: a key committed to the repository would be shared by every deployment.
SECRET_KEY = env("DJANGO_SECRET_KEY")
# Previous keys, still accepted for signatures and for decrypting Service secrets during rotation.
SECRET_KEY_FALLBACKS = env.list("DJANGO_SECRET_KEY_FALLBACKS", default=[])

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")

# CACHES
# ------------------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": env("REDIS_URL"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "IGNORE_EXCEPTIONS": True,
        },
    }
}

# SECURITY
# ------------------------------------------------------------------------------
if env.bool("HTTPS", False):
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    # Opt-in: browsers remember HSTS for this long, so enable it only once HTTPS is stable.
    SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=0)
