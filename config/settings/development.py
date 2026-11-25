"""Development settings: DEBUG on, debug toolbar and django-extensions when installed. Never use in production."""

from .base import *  # noqa: F403
from .base import INSTALLED_APPS, MIDDLEWARE, TEMPLATES, env

# GENERAL
# ------------------------------------------------------------------------------
DEBUG = True
SECRET_KEY = env("DJANGO_SECRET_KEY", default="") or "development-only-insecure-key-do-not-use-in-production"
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["localhost", "127.0.0.1", "[::1]"])

# CACHES
# ------------------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": env("REDIS_URL", default="redis://localhost:6379/0"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "IGNORE_EXCEPTIONS": True,
        },
    }
}

TEMPLATES[0]["OPTIONS"]["debug"] = True

# Plain HTTP on localhost
MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN = True

# WhiteNoise
# ------------------------------------------------------------------------------
INSTALLED_APPS = ["whitenoise.runserver_nostatic", *INSTALLED_APPS]

# django-debug-toolbar
# ------------------------------------------------------------------------------
try:
    import debug_toolbar  # noqa: F401

    INSTALLED_APPS += ["debug_toolbar"]
    MIDDLEWARE = [*MIDDLEWARE, "debug_toolbar.middleware.DebugToolbarMiddleware"]
    DEBUG_TOOLBAR_CONFIG = {
        "DISABLE_PANELS": ["debug_toolbar.panels.redirects.RedirectsPanel"],
        "SHOW_TEMPLATE_CONTEXT": True,
    }
    INTERNAL_IPS = ["127.0.0.1", "10.0.2.2"]
    if env("USE_DOCKER", default="no") == "yes":
        import socket

        hostname, _, ips = socket.gethostbyname_ex(socket.gethostname())
        INTERNAL_IPS += [".".join([*ip.split(".")[:-1], "1"]) for ip in ips]
except ImportError:
    pass

# django-extensions
# ------------------------------------------------------------------------------
try:
    import django_extensions  # noqa: F401

    INSTALLED_APPS += ["django_extensions"]
except ImportError:
    pass
