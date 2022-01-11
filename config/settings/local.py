from .base import *  # noqa
from .base import env

# GENERAL
# ------------------------------------------------------------------------------
DEBUG = False
SECRET_KEY = env(
    "DJANGO_SECRET_KEY",
    default="8Iji8D9B0ZDdn1ntQjf5N7cQV5mi20JE3KzY4wAcn0lqF329niLCr4G1Kme1d5B8",
)

ALLOWED_HOSTS = env.str("ALLOWED_HOSTS").split(",")

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


# EMAIL
# ------------------------------------------------------------------------------
EMAIL_HOST = env("EMAIL_HOST", default="mailhog")
EMAIL_PORT = 1025

# WhiteNoise
# ------------------------------------------------------------------------------
INSTALLED_APPS = ["whitenoise.runserver_nostatic"] + INSTALLED_APPS  # noqa F405
STATICFILES_STORAGE = "whitenoise.storage.CompressedStaticFilesStorage"

# django-debug-toolbar
# ------------------------------------------------------------------------------
try:
    import debug_toolbar  # noqa F401

    INSTALLED_APPS += ["debug_toolbar"]  # noqa F405

    MIDDLEWARE += ["debug_toolbar.middleware.DebugToolbarMiddleware"]  # noqa F405
    DEBUG_TOOLBAR_CONFIG = {
        "DISABLE_PANELS": ["debug_toolbar.panels.redirects.RedirectsPanel"],
        "SHOW_TEMPLATE_CONTEXT": True,
    }
    INTERNAL_IPS = ["127.0.0.1", "10.0.2.2"]
    if env("USE_DOCKER") == "yes":
        import socket

        hostname, _, ips = socket.gethostbyname_ex(socket.gethostname())
        INTERNAL_IPS += [".".join(ip.split(".")[:-1] + ["1"]) for ip in ips]
except ImportError:
    pass

# django-extensions
# ------------------------------------------------------------------------------
try:
    import django_extensions  # noqa F401

    INSTALLED_APPS += ["django_extensions"]  # noqa F405
except ImportError:
    pass
