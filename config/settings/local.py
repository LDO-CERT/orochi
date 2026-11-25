from .base import *  # noqa
from .base import env

# GENERAL
# ------------------------------------------------------------------------------
DEBUG = False
# No default: a key committed to the repository would be shared by every deployment.
SECRET_KEY = env("DJANGO_SECRET_KEY")
# Previous keys, still accepted for signatures and for decrypting Service secrets during rotation.
SECRET_KEY_FALLBACKS = env.list("DJANGO_SECRET_KEY_FALLBACKS", default=[])

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
MAILERS = {
    "default": {
        "BACKEND": env("DJANGO_EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend"),
        "OPTIONS": {
            "host": env("EMAIL_HOST", default="mailpit"),
            "port": env.int("EMAIL_PORT", default=25),
            "timeout": env.int("EMAIL_TIMEOUT", default=30),
            "use_tls": env.bool("EMAIL_USE_TLS", default=True),
            "username": env("EMAIL_HOST_USER", default=""),
            "password": env("EMAIL_HOST_PASSWORD", default=""),
        },
    }
}
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default=None)

# WhiteNoise
# ------------------------------------------------------------------------------
INSTALLED_APPS = ["whitenoise.runserver_nostatic"] + INSTALLED_APPS  # noqa F405

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
