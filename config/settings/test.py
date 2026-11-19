"""With these settings, tests run faster."""

import os

# Defaults so that `uv run pytest` works without the Docker env files.
# Real environment variables (e.g. in CI or inside the containers) take precedence.
for _name, _value in {
    "DATABASE_URL": "postgresql://debug:debug@localhost:5432/orochi",
    "REDIS_SERVER": "localhost",
    "REDIS_PORT": "6379",
    "DASK_SCHEDULER_URL": "tcp://localhost:8786",
    "AUTH_LDAP_SERVER_URI": "",
    "AUTH_LDAP_BIND_DN": "",
    "AUTH_LDAP_BIND_PASSWORD": "",
    "AUTH_LDAP_USER_SEARCH_DN": "",
    "AUTH_LDAP_USER_SEARCH_ALIAS": "",
    "AUTH_LDAP_USER_ATTR_MAP": "",
    "DEFAULT_YARA_RULE_PATH": "/yara/default.yara",
    "THREAD_NO": "2",
    "AWESOME_PATH": "https://raw.githubusercontent.com/InQuest/awesome-yara/master/README.md",
    "VOLATILITY_SYMBOL_DOWNLOAD_PATH": "https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/",
    "LOCAL_YARA_PATH": "/yara",
    "LOCAL_UPLOAD_PATH": "/uploads",
    "REGIPY_PLUGINS": "computer_name,host_domain_name,network_drives_plugin",
}.items():
    os.environ.setdefault(_name, _value)

from .base import *  # noqa: E402, F403
from .base import env  # noqa: E402

# GENERAL
# ------------------------------------------------------------------------------
SECRET_KEY = env(
    "DJANGO_SECRET_KEY",
    default="PYqlTsTqt6iquK71sHEylQI7yXxYklb3zXhOxGDZA5r0pp1QXg1lLaNzZ4dkHWrr",
)
TEST_RUNNER = "django.test.runner.DiscoverRunner"

# CACHES
# ------------------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "",
    }
}

# PASSWORDS
# ------------------------------------------------------------------------------
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# TEMPLATES
# ------------------------------------------------------------------------------
TEMPLATES[-1]["OPTIONS"]["loaders"] = [  # type: ignore[index] # noqa F405
    (
        "django.template.loaders.cached.Loader",
        [
            "django.template.loaders.filesystem.Loader",
            "django.template.loaders.app_directories.Loader",
        ],
    )
]

# EMAIL
# ------------------------------------------------------------------------------
MAILERS = {
    "default": {
        "BACKEND": "django.core.mail.backends.locmem.EmailBackend",
    }
}

# TASKS
# ------------------------------------------------------------------------------
TASKS = {
    "default": {
        "BACKEND": "django.tasks.backends.dummy.DummyBackend",
        "QUEUES": [],
    }
}

# CHANNELS
# ------------------------------------------------------------------------------
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}
