"""
Base settings to build other settings files upon.
"""

from pathlib import Path

import environ
import ldap
from django_auth_ldap.config import LDAPSearch

ROOT_DIR = Path(__file__).resolve(strict=True).parent.parent.parent
# orochi/
APPS_DIR = ROOT_DIR / "orochi"
env = environ.Env()

if READ_DOT_ENV_FILE := env.bool("DJANGO_READ_DOT_ENV_FILE", default=False):
    # OS environment variables take precedence over variables from .env
    env.read_env(str(ROOT_DIR / ".env"))

# GENERAL
# ------------------------------------------------------------------------------
DEBUG = env.bool("DJANGO_DEBUG", False)
TIME_ZONE = "UTC"
LANGUAGE_CODE = "en-us"
SITE_ID = 1
USE_I18N = True
USE_L10N = True
USE_TZ = True

DATA_UPLOAD_MAX_NUMBER_FIELDS = None

LOCALE_PATHS = [str(ROOT_DIR / "locale")]

# DATABASES
# ------------------------------------------------------------------------------
DATABASES = {"default": env.db("DATABASE_URL")}
DATABASES["default"]["ATOMIC_REQUESTS"] = True

# URLS
# ------------------------------------------------------------------------------
ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

# APPS
# ------------------------------------------------------------------------------
DJANGO_APPS = [
    "daphne",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "django.contrib.admin",
    "django.contrib.postgres",
    "django.forms",
    "channels",
]
THIRD_PARTY_APPS = [
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "colorfield",
    "crispy_forms",
    "crispy_bootstrap5",
    "django_file_form",
    "guardian",
    "widget_tweaks",
    "django_json_widget",
    "rest_framework",
    "rest_framework.authtoken",
    "drf_yasg",
    "django_admin_listfilter_dropdown",
    "django_admin_multiple_choice_list_filter",
]

LOCAL_APPS = [
    "orochi.users.apps.UsersConfig",
    "orochi.website.apps.WebsiteConfig",
    "orochi.ya.apps.YaConfig",
]
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# MIGRATIONS
# ------------------------------------------------------------------------------
MIGRATION_MODULES = {"sites": "orochi.contrib.sites.migrations"}

# AUTHENTICATION
# ------------------------------------------------------------------------------
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
    "guardian.backends.ObjectPermissionBackend",
]


if use_ldap := env.bool("USE_LDAP", False):
    AUTHENTICATION_BACKENDS = [
        "django_auth_ldap.backend.LDAPBackend"
        "django.contrib.auth.backends.ModelBackend",
        "guardian.backends.ObjectPermissionBackend",
    ]
else:
    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",
        "allauth.account.auth_backends.AuthenticationBackend",
        "guardian.backends.ObjectPermissionBackend",
    ]

AUTH_USER_MODEL = "users.User"
LOGIN_REDIRECT_URL = "users:redirect"
LOGIN_URL = "account_login"

# PASSWORDS
# ------------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# MIDDLEWARE
# ------------------------------------------------------------------------------
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.common.BrokenLinkEmailsMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "orochi.website.middleware.UpdatesMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

# STATIC
# ------------------------------------------------------------------------------
STATIC_ROOT = ROOT_DIR / "staticfiles"
STATIC_ROOT.mkdir(parents=True, exist_ok=True)

STATIC_URL = "/static/"
STATICFILES_DIRS = [str(APPS_DIR / "static")]
STATICFILES_FINDERS = [
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
]

# MEDIA
# ------------------------------------------------------------------------------
MEDIA_ROOT = "/media"
MEDIA_URL = "/media/"

# FILE_UPLOAD
# ------------------------------------------------------------------------------
FILE_FORM_UPLOAD_DIR = "tmp"
Path(MEDIA_ROOT, FILE_FORM_UPLOAD_DIR).mkdir(parents=True, exist_ok=True)

DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1024 * 15
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1024 * 15

# TEMPLATES
# ------------------------------------------------------------------------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [str(APPS_DIR / "templates")],
        "OPTIONS": {
            "loaders": [
                "django.template.loaders.filesystem.Loader",
                "django.template.loaders.app_directories.Loader",
            ],
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
                "orochi.utils.context_processors.settings_context",
            ],
            "debug": True,
        },
    }
]
FORM_RENDERER = "django.forms.renderers.TemplatesSetting"
CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"
CRISPY_TEMPLATE_PACK = "bootstrap5"

# FIXTURES
# ------------------------------------------------------------------------------
FIXTURE_DIRS = (str(APPS_DIR / "fixtures"),)

# SECURITY
# ------------------------------------------------------------------------------
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"

# EMAIL
# ------------------------------------------------------------------------------
EMAIL_BACKEND = env(
    "DJANGO_EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend"
)
EMAIL_TIMEOUT = 5

# ADMIN
# ------------------------------------------------------------------------------
ADMIN_URL = "admin/"
ADMINS = [("""LDO-CERT""", "ldo-cert@example.com")]
MANAGERS = ADMINS

# LOGGING
# ------------------------------------------------------------------------------
DEBUG_LEVEL = env("DEBUG_LEVEL", default="WARNING")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "%(levelname)s %(asctime)s %(module)s "
            "%(process)d %(thread)d %(message)s"
        }
    },
    "handlers": {
        "console": {
            "level": DEBUG_LEVEL,
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        }
    },
    "root": {"level": DEBUG_LEVEL, "handlers": ["console"]},
    "loggers": {
        "distributed": {"level": DEBUG_LEVEL, "handlers": ["console"]},
    },
}

# django-allauth
# ------------------------------------------------------------------------------
ACCOUNT_ALLOW_REGISTRATION = env.bool("DJANGO_ACCOUNT_ALLOW_REGISTRATION", True)
ACCOUNT_AUTHENTICATION_METHOD = "username"
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_ADAPTER = "orochi.users.adapters.AccountAdapter"
SOCIALACCOUNT_ADAPTER = "orochi.users.adapters.SocialAccountAdapter"

# Elasticsearch
# -------------------------------------------------------------------------------
ELASTICSEARCH_URL = env("ELASTICSEARCH_URL")

# Dask
# -------------------------------------------------------------------------------
DASK_SCHEDULER_URL = env("DASK_SCHEDULER_URL")

# AUTOFIELD
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# Channels
# -------------------------------------------------------------------------------
ASGI_APPLICATION = "config.routing.application"
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [(env("REDIS_SERVER"), env("REDIS_PORT"))],
        },
    },
}

# LDAP
# ------------------------------------------------------------------------------
if use_ldap:
    AUTH_LDAP_SERVER_URI = env("AUTH_LDAP_SERVER_URI")
    AUTH_LDAP_BIND_DN = env("AUTH_LDAP_BIND_DN")
    AUTH_LDAP_BIND_PASSWORD = env("AUTH_LDAP_BIND_PASSWORD")
    AUTH_LDAP_USER_SEARCH = LDAPSearch(
        env("AUTH_LDAP_USER_SEARCH_DN"),
        ldap.SCOPE_SUBTREE,
        env("AUTH_LDAP_USER_SEARCH_ALIAS"),
    )
    AUTH_LDAP_USER_ATTR_MAP = env.dict("AUTH_LDAP_USER_ATTR_MAP")

# REST FRAMEWORK
# -------------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
}

# django-cors-headers - https://github.com/adamchainz/django-cors-headers#setup
CORS_URLS_REGEX = r"^/api/.*$"
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS")
# OROCHI CONFIGURATIONS
# -------------------------------------------------------------------------------

# elastic windows size to increase number of returned results
MAX_ELASTIC_WINDOWS_SIZE = env("MAX_ELASTIC_WINDOWS_SIZE")
# path of the default yara path
DEFAULT_YARA_RULE_PATH = env("DEFAULT_YARA_RULE_PATH")
# thread number for multiprocess operation
THREAD_NO = env.int("THREAD_NO")
# online url for awesome readme file
AWESOME_PATH = env("AWESOME_PATH")
# local path for yara folder
LOCAL_YARA_PATH = env("LOCAL_YARA_PATH")
# extension valid to be considered as yara file
YARA_EXT = [".yar", ".yara", ".rule"]
# indexes name for rules
RULES_INDEX = "rules"
RULES_ANALYSIS_INDEX = "rules_analysis"
# local path of volatility folder
VOLATILITY_SYMBOL_PATH = "/src/volatility3/volatility3/symbols"
VOLATILITY_PLUGIN_PATH = "/src/volatility3/volatility3/plugins/custom"
# local path of dwarg2json executable
DWARF2JSON = "/dwarf2json/./dwarf2json"
# online path of volatility symbols
VOLATILITY_SYMBOL_DOWNLOAD_PATH = env("VOLATILITY_SYMBOL_DOWNLOAD_PATH")
# path of a remote folder with already uploaded files
LOCAL_UPLOAD_PATH = env("LOCAL_UPLOAD_PATH")
# Regipy plugins
REGIPY_PLUGINS = env.list("REGIPY_PLUGINS")
