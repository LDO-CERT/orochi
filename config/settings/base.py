"""Base settings to build other settings files upon."""

from pathlib import Path

import environ
import ldap
from django_auth_ldap.config import LDAPSearch
from import_export.formats.base_formats import JSON

ROOT_DIR = Path(__file__).resolve(strict=True).parent.parent.parent
BASE_DIR = ROOT_DIR
# orochi/
APPS_DIR = ROOT_DIR / "orochi"
env = environ.Env()

if READ_DOT_ENV_FILE := env.bool("DJANGO_READ_DOT_ENV_FILE", default=True):
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
    "allauth.mfa",
    "colorfield",
    "crispy_forms",
    "crispy_bootstrap5",
    "django_file_form",
    "guardian",
    "widget_tweaks",
    "django_json_widget",
    "django_admin_listfilter_dropdown",
    "django_admin_multiple_choice_list_filter",
    "extra_settings",
    "import_export",
    "django_htmx",
    "django_tailwind_cli",
    "easyaudit",
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
AUTH_LDAP_SERVER_URI = env("AUTH_LDAP_SERVER_URI", default="").strip()
AUTHENTICATION_BACKENDS = [
    *(["django_auth_ldap.backend.LDAPBackend"] if AUTH_LDAP_SERVER_URI else []),
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

AUTH_USER_MODEL = "users.User"
LOGIN_REDIRECT_URL = "website:index"
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
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
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
    # "django.middleware.common.BrokenLinkEmailsMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "orochi.website.middleware.UpdatesMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
    "easyaudit.middleware.easyaudit.EasyAuditMiddleware",
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

# TAILWIND CLI
TAILWIND_CLI_VERSION = "4.3.5"
TAILWIND_CLI_AUTOMATIC_DOWNLOAD = False
TAILWIND_CLI_SRC_CSS = "css/tailwind.css"
TAILWIND_CLI_DIST_CSS = "css/tailwind_dist.css"
TAILWIND_CLI_PATH = str(ROOT_DIR / "tailwindcss")

# MEDIA
# ------------------------------------------------------------------------------
MEDIA_ROOT = env("DJANGO_MEDIA_ROOT", default="/media")
MEDIA_URL = "/media/"

# FILE_UPLOAD
# ------------------------------------------------------------------------------
FILE_FORM_UPLOAD_DIR = "tmp"
try:
    Path(MEDIA_ROOT, FILE_FORM_UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
except OSError:
    pass

DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1024 * 15
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1024 * 15

# TEMPLATES
# ------------------------------------------------------------------------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [str(APPS_DIR / "templates")],
        # No explicit loaders: Django wraps filesystem + app directories loaders in the cached loader
        "APP_DIRS": True,
        "OPTIONS": {
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
            "debug": DEBUG,
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
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="webmaster@localhost")
SERVER_EMAIL = env("SERVER_EMAIL", default="noreply@localhost")

# ADMIN
# ------------------------------------------------------------------------------
ADMIN_URL = "admin/"
ADMINS = env.list("ADMINS_EMAIL", default=["ldo-cert@orochi.dev"])
MANAGERS = ADMINS

# LOGGING
# ------------------------------------------------------------------------------
DEBUG_LEVEL = env("DEBUG_LEVEL", default="WARNING")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"verbose": {"format": "%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s"}},
    "handlers": {
        "console": {
            "level": DEBUG_LEVEL,
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        }
    },
    "root": {"level": DEBUG_LEVEL, "handlers": ["console"]},
    "loggers": {
        "orochi": {"level": env("OROCHI_LOG_LEVEL", default=DEBUG_LEVEL), "handlers": ["console"], "propagate": False},
        "pymisp": {"level": "WARNING", "handlers": ["console"], "propagate": False},
        "git": {"level": "WARNING", "handlers": ["console"], "propagate": False},
        "asyncio": {"level": "WARNING", "handlers": ["console"], "propagate": False},
        "urllib3": {"level": "WARNING", "handlers": ["console"], "propagate": False},
        "distributed": {"level": DEBUG_LEVEL, "handlers": ["console"], "propagate": False},
        "django_auth_ldap": {"level": DEBUG_LEVEL, "handlers": ["console"], "propagate": False},
        "import_export": {"level": DEBUG_LEVEL, "handlers": ["console"], "propagate": False},
    },
}

# django-allauth
# ------------------------------------------------------------------------------
# Closed by default: a forensic platform should not accept anonymous sign-ups.
ACCOUNT_ALLOW_REGISTRATION = env.bool("DJANGO_ACCOUNT_ALLOW_REGISTRATION", False)
ACCOUNT_LOGIN_METHODS = {"username"}
ACCOUNT_SIGNUP_FIELDS = env.list("ACCOUNT_SIGNUP_FIELDS", default=["username*", "email", "password1*", "password2*"])
ACCOUNT_EMAIL_VERIFICATION = env("ACCOUNT_EMAIL_VERIFICATION", default="optional")
ACCOUNT_ADAPTER = "orochi.users.adapters.AccountAdapter"

MFA_SUPPORTED_TYPES = ["totp", "webauthn"]
MFA_PASSKEY_LOGIN_ENABLED = False
# Passkeys over plain HTTP only when explicitly allowed (development.py enables it)
MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN = env.bool("MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN", default=DEBUG)

# Dask
# -------------------------------------------------------------------------------
DASK_SCHEDULER_URL = env("DASK_SCHEDULER_URL")

# AUTOFIELD
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# IMPORT/EXPORT
IMPORT_EXPORT_FORMATS = [JSON]

# Channels
# -------------------------------------------------------------------------------
ASGI_APPLICATION = "config.routing.application"
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [
                {
                    "host": env("REDIS_SERVER"),
                    "port": env("REDIS_PORT"),
                    "socket_timeout": None,
                }
            ],
        },
    },
}

# TASKS
# -------------------------------------------------------------------------------
TASKS = {
    "default": {
        "BACKEND": "orochi.backends.dask.DaskTaskBackend",
        "QUEUES": [],  # Empty list = allow all queue names
        "OPTIONS": {
            "ADDRESS": env("DASK_SCHEDULER_URL"),
        },
    },
}

# OBJECT STORAGE (Optional S3 / MinIO / Azure Blob - Issue #1562)
# -------------------------------------------------------------------------------
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}
USE_S3_STORAGE = env.bool("USE_S3_STORAGE", default=False)
USE_AZURE_STORAGE = env.bool("USE_AZURE_STORAGE", default=False)
# Local copies of remote dumps (MEDIA_ROOT/_storage_cache) are evicted, least recently used
# first, above this size. 0 disables eviction.
STORAGE_CACHE_MAX_BYTES = env.int("STORAGE_CACHE_MAX_GB", default=0) * 1024**3
if USE_S3_STORAGE:
    # Requires the django-storages[s3] package, which is not installed by default (orochi.E001).
    STORAGES["default"] = {
        "BACKEND": env("DEFAULT_FILE_STORAGE_BACKEND", default="storages.backends.s3.S3Storage"),
        "OPTIONS": {
            "bucket_name": env("AWS_STORAGE_BUCKET_NAME", default="orochi-dumps"),
            "endpoint_url": env("AWS_S3_ENDPOINT_URL", default=None),
            "access_key": env("AWS_ACCESS_KEY_ID", default=None),
            "secret_key": env("AWS_SECRET_ACCESS_KEY", default=None),
            "region_name": env("AWS_S3_REGION_NAME", default="us-east-1"),
        },
    }
elif USE_AZURE_STORAGE:
    # Requires django-storages[azure] (Issue #1562).
    STORAGES["default"] = {
        "BACKEND": env(
            "DEFAULT_FILE_STORAGE_BACKEND",
            default="storages.backends.azure_storage.AzureStorage",
        ),
        "OPTIONS": {
            "account_name": env("AZURE_ACCOUNT_NAME", default=None),
            "account_key": env("AZURE_ACCOUNT_KEY", default=None),
            "azure_container": env("AZURE_CONTAINER", default="orochi-dumps"),
            "connection_string": env("AZURE_CONNECTION_STRING", default=None),
        },
    }

# LDAP
# ------------------------------------------------------------------------------
AUTH_LDAP_BIND_DN = env("AUTH_LDAP_BIND_DN", default="")
AUTH_LDAP_BIND_PASSWORD = env("AUTH_LDAP_BIND_PASSWORD", default="")
AUTH_LDAP_USER_SEARCH = LDAPSearch(
    env("AUTH_LDAP_USER_SEARCH_DN", default=""),
    ldap.SCOPE_SUBTREE,
    env("AUTH_LDAP_USER_SEARCH_ALIAS", default="(uid=%(user)s)"),
)
AUTH_LDAP_USER_ATTR_MAP = env.dict("AUTH_LDAP_USER_ATTR_MAP", default={})

# django-cors-headers - https://github.com/adamchainz/django-cors-headers#setup
CORS_URLS_REGEX = r"^/api/.*$"
CSRF_DEFAULT_TRUSTED = [
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1",
    "http://localhost:8000",
    "https://localhost:8000",
    "http://orochi.dev",
    "https://orochi.dev",
]
CSRF_TRUSTED_ORIGINS = sorted(set(CSRF_DEFAULT_TRUSTED + env.list("CSRF_TRUSTED_ORIGINS", default=[])))


# OROCHI EXTRA_SETTINGS
# ------------------------------------------------------------------------------
EXTRA_SETTINGS_ADMIN_APP = "extra_settings"
EXTRA_SETTINGS_CACHE_NAME = "extra_settings"
EXTRA_SETTINGS_IMAGE_UPLOAD_TO = "images"

EXTRA_SETTINGS_DEFAULTS = [
    {
        "description": "path of the default yara path. When changed you must rebuild it.",
        "name": "DEFAULT_YARA_RULE_PATH",
        "type": "string",
        "value": env("DEFAULT_YARA_RULE_PATH"),
    },
    {
        "description": "Thread number for multiprocess operation",
        "name": "THREAD_NO",
        "type": "int",
        "value": env.int("THREAD_NO"),
    },
    {
        "description": "Online url for awesome readme file",
        "name": "AWESOME_PATH",
        "type": "string",
        "value": env("AWESOME_PATH"),
    },
    {
        "description": "Online path of volatility symbols",
        "name": "VOLATILITY_SYMBOL_DOWNLOAD_PATH",
        "type": "string",
        "value": env("VOLATILITY_SYMBOL_DOWNLOAD_PATH"),
    },
    {
        "description": (
            "Download the debug package of an unknown Linux kernel, build its ISF and run the automatic plugins "
            "when a dump has no symbols (needs Internet access)."
        ),
        "name": "AUTO_RESOLVE_SYMBOLS",
        "type": "bool",
        "value": env.bool("AUTO_RESOLVE_SYMBOLS", default=False),
    },
    {
        "description": (
            "Remote banners index used by Volatility to download Linux/Mac ISF on demand. "
            "Empty disables it (air-gapped installations)."
        ),
        "name": "VOLATILITY_REMOTE_ISF_URL",
        "type": "string",
        "value": env(
            "VOLATILITY_REMOTE_ISF_URL",
            default="https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json",
        ),
    },
    {
        "description": "Comma separated regipy plugins run on the registry hives extracted from Windows dumps.",
        "name": "REGIPY_PLUGINS",
        "type": "string",
        "value": env("REGIPY_PLUGINS"),
    },
    {
        "description": "Local cache of remote (S3/MinIO) dumps, in GB: least recently used copies are evicted above it. 0 = never.",
        "name": "STORAGE_CACHE_MAX_GB",
        "type": "int",
        "value": env.int("STORAGE_CACHE_MAX_GB", default=0),
    },
    {
        "description": "Path for custom login logo",
        "name": "CUSTOM_LOGO",
        "type": "image",
        "value": None,
    },
]

# local path for yara folder
LOCAL_YARA_PATH = env("LOCAL_YARA_PATH")
# Valid yara file exts
YARA_EXT = [".yar", ".yara", ".rule"]


# local path of volatility folder
def _resolve_vol_path(subpath: str, docker_path: str) -> str:
    if Path(docker_path).exists():
        return docker_path
    try:
        import volatility3

        vol_root = Path(volatility3.__file__).resolve().parent
        candidate = vol_root / subpath
        if candidate.exists() or not Path(docker_path).exists():
            return str(candidate)
    except Exception:
        pass
    return docker_path


VOLATILITY_SYMBOL_PATH = env("VOLATILITY_SYMBOL_PATH", default=_resolve_vol_path("symbols", "/symbols"))
VOLATILITY_PLUGIN_PATH = env("VOLATILITY_PLUGIN_PATH", default=_resolve_vol_path("plugins/custom", "/plugins"))
# Remote banners index for on-demand Linux/Mac ISF download (empty to disable)
VOLATILITY_REMOTE_ISF_URL = env(
    "VOLATILITY_REMOTE_ISF_URL",
    default="https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json",
)
# local path of dwarf2json executable
DWARF2JSON = "/dwarf2json/./dwarf2json"
# local path of btf2json executable
BTF2JSON = "/btf2json/btf2json"
# path of a remote folder with already uploaded files
LOCAL_UPLOAD_PATH = env("LOCAL_UPLOAD_PATH")
# Regipy plugins
REGIPY_PLUGINS = env.list("REGIPY_PLUGINS")

# HTTPS
if env.bool("HTTPS", False) or env("USE_DOCKER", default="no") == "yes":
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
if env.bool("HTTPS", False):
    SECURE_SSL_REDIRECT = True

# EASY AUDIT
DJANGO_EASY_AUDIT_UNREGISTERED_CLASSES_EXTRA = ["website.TaskLog", "website.Value", "website.Result"]
DJANGO_EASY_AUDIT_UNREGISTERED_URLS_EXTRA = [r"^.*/dask_status/?$"]
