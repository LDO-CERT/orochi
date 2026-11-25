"""Settings modules load with a minimal environment and keep production safe (#256)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]

MINIMAL_ENV = {
    "DJANGO_READ_DOT_ENV_FILE": "False",
    "DJANGO_SECRET_KEY": "x" * 60,
    "ALLOWED_HOSTS": "orochi.example",
    "DATABASE_URL": "postgresql://u:p@localhost:5432/orochi",
    "REDIS_URL": "redis://localhost:6379/0",
    "REDIS_SERVER": "localhost",
    "REDIS_PORT": "6379",
    "DASK_SCHEDULER_URL": "tcp://localhost:8786",
    "DEFAULT_YARA_RULE_PATH": "/tmp/default.yara",
    "THREAD_NO": "2",
    "AWESOME_PATH": "https://example.invalid/README.md",
    "VOLATILITY_SYMBOL_DOWNLOAD_PATH": "https://example.invalid/",
    "LOCAL_YARA_PATH": "/tmp",
    "LOCAL_UPLOAD_PATH": "/tmp",
    "REGIPY_PLUGINS": "computer_name",
    "DJANGO_MEDIA_ROOT": "/tmp/orochi_settings_test_media",
}

PROBE = """
import json, django
from django.conf import settings
django.setup()
from django.template import engines
loaders = [type(l).__name__ for l in engines["django"].engine.template_loaders]
print(json.dumps({
    "DEBUG": settings.DEBUG,
    "template_debug": engines["django"].engine.debug,
    "loaders": loaders,
    "DEFAULT_FROM_EMAIL": settings.DEFAULT_FROM_EMAIL,
    "ADMINS": settings.ADMINS,
    "SESSION_COOKIE_SECURE": settings.SESSION_COOKIE_SECURE,
    "CSRF_COOKIE_SECURE": settings.CSRF_COOKIE_SECURE,
    "MFA_INSECURE": settings.MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN,
    "apps": [a for a in settings.INSTALLED_APPS if a in ("debug_toolbar", "django_extensions")],
}))
"""


def _run(module: str, extra_env: dict | None = None, args: list[str] | None = None) -> subprocess.CompletedProcess:
    # Isolated from the test process: other tests may change os.environ
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR") if k in os.environ}
    env.update(MINIMAL_ENV)
    env.update(extra_env or {})
    env["DJANGO_SETTINGS_MODULE"] = module
    cmd = args or [sys.executable, "-c", PROBE]
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)


def _probe(module: str, extra_env: dict | None = None) -> dict:
    proc = _run(module, extra_env)
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_production_settings_are_safe():
    prod = _probe("config.settings.production")
    assert prod["DEBUG"] is False
    assert prod["template_debug"] is False
    assert prod["loaders"] == ["Loader"]  # the cached loader wraps filesystem + app directories
    assert prod["DEFAULT_FROM_EMAIL"]
    assert prod["MFA_INSECURE"] is False
    assert prod["apps"] == []
    assert prod["SESSION_COOKIE_SECURE"] is False


def test_production_https_enables_secure_cookies():
    prod = _probe("config.settings.production", {"HTTPS": "True", "ADMINS_EMAIL": "a@x.test,b@x.test"})
    assert prod["SESSION_COOKIE_SECURE"] is True
    assert prod["CSRF_COOKIE_SECURE"] is True
    assert prod["ADMINS"] == ["a@x.test", "b@x.test"]


def test_local_is_an_alias_of_production():
    assert _probe("config.settings.local") == _probe("config.settings.production")


def test_development_settings_enable_debugging():
    dev = _probe("config.settings.development", {"DJANGO_SECRET_KEY": ""})
    assert dev["DEBUG"] is True
    assert dev["template_debug"] is True
    assert dev["MFA_INSECURE"] is True


@pytest.mark.parametrize("module", ["config.settings.production", "config.settings.development"])
def test_system_checks_pass(module):
    # The GeneratedField model check reads the server version: use the test suite's database
    database_url = os.environ.get("DATABASE_URL", "postgresql://debug:debug@localhost:5432/orochi")
    proc = _run(
        module,
        {"HTTPS": "True", "DATABASE_URL": database_url},
        [sys.executable, "manage.py", "check", "--deploy", "--fail-level", "ERROR"],
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
