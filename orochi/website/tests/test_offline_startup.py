"""Regression tests for Issue #1670: web container offline startup & pinned Tailwind binary."""

from pathlib import Path

from django.conf import settings

ROOT = Path(__file__).resolve().parents[3]


def test_tailwind_version_pinned_and_runtime_download_disabled():
    """Tailwind CLI version must be pinned and automatic runtime downloads disabled."""
    assert getattr(settings, "TAILWIND_CLI_VERSION", None) == "4.3.5"
    assert getattr(settings, "TAILWIND_CLI_AUTOMATIC_DOWNLOAD", True) is False


def test_dockerfile_pins_tailwind_and_verifies_sha256():
    """Dockerfile must pin Tailwind version and verify SHA-256 checksum at build time."""
    dockerfile = (ROOT / "compose" / "local" / "django" / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG TAILWIND_CLI_VERSION=4.3.5" in dockerfile
    assert "TAILWIND_SHA256_AMD64=" in dockerfile
    assert "TAILWIND_SHA256_ARM64=" in dockerfile
    assert "sha256sum -c -" in dockerfile
    assert "ensure_cli_binary" not in dockerfile


def test_start_script_offline_safe_and_no_makemigrations_or_default_watcher():
    """Production start script must not run makemigrations, default watcher, or rebuild CSS unnecessarily."""
    start_script = (ROOT / "compose" / "local" / "django" / "start").read_text(encoding="utf-8")
    assert "makemigrations" not in start_script
    assert "TAILWIND_REBUILD:-0" in start_script
    assert "TAILWIND_WATCH:-0" in start_script
