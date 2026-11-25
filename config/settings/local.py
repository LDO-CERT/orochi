"""Deprecated alias of ``config.settings.production``.

Kept so that existing ``.envs/.local/.django`` files with ``DJANGO_SETTINGS_MODULE=config.settings.local`` keep
working. New deployments use ``config.settings.production`` (or ``config.settings.development`` when developing).
"""

from .production import *  # noqa: F403
