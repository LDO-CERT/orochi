"""
ASGI config for orochi project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/dev/howto/deployment/asgi/

"""
import os
import sys
import django

from pathlib import Path

# from django.core.asgi import get_asgi_application
from channels.routing import get_default_application

# from config.websocket import websocket_application

# This allows easy placement of apps within the interior
# orochi directory.
ROOT_DIR = Path(__file__).resolve(strict=True).parent.parent
sys.path.append(str(ROOT_DIR / "orochi"))

# If DJANGO_SETTINGS_MODULE is unset, default to the local settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")

# django_application = get_asgi_application()
# ws_application = get_default_application()

django.setup()
application = get_default_application()
