import logging
import os
import sys

import django

logger = logging.getLogger("distributed.utils_perf")
logger.setLevel(logging.ERROR)

os.environ["DATABASE_URL"] = "postgres://{}:{}@{}:{}/{}".format(
    os.environ["POSTGRES_USER"],
    os.environ["POSTGRES_PASSWORD"],
    os.environ["POSTGRES_HOST"],
    os.environ["POSTGRES_PORT"],
    os.environ["POSTGRES_DB"],
)

sys.path.insert(0, "/app/orochi")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.local")
django.setup()
