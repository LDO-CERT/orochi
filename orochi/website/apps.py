import threading
import time

from django.apps import AppConfig


class WebsiteConfig(AppConfig):
    name = "orochi.website"

    def ready(self):
        import sys

        # Do not run background startup tasks when running tests or management commands
        cli_skip = [
            "pytest",
            "test",
            "makemigrations",
            "migrate",
            "collectstatic",
            "shell",
            "check",
        ]
        if any(cmd in " ".join(sys.argv) for cmd in cli_skip):
            return

        def enqueue_cache_task():
            import logging

            from dask.distributed import Client
            from django.conf import settings
            from django.core.cache import cache

            logger = logging.getLogger(__name__)

            # Poll for Dask scheduler and at least one worker to be ready (up to 90s)
            ready = False
            for _ in range(18):
                time.sleep(5)
                try:
                    client = Client(settings.DASK_SCHEDULER_URL, timeout="3s")
                    workers = client.scheduler_info().get("workers", {})
                    client.close()
                    if workers:
                        ready = True
                        break
                except Exception:
                    pass

            if not ready:
                logger.warning(
                    "Dask scheduler/workers not ready within startup timeout for cache build."
                )
                return

            try:
                # Check if we already enqueued this recently (e.g., in the last 60 seconds)
                # This prevents multiple workers (gunicorn/dask) from enqueuing the same task concurrently
                if not cache.get("cache_build_enqueued"):
                    cache.set("cache_build_enqueued", True, timeout=60)
                    from orochi.website.tasks import build_cache_in_background

                    build_cache_in_background.enqueue()
            except Exception as e:
                logger.error(f"Failed to enqueue cache task: {e}")

        # Enqueue the cache build task using django.tasks in a background thread
        # to prevent blocking app initialization and avoid DB cursor warnings.
        thread = threading.Thread(target=enqueue_cache_task)
        thread.daemon = True
        thread.start()
