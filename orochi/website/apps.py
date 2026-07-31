import threading
import time

from django.apps import AppConfig


class WebsiteConfig(AppConfig):
    name = "orochi.website"

    def ready(self):
        def enqueue_cache_task():
            # Sleep briefly to let Dask scheduler initialize and to bypass quick management commands
            time.sleep(5)
            try:
                from orochi.website.tasks import build_cache_in_background

                build_cache_in_background.enqueue()
            except Exception as e:
                import logging

                logging.getLogger(__name__).error(f"Failed to enqueue cache task: {e}")

        # Enqueue the cache build task using django.tasks in a background thread
        # to prevent blocking app initialization and avoid DB cursor warnings.
        thread = threading.Thread(target=enqueue_cache_task)
        thread.daemon = True
        thread.start()
