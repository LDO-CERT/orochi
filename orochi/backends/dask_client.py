import logging
import threading

from dask.distributed import Client
from django.conf import settings

logger = logging.getLogger(__name__)

_client_lock = threading.Lock()
_global_client: Client | None = None


def get_dask_client(timeout: str = "5s") -> Client:
    """Returns a thread-safe, process-level persistent Dask client singleton.

    Automatically reconnects if the client or cluster was closed.
    """
    global _global_client
    if (
        _global_client is None
        or _global_client.status in ("closed", "closing")
        or (
            getattr(_global_client, "cluster", None) is not None
            and _global_client.cluster.status in ("closed", "closing")
        )
    ):
        with _client_lock:
            if (
                _global_client is None
                or _global_client.status in ("closed", "closing")
                or (
                    getattr(_global_client, "cluster", None) is not None
                    and _global_client.cluster.status in ("closed", "closing")
                )
            ):
                logger.info("Initializing persistent Dask Client connected to %s", settings.DASK_SCHEDULER_URL)
                _global_client = Client(
                    settings.DASK_SCHEDULER_URL,
                    timeout=timeout,
                    set_as_default=False,
                )
    return _global_client


def close_dask_client() -> None:
    """Closes the persistent Dask client if open."""
    global _global_client
    with _client_lock:
        if _global_client is not None:
            try:
                _global_client.close()
            except Exception as e:
                logger.warning("Error closing Dask client: %s", e)
            finally:
                _global_client = None
