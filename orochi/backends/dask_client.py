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


def wait_for_scheduler(key: str, timeout: float = 30.0, client: Client | None = None) -> bool:
    """Block until the scheduler knows the task ``key``; False after ``timeout`` seconds.

    ``submit`` and ``fire_and_forget`` only queue messages in the client: a short-lived process (management command,
    script) that exits right after can lose the task. Web servers and workers are long-lived and do not need this.
    """
    import time

    client = client or get_dask_client()
    deadline = time.monotonic() + timeout
    while True:
        try:
            if client.run_on_scheduler(lambda dask_scheduler, key=key: key in dask_scheduler.tasks):
                return True
        except Exception as exc:
            logger.debug("Scheduler check for %s failed: %s", key, exc)
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def submit_and_confirm(fn, *args, timeout: float = 30.0, **kwargs) -> str:
    """Submit ``fn(*args, **kwargs)`` as fire-and-forget and return its key once the scheduler holds it.

    Raises ``RuntimeError`` when the scheduler does not acknowledge the task within ``timeout`` seconds.
    """
    from distributed import fire_and_forget

    client = get_dask_client()
    future = client.submit(fn, *args, pure=False, **kwargs)
    fire_and_forget(future)
    if not wait_for_scheduler(future.key, timeout=timeout, client=client):
        raise RuntimeError(f"Dask scheduler did not receive task {future.key}")
    return future.key
