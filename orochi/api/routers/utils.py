from dask.distributed import Client
from django.conf import settings
from ninja import Router
from ninja.security import django_auth

from orochi.api.models import DaskStatusOut

router = Router()


@router.get(
    "/dask_status", auth=django_auth, response=DaskStatusOut, url_name="dask_status"
)
def dask_status(request):
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    res = dask_client.run_on_scheduler(
        lambda dask_scheduler: {
            w: [(ts.key, ts.state) for ts in ws.processing]
            for w, ws in dask_scheduler.workers.items()
        }
    )
    dask_client.close()
    return sum(len(running_tasks) for running_tasks in res.values())
