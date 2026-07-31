import json
from pathlib import Path
from typing import Any

import geoip2.database
from dask.distributed import Client
from django.conf import settings
from django.shortcuts import get_object_or_404
from geoip2.errors import GeoIP2Error
from guardian.shortcuts import get_objects_for_user
from ninja import Router
from ninja.security import django_auth

from orochi.api.models import DaskStatusOut, ErrorsOut
from orochi.website.models import Dump

router = Router()


@router.get("changelog", auth=django_auth, response={200: Any, 400: ErrorsOut})
def changelog(request):
    """
    Summary:
    Endpoint to retrieve the changelog content.

    Explanation:
    Retrieves the content of the CHANGELOG.md file and returns it as a response. If an exception occurs during the process, it returns an error response.

    Args:
    - request: The request object.

    Returns:
    - Tuple[int, Dict[str, str]]: A tuple containing the status code and a dictionary with the changelog content.

    Raises:
    - ErrorsOut: If an exception occurs during the file reading process.
    """
    try:
        changelog_path = Path("/app/CHANGELOG.md")
        with open(changelog_path, "r") as f:
            changelog_content = "".join(f.readlines())
            return 200, {"note": changelog_content}
    except Exception as excp:
        return 400, ErrorsOut(errors=str(excp))


@router.get(
    "/dask_status",
    auth=django_auth,
    response=DaskStatusOut,
    url_name="dask_status",
)
def dask_status(request):
    """
    Get the total number of running tasks on the Dask scheduler.

    Args:
        request: The request object.

    Returns:
        int: The total number of running tasks on the Dask scheduler.
    """
    dask_client = Client(settings.DASK_SCHEDULER_URL)
    res = dask_client.run_on_scheduler(
        lambda dask_scheduler: {
            w: [(ts.key, ts.state) for ts in ws.processing]
            for w, ws in dask_scheduler.workers.items()
        }
    )
    dask_client.close()
    return DaskStatusOut(
        running=sum(len(running_tasks) for running_tasks in res.values())
    )


@router.get(
    "/maxmind",
    auth=django_auth,
    url_name="maxmind",
    response={200: Any, 400: ErrorsOut},
)
def maxmind(request, ip: str):
    """
    Retrieve geolocation data for the given IP address using MaxMind databases.

    Args:
        request: The request object.
        ip (str): The IP address for which geolocation data is to be retrieved.

    Returns:
        tuple: A tuple containing the HTTP status code and the geolocation data as a dictionary.
            The status code 200 indicates success, while 400 indicates an error.
    """
    if (
        not Path("/maxmind/GeoLite2-ASN.mmdb").exists()
        and not Path("/maxmind/GeoLite2-City.mmdb").exists()
        and not Path("/maxmind/GeoLite2-Country.mmdb").exists()
    ):
        return 400, ErrorsOut(errors="Maxmind databases not found.")

    try:
        data = {}
        if Path("/maxmind/GeoLite2-ASN.mmdb").exists():
            with geoip2.database.Reader("/maxmind/GeoLite2-ASN.mmdb") as reader:
                data |= reader.asn(ip).to_dict()
        if Path("/maxmind/GeoLite2-City.mmdb").exists():
            with geoip2.database.Reader("/maxmind/GeoLite2-City.mmdb") as reader:
                data |= reader.city(ip).to_dict()
        if Path("/maxmind/GeoLite2-Country.mmdb").exists():
            with geoip2.database.Reader("/maxmind/GeoLite2-Country.mmdb") as reader:
                data |= reader.country(ip).to_dict()
        return 200, data
    except (GeoIP2Error, Exception) as excp:
        return 400, ErrorsOut(errors=str(excp))


@router.get("/vt", url_name="vt", response={200: Any, 400: ErrorsOut}, auth=django_auth)
def get_extracted_dump_vt_report(request, path: str):
    path = Path(path)
    index = path.parts[2]
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return 403, ErrorsOut(errors="You do not have permission to access this dump.")
    if path.exists():
        return 200, json.loads(open(path, "r").read())
    return 400, ErrorsOut(errors="File not found.")
