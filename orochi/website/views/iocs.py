import json
import logging
import sys

import requests
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user

from orochi.website.defaults import (
    SERVICE_ABUSEIPDB,
    SERVICE_GREYNOISE,
    SERVICE_MISP,
    SERVICE_OTX,
    SERVICE_VIRUSTOTAL,
)
from orochi.website.ioc import (
    export_iocs_to_stix,
)
from orochi.website.models import (
    Dump,
    DumpIOC,
    Service,
)
from orochi.website.views.common import (
    is_not_readonly,
)

logger = logging.getLogger(__name__)


def _views_pkg():
    """The ``orochi.website.views`` package, so tests can patch helpers exposed there."""
    return sys.modules["orochi.website.views"]


@login_required
@require_http_methods(["GET", "POST"])
def dump_iocs(request, index):
    """View and extract IOCs for a memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    if request.method == "POST":
        if not is_not_readonly(request.user):
            return HttpResponseForbidden("Read-only users cannot run IOC extraction.")
        _views_pkg().extract_dump_iocs(dump)
    else:
        # Auto-extract on first visit if none exist
        if not dump.iocs.exists():
            _views_pkg().extract_dump_iocs(dump)

    iocs = dump.iocs.all()
    kpi_counts = {
        "total": iocs.count(),
        "malicious": iocs.filter(is_malicious=True).count(),
        "ip": iocs.filter(ioc_type="ip").count(),
        "hash": iocs.filter(ioc_type__in=["hash_sha256", "hash_md5"]).count(),
        "domain": iocs.filter(ioc_type="domain").count(),
        "url": iocs.filter(ioc_type="url").count(),
        "yara": iocs.filter(ioc_type="yara").count(),
    }

    # Available services status
    services = {s.name: s for s in Service.objects.all()}
    intel_services = {
        "misp": SERVICE_MISP in services,
        "virustotal": SERVICE_VIRUSTOTAL in services,
        "abuseipdb": SERVICE_ABUSEIPDB in services,
        "otx": SERVICE_OTX in services,
        "greynoise": SERVICE_GREYNOISE in services,
    }

    is_htmx = getattr(request, "htmx", False)
    template = "website/partial_dump_iocs.html" if is_htmx else "website/dump_iocs.html"
    return render(
        request,
        template,
        {
            "dump": dump,
            "iocs": iocs,
            "kpi_counts": kpi_counts,
            "intel_services": intel_services,
            "readonly": not is_not_readonly(request.user),
            "is_standalone": not is_htmx,
        },
    )


@login_required
@require_http_methods(["POST"])
def ioc_enrich(request, index, ioc_id):
    """Enrich a single IOC using configured threat intel services."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")
    if not is_not_readonly(request.user):
        return HttpResponseForbidden("Read-only users cannot run threat enrichment.")

    ioc = get_object_or_404(DumpIOC, id=ioc_id, dump=dump)
    results = _views_pkg().enrich_ioc(ioc)
    return JsonResponse(
        {
            "success": True,
            "ioc_id": ioc.id,
            "threat_score": ioc.threat_score,
            "is_malicious": ioc.is_malicious,
            "enrichment": ioc.enrichment,
            "results": results,
        }
    )


@login_required
@require_http_methods(["POST"])
def ioc_enrich_all(request, index):
    """Batch enrich all IOCs for a memory dump."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")
    if not is_not_readonly(request.user):
        return HttpResponseForbidden("Read-only users cannot run threat enrichment.")

    from orochi.website.ioc import enrich_iocs

    return JsonResponse(enrich_iocs(dump.iocs.all(), enrich=_views_pkg().enrich_ioc))


@login_required
@require_http_methods(["POST"])
def ioc_export_misp(request, index):
    """Export IOCs for a dump to MISP."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")
    if not is_not_readonly(request.user):
        return HttpResponseForbidden("Read-only users cannot export to MISP.")

    raw_ids = request.POST.get("ioc_ids")
    if raw_ids:
        try:
            ids = [int(x.strip()) for x in raw_ids.split(",") if x.strip()]
            iocs = list(dump.iocs.filter(id__in=ids))
        except ValueError:
            iocs = list(dump.iocs.all())
    else:
        # Default: export all malicious or all IOCs if none explicitly marked malicious
        mal_iocs = list(dump.iocs.filter(is_malicious=True))
        iocs = mal_iocs if mal_iocs else list(dump.iocs.all())

    if not iocs:
        return JsonResponse(
            {"detail": "No IOCs available to export.", "message": "No IOCs available to export."}, status=400
        )

    try:
        res = _views_pkg().export_iocs_to_misp(dump, iocs, request.user)
        return JsonResponse(res)
    except Exception:
        logger.exception("MISP IOC export failed")
        msg = "MISP IOC export failed, check the server logs for details."
        return JsonResponse({"detail": msg, "message": msg}, status=400)


@login_required
@require_http_methods(["GET"])
def ioc_export_file(request, index):
    """Download IOCs in CSV, JSON, or STIX 2.1 format."""
    dump = get_object_or_404(Dump, index=index)
    if dump not in get_objects_for_user(request.user, "website.can_see"):
        return HttpResponseForbidden("Unauthorized to view this dump.")

    fmt = request.GET.get("format", "json").lower()
    iocs = list(dump.iocs.all())

    if fmt == "csv":
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["IOC Type", "Indicator Value", "Threat Score", "Malicious", "Source Plugin", "Context", "Enrichment"]
        )
        for ioc in iocs:
            writer.writerow(
                [
                    ioc.ioc_type,
                    ioc.value,
                    ioc.threat_score,
                    ioc.is_malicious,
                    ioc.source_plugin,
                    json.dumps(ioc.context),
                    json.dumps(ioc.enrichment),
                ]
            )
        response = HttpResponse(output.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = f'attachment; filename="iocs_{dump.index}.csv"'
        return response

    elif fmt == "stix":
        stix_bundle = export_iocs_to_stix(dump, iocs)
        response = HttpResponse(json.dumps(stix_bundle, indent=2), content_type="application/json")
        response["Content-Disposition"] = f'attachment; filename="stix2_iocs_{dump.index}.json"'
        return response

    else:  # JSON
        data = [
            {
                "id": ioc.id,
                "type": ioc.ioc_type,
                "value": ioc.value,
                "threat_score": ioc.threat_score,
                "is_malicious": ioc.is_malicious,
                "source_plugin": ioc.source_plugin,
                "context": ioc.context,
                "enrichment": ioc.enrichment,
                "created_at": ioc.created_at.isoformat(),
            }
            for ioc in iocs
        ]
        response = HttpResponse(json.dumps(data, indent=2), content_type="application/json")
        response["Content-Disposition"] = f'attachment; filename="iocs_{dump.index}.json"'
        return response


@login_required
@require_http_methods(["GET", "POST"])
def test_service_connection(request):
    """Test connectivity and authentication for external services (MISP, VT, AbuseIPDB, etc.)."""

    if not request.user.is_superuser:
        return HttpResponseForbidden("Only administrators can test service connectivity.")

    service_name = request.GET.get("service") or request.POST.get("service")
    try:
        service_id = int(service_name) if service_name and service_name.isdigit() else None
    except ValueError:
        service_id = None

    if not service_id:
        name_map = {
            "misp": SERVICE_MISP,
            "virustotal": SERVICE_VIRUSTOTAL,
            "abuseipdb": SERVICE_ABUSEIPDB,
            "otx": SERVICE_OTX,
            "greynoise": SERVICE_GREYNOISE,
        }
        service_id = name_map.get(str(service_name).lower())

    if not service_id:
        return JsonResponse({"success": False, "detail": "Invalid or unspecified service."}, status=400)

    try:
        service = Service.objects.get(name=service_id)
    except Service.DoesNotExist:
        return JsonResponse({"success": False, "detail": "Service is not configured."}, status=404)

    proxy_dict = service.proxy if (service.proxy and isinstance(service.proxy, dict)) else None

    try:
        if service.name == SERVICE_MISP:
            misp = _views_pkg().PyMISP(service.url, service.decrypted_key, service.verify_ssl, proxies=proxy_dict)
            version = misp.misp_instance_version
            ver_str = version.get("version", "unknown") if isinstance(version, dict) else str(version)
            return JsonResponse({"success": True, "message": f"Connected to MISP v{ver_str}", "version": version})

        elif service.name == SERVICE_ABUSEIPDB:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": service.decrypted_key, "Accept": "application/json"},
                params={"ipAddress": "8.8.8.8", "maxAgeInDays": "30"},
                proxies=proxy_dict,
                timeout=8,
            )
            if resp.status_code == 200:
                return JsonResponse({"success": True, "message": "Connected to AbuseIPDB API successfully."})
            return JsonResponse(
                {"success": False, "detail": f"AbuseIPDB returned status {resp.status_code}: {resp.text}"}, status=400
            )

        elif service.name == SERVICE_OTX:
            resp = requests.get(
                "https://otx.alienvault.com/api/v1/user/me",
                headers={"X-OTX-API-KEY": service.decrypted_key, "Accept": "application/json"},
                proxies=proxy_dict,
                timeout=8,
            )
            if resp.status_code == 200:
                username = resp.json().get("username", "")
                return JsonResponse({"success": True, "message": f"Connected to AlienVault OTX as user '{username}'."})
            return JsonResponse(
                {"success": False, "detail": f"AlienVault OTX returned status {resp.status_code}"}, status=400
            )

        elif service.name == SERVICE_GREYNOISE:
            resp = requests.get(
                "https://api.greynoise.io/v3/community/8.8.8.8",
                headers={"key": service.decrypted_key, "Accept": "application/json"},
                proxies=proxy_dict,
                timeout=8,
            )
            if resp.status_code in [200, 404]:
                return JsonResponse({"success": True, "message": "Connected to GreyNoise API successfully."})
            return JsonResponse(
                {"success": False, "detail": f"GreyNoise returned status {resp.status_code}"}, status=400
            )

        elif service.name == SERVICE_VIRUSTOTAL:
            resp = requests.get(
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": service.decrypted_key, "Accept": "application/json"},
                proxies=proxy_dict,
                timeout=8,
            )
            if resp.status_code == 200:
                return JsonResponse({"success": True, "message": "Connected to VirusTotal API v3 successfully."})
            return JsonResponse(
                {"success": False, "detail": f"VirusTotal returned status {resp.status_code}"}, status=400
            )

        return JsonResponse({"success": False, "detail": "Service does not support connection testing."}, status=400)

    except Exception as exc:
        return JsonResponse({"success": False, "detail": str(exc)}, status=500)
