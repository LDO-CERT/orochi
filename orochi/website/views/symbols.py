import logging

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.views.decorators.http import require_http_methods

from orochi.website.defaults import RESULT_STATUS_DISABLED, RESULT_STATUS_UNSATISFIED
from orochi.website.forms import (
    SymbolBannerForm,
    SymbolISFForm,
    SymbolPackageForm,
    SymbolUploadForm,
)
from orochi.website.models import (
    Dump,
)
from orochi.website.views.common import (
    is_admin,
    role_required,
)

logger = logging.getLogger(__name__)


@login_required
@role_required(is_admin)
@require_http_methods(["GET"])
def banner_symbols(request):
    """Return suggested banner and a button to download item with Smart Symbol Assistant diagnosis."""
    dump = get_object_or_404(Dump, index=request.GET.get("index"))
    from orochi.website.symbols_assistant import diagnose_symbols

    diagnosis = diagnose_symbols(dump)
    initial_path = dump.suggested_symbols_path or diagnosis.get("suggested_paths") or []
    context = {
        "dump": dump,
        "diagnosis": diagnosis,
        "can_auto_resolve": diagnosis.get("can_auto_resolve", False),
        "retryable_count": dump.result_set.filter(
            result__in=[RESULT_STATUS_UNSATISFIED, RESULT_STATUS_DISABLED]
        ).count(),
        "form": SymbolBannerForm(instance=dump, initial={"path": initial_path}),
    }
    if getattr(request, "htmx", False):
        return render(request, "website/partial_symbols_banner.html", context)

    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_symbols_banner.html",
                context,
                request=request,
            )
        }
    )


@login_required
@role_required(is_admin)
def list_symbols(request):
    """Return list of symbols with diagnostics health."""
    from orochi.website.symbols_assistant import check_symbols_health

    health = check_symbols_health()
    return TemplateResponse(request, "website/list_symbols.html", {"health": health})


@login_required
@role_required(is_admin)
@require_http_methods(["GET"])
def upload_symbols(request):
    """Upload symbols"""
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_symbols_upload.html",
                {"form": SymbolUploadForm()},
                request=request,
            )
        }
    )


@login_required
@role_required(is_admin)
@require_http_methods(["GET"])
def download_isf(request):
    """Download all symbols from provided isf server path"""
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_isf_download.html",
                {"form": SymbolISFForm()},
                request=request,
            )
        }
    )


@login_required
@role_required(is_admin)
@require_http_methods(["GET"])
def upload_packages(request):
    """Generate symbols from uploaded file"""
    return JsonResponse(
        {
            "html_form": render_to_string(
                "website/partial_packages_upload.html",
                {"form": SymbolPackageForm()},
                request=request,
            )
        }
    )
