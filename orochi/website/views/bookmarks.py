import contextlib
import logging

from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.db.utils import IntegrityError
from django.http import JsonResponse
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import get_objects_for_user

from orochi.website.forms import (
    BookmarkForm,
    EditBookmarkForm,
)
from orochi.website.models import (
    Bookmark,
    Case,
    Dump,
    Plugin,
    UserPlugin,
)
from orochi.website.views.common import (
    DUMP_ORDER_BY,
    INDEX_VALUES_LIST,
    is_not_readonly,
)

logger = logging.getLogger(__name__)


@login_required
@require_http_methods(["GET", "POST"])
def add_bookmark(request):
    """Add bookmark in user settings"""
    if request.method == "POST":
        form = BookmarkForm(request.POST)
        if form.is_valid():
            try:
                indexes = []
                ok_indexes = list(get_objects_for_user(request.user, "website.can_see").values_list("index", flat=True))
                selected = form.cleaned_data.get("selected_indexes", "")
                for index_id in selected.split(","):
                    index_id = str(index_id).strip()
                    if not index_id:
                        continue
                    if index_id not in ok_indexes:
                        continue
                    index = get_object_or_404(Dump, index=index_id)
                    indexes.append(index)

                if indexes:
                    plugin = get_object_or_404(Plugin, name=form.cleaned_data.get("selected_plugin"))
                    bookmark = form.save(commit=False)
                    bookmark.user = request.user
                    bookmark.plugin = plugin
                    bookmark.save()
                    for index in indexes:
                        bookmark.indexes.add(index)
                    return HttpResponse(
                        "",
                        headers={
                            "HX-Trigger": '{"showMessage": {"title": "Bookmark saved!", "content": "Bookmark has been created", "type": "success"}, "closeModal": true}'
                        },
                    )
                else:
                    form.add_error(None, "No valid indexes selected")
            except IntegrityError:
                form.add_error("name", "Bookmark already exists")
        return render(request, "website/partial_bookmark_create.html", {"form": form})

    if getattr(request, "htmx", False):
        initial = request.GET.dict()
        if "selected_indexes" in initial:
            with contextlib.suppress(Exception):
                import json

                indexes = json.loads(initial["selected_indexes"])
                if isinstance(indexes, list):
                    initial["selected_indexes"] = ",".join(indexes)
        return render(
            request,
            "website/partial_bookmark_create.html",
            {"form": BookmarkForm(initial=initial)},
        )

    data = {
        "html_form": render_to_string(
            "website/partial_bookmark_create.html",
            {"form": BookmarkForm()},
            request=request,
        )
    }
    return JsonResponse(data)


@login_required
@require_http_methods(["GET"])
def edit_bookmark(request):
    """Edit bookmark information"""
    bookmark = get_object_or_404(Bookmark, pk=request.GET.get("pk"), user=request.user)
    context = {"form": EditBookmarkForm(instance=bookmark), "id": bookmark.pk}
    data = {"html_form": render_to_string("website/partial_bookmark_edit.html", context, request=request)}
    return JsonResponse(data)


@login_required
def bookmarks(request, indexes, plugin, query=None):
    """Open index but from a stored configuration of indexes and plugin"""
    from django.db.models import Exists, OuterRef

    has_auto_plugins = UserPlugin.objects.filter(
        plugin__operating_system__in=[OuterRef("operating_system"), "Other"],
        user=request.user,
        plugin__disabled=False,
        automatic=True,
    )

    context = {
        "dumps": get_objects_for_user(request.user, "website.can_see")
        .annotate(has_auto=Exists(has_auto_plugins))
        .values_list(*INDEX_VALUES_LIST)
        .order_by(*DUMP_ORDER_BY),
        "main_page": True,
        "selected_indexes": indexes,
        "selected_plugin": plugin,
        "selected_query": query,
        "cases": Case.objects.filter(Q(user=request.user) | Q(collaborators=request.user))
        .prefetch_related("evidences", "collaborators")
        .distinct(),
        "readonly": not is_not_readonly(request.user),
    }
    return TemplateResponse(request, "website/index.html", context)
