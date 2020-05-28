# DJANGO
# ------------------------------------------------------------------------------
import uuid
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, Http404
from django.template.loader import render_to_string
from django.conf import settings

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search

from django.contrib.auth.decorators import login_required
from guardian.shortcuts import get_objects_for_user

from .models import Analysis
from .forms import AnalysisForm


@login_required
def index(request):
    context = {
        "list_indices": get_objects_for_user(
            request.user, "website.can_see"
        ).values_list("index", "name", "color"),
    }
    return render(request, "website/index.html", context)


@login_required
def plugins(request):
    if request.is_ajax():
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        indexes = request.GET.getlist("indexes[]")

        doc_types = []

        # CHECK IF I CAN SEE INDEXES
        analyses = Analysis.objects.filter(index__in=indexes)
        for analysis in analyses:
            if analysis not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404

        # LOOK FOR INDEXES ON ES AND GRAB PLUGINS
        for index in indexes:
            if index == None or not index:
                continue
            for x in es_client.indices.get_alias("*"):
                if x.startswith(index):
                    plugin = "_".join(x.split("_")[1:])
                    if plugin not in doc_types:
                        doc_types.append(plugin)
        return JsonResponse(sorted(doc_types), safe=False)
    else:
        raise Http404("404")


@login_required
def analysis(request):
    if request.is_ajax():
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])

        # GET DATA
        indexes = request.GET.getlist("indexes[]")
        plugin = request.GET.get("plugin")

        # GET DICT OF COLOR AND CHECK PERMISSIONS
        analyses = Analysis.objects.filter(index__in=indexes)
        colors = {}
        for analysis in analyses:
            if analysis not in get_objects_for_user(request.user, "website.can_see"):
                raise Http404
            colors[analysis.index] = analysis.color

        # SEARCH FOR ITEMS AND KEEP INDEX
        for index in indexes:
            if (
                f"{index}_{plugin}" not in es_client.indices.get_alias("*")
                or index == "None"
                or not index
            ):
                indexes.remove(index)
        indexes_list = ",".join([f"{index}_{plugin}" for index in indexes])
        s = Search(using=es_client, index=indexes_list).extra(size=10000)
        result = s.execute()
        info = [(hit.to_dict(), hit.meta.index.split("_")[0]) for hit in result]

        data = []
        for item, item_index in info:
            item.update({"color": colors[item_index]})
            data.append(item)

        response = {"data": data}
        return JsonResponse(response, safe=False)
    else:
        raise Http404("404")


@login_required
def create(request):
    data = dict()

    if request.method == "POST":
        form = AnalysisForm(data=request.POST)
        if form.is_valid():
            index = form.save(commit=False)
            index.author = request.user
            index.upload = form.cleaned_data["upload"]
            index.index = str(uuid.uuid1())
            index.save()
            form.delete_temporary_files()
            data["form_is_valid"] = True

            # Return the new list of available indexes
            data["new_indices"] = [
                x
                for x in get_objects_for_user(
                    request.user, "website.can_see"
                ).values_list("index", "color", "name")
            ]
        else:
            data["form_is_valid"] = False
    else:
        form = AnalysisForm()

    context = {"form": form}
    data["html_form"] = render_to_string(
        "website/partial_create.html", context, request=request,
    )
    return JsonResponse(data)
