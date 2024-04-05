from typing import List

from django.shortcuts import get_object_or_404
from ninja import Query, Router
from ninja.security import django_auth

from orochi.api.filters import OperatingSytemFilters
from orochi.api.models import PluginInSchema, PluginOutSchema, SuccessResponse
from orochi.website.models import Plugin, UserPlugin

router = Router()


@router.get("/", response={200: List[PluginOutSchema]}, auth=django_auth)
def list_plugins(request, filters: Query[OperatingSytemFilters] = None):
    if filters and filters.operating_system:
        return Plugin.objects.filter(operating_system=filters.operating_system)
    return Plugin.objects.all()


@router.get("/{name}", response={200: PluginOutSchema}, auth=django_auth)
def get_plugin(request, name: str):
    return Plugin.objects.get(name=name)


@router.put("/{name}", response={200: PluginOutSchema}, auth=django_auth)
def update_plugin(request, name: str, data: PluginInSchema):
    plugin = get_object_or_404(Plugin, name=name)
    for attr, value in data.dict().items():
        setattr(plugin, attr, value)
    plugin.save()
    return plugin


@router.post(
    "/{name}/enable/{enable}",
    auth=django_auth,
    url_name="enable",
    response={200: SuccessResponse},
)
def enable_plugin(request, name: str, enable: bool):
    plugin = get_object_or_404(UserPlugin, plugin__name=name, user=request.user)
    plugin.automatic = enable
    plugin.save()
    return 200, {
        "message": f"Plugin {name} enabled" if enable else f"Plugin {name} disabled"
    }
