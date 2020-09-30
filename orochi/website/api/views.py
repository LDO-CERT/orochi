from rest_framework.decorators import action
from rest_framework import permissions
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from orochi.users.api.serializers import UserSerializer
from orochi.website.api.serializers import (
    DumpSerializer,
    ResultSerializer,
    PluginSerializer,
)
from orochi.website.models import Dump, Result, Plugin


## Custom permissions
class NotUpdateAndIsAuthenticated(permissions.IsAuthenticated):
    def has_permission(self, request, view):
        return (
            view.action not in ["update", "partial_update"] or request.user.is_superuser
        )


# PLUGIN
class PluginViewSet(
    RetrieveModelMixin, ListModelMixin, UpdateModelMixin, GenericViewSet
):
    serializer_class = PluginSerializer
    queryset = Plugin.objects.all()
    lookup_field = "pk"
    permission_classes = [NotUpdateAndIsAuthenticated]

    def get_queryset(self, *args, **kwargs):
        return self.queryset.all()


# DUMP
class DumpViewSet(RetrieveModelMixin, ListModelMixin, UpdateModelMixin, GenericViewSet):
    serializer_class = DumpSerializer
    queryset = Dump.objects.all()
    lookup_field = "pk"

    def get_queryset(self, *args, **kwargs):
        return self.queryset.filter(author__pk=self.request.user.id)


# RESULT


class ResultViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    serializer_class = ResultSerializer
    queryset = Result.objects.all()
    lookup_field = "pk"

    def get_queryset(self, *args, **kwargs):
        return self.queryset.filter(dump__pk=self.kwargs["dump_pk"])
