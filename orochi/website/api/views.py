from rest_framework.decorators import action
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


class DumpViewSet(RetrieveModelMixin, ListModelMixin, UpdateModelMixin, GenericViewSet):
    serializer_class = DumpSerializer
    queryset = Dump.objects.all()
    lookup_field = "pk"

    def get_queryset(self, *args, **kwargs):
        return self.queryset.filter(author__pk=self.request.user.id)


class PluginViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    serializer_class = PluginSerializer
    queryset = Plugin.objects.all()
    lookup_field = "pk"

    def get_queryset(self, *args, **kwargs):
        return self.queryset.all()


class ResultViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    serializer_class = ResultSerializer
    queryset = Result.objects.all()
    lookup_field = "pk"

    def get_queryset(self, *args, **kwargs):
        return self.queryset.filter(dump__pk=self.kwargs["dump_pk"])
