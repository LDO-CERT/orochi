import os
import uuid

from rest_framework.decorators import action
from rest_framework import status, parsers
from rest_framework.mixins import (
    ListModelMixin,
    RetrieveModelMixin,
    UpdateModelMixin,
    CreateModelMixin,
    DestroyModelMixin,
)
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from orochi.users.api.serializers import UserSerializer
from orochi.website.api.permissions import (
    NotUpdateAndIsAuthenticated,
    AuthAndAuthorized,
    ParentAuthAndAuthorized,
)
from orochi.website.api.serializers import (
    DumpSerializer,
    ResultSerializer,
    PluginSerializer,
)
from orochi.website.models import Dump, Result, Plugin, UserPlugin
from orochi.website.views import index_f_and_f, plugin_f_and_f
from guardian.shortcuts import get_objects_for_user

from django.db import transaction
from django.conf import settings

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search


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
class DumpViewSet(
    RetrieveModelMixin,
    ListModelMixin,
    CreateModelMixin,
    GenericViewSet,
    DestroyModelMixin,
):
    serializer_class = DumpSerializer
    queryset = Dump.objects.all()
    lookup_field = "pk"
    permission_classes = [AuthAndAuthorized]
    parser_classes = [parsers.MultiPartParser]

    def get_queryset(self, *args, **kwargs):
        if self.request.user.is_superuser:
            return self.queryset
        return get_objects_for_user(self.request.user, "website.can_see")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            dump = Dump.objects.create(
                index=str(uuid.uuid1()),
                author=request.user,
                upload=request.FILES["upload"],
                name=serializer.validated_data["name"],
                operating_system=serializer.validated_data["operating_system"],
            )

            os.mkdir("{}/{}".format(settings.MEDIA_ROOT, dump.index))
            Result.objects.bulk_create(
                [
                    Result(
                        plugin=up.plugin,
                        dump=dump,
                        result=5 if not up.automatic else 0,
                    )
                    for up in UserPlugin.objects.filter(
                        plugin__operating_system__in=[dump.operating_system, "Other"],
                        user=request.user,
                        plugin__disabled=False,
                    )
                ]
            )
            transaction.on_commit(lambda: index_f_and_f(dump.pk, request.user.pk))
            return Response(
                status=status.HTTP_200_OK,
                data=DumpSerializer(dump, context={"request": request}).data,
            )
        return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


# RESULT
class ResultViewSet(RetrieveModelMixin, GenericViewSet):
    serializer_class = ResultSerializer
    queryset = Result.objects.all()
    permission_classes = [ParentAuthAndAuthorized]

    @action(detail=True, methods=["post"])
    def resubmit(self, request, pk=None, dump_pk=None, params=None):
        result = self.queryset.get(dump__pk=dump_pk, pk=pk)
        plugin = result.plugin
        dump = result.dump
        plugin_f_and_f(dump, plugin, params)
        return Response(
            status=status.HTTP_200_OK,
            data=ResultSerializer(result, context={"request": request}).data,
        )

    @action(detail=True, methods=["get"])
    def result(self, request, pk=None, dump_pk=None):
        result = self.queryset.get(dump__pk=dump_pk, pk=pk)
        index = f"{result.dump.index}_{result.plugin.name.lower()}"
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        s = Search(using=es_client, index=index).extra(size=10000)
        results = s.execute()
        info = [hit.to_dict() for hit in results]
        return Response(
            status=status.HTTP_200_OK,
            data=info,
        )

    def get_queryset(self, *args, **kwargs):
        return self.queryset.filter(dump__pk=self.kwargs["dump_pk"])
