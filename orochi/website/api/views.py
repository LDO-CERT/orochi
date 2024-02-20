import contextlib
import json
import os
import shutil
import uuid
from pathlib import Path

from django.conf import settings
from django.db import transaction
from elasticsearch import Elasticsearch, NotFoundError
from elasticsearch_dsl import Search
from guardian.shortcuts import get_objects_for_user
from rest_framework import parsers, status
from rest_framework.decorators import action
from rest_framework.mixins import (
    CreateModelMixin,
    DestroyModelMixin,
    ListModelMixin,
    RetrieveModelMixin,
    UpdateModelMixin,
)
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from orochi.website.api.permissions import (
    AuthAndAuthorized,
    NotUpdateAndIsAuthenticated,
    ParentAuthAndAuthorized,
)
from orochi.website.api.serializers import (
    DumpSerializer,
    ImportLocalSerializer,
    PluginSerializer,
    ResubmitSerializer,
    ResultSerializer,
    ShortDumpSerializer,
    ShortResultSerializer,
)
from orochi.website.models import (
    RESULT_STATUS_NOT_STARTED,
    RESULT_STATUS_RUNNING,
    Dump,
    Plugin,
    Result,
    UserPlugin,
)
from orochi.website.views import index_f_and_f, plugin_f_and_f


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
    queryset = Dump.objects.all()
    lookup_field = "pk"
    permission_classes = [AuthAndAuthorized]
    parser_classes = [parsers.MultiPartParser]

    def get_serializer_class(self):
        if self.action == "list":
            return ShortDumpSerializer
        if self.action == "import_local":
            return ImportLocalSerializer
        return DumpSerializer

    def get_queryset(self, *args, **kwargs):
        if self.request.user.is_superuser:
            return self.queryset
        return get_objects_for_user(self.request.user, "website.can_see")

    def destroy(self, request, pk=None):
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        dump = self.queryset.get(pk=pk)
        indexes = f"{dump.index}_*"
        dump.delete()
        es_client.indices.delete(index=f"{indexes}", ignore=[400, 404])
        with contextlib.suppress(FileNotFoundError):
            shutil.rmtree(f"{settings.MEDIA_ROOT}/{dump.index}")
        return Response(status=status.HTTP_204_NO_CONTENT)

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

            os.mkdir(f"{settings.MEDIA_ROOT}/{dump.index}")
            Result.objects.bulk_create(
                [
                    Result(
                        plugin=up.plugin,
                        dump=dump,
                        result=(
                            RESULT_STATUS_RUNNING
                            if up.automatic
                            else RESULT_STATUS_NOT_STARTED
                        ),
                    )
                    for up in UserPlugin.objects.filter(
                        plugin__operating_system__in=[dump.operating_system, "Other"],
                        user=request.user,
                        plugin__disabled=False,
                    )
                ]
            )
            transaction.on_commit(
                lambda: index_f_and_f(
                    dump.pk,
                    request.user.pk,
                    password=serializer.validated_data.get("password"),
                    restart=None,
                )
            )
            return Response(
                status=status.HTTP_200_OK,
                data=ShortDumpSerializer(dump, context={"request": request}).data,
            )
        return Response(
            {"Error": "Error in dump creation"},
            status=status.HTTP_400_BAD_REQUEST,
            data=serializer.errors,
        )

    @action(detail=False, methods=["post"], serializer_class=ImportLocalSerializer)
    def import_local(self, request):
        dump_index = str(uuid.uuid1())
        os.mkdir(f"{settings.MEDIA_ROOT}/{dump_index}")

        local_path = Path(request.data["filepath"])
        filename = local_path.name

        if not local_path.exists():
            return Response(
                {"Error": "Filepath does not exists!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        shutil.copy(
            str(local_path),
            f"{settings.MEDIA_ROOT}/{dump_index}",
        )

        operating_system = request.data["operating_system"]
        operating_system = operating_system.capitalize()
        if operating_system not in ["Linux", "Windows", "Mac"]:
            return Response(
                {"Error": "Option selected for OS is not valid [Linux, Windows, Mac]."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        name = request.data["name"]

        with transaction.atomic():
            dump = Dump(
                author=request.user,
                index=dump_index,
                name=name,
                operating_system=operating_system,
            )
            dump.upload.name = f"{settings.MEDIA_URL}{dump_index}/{filename}"
            dump.save()
            Result.objects.bulk_create(
                [
                    Result(
                        plugin=up.plugin,
                        dump=dump,
                        result=(
                            RESULT_STATUS_RUNNING
                            if up.automatic
                            else RESULT_STATUS_NOT_STARTED
                        ),
                    )
                    for up in UserPlugin.objects.filter(
                        plugin__operating_system__in=[
                            operating_system,
                            "Other",
                        ],
                        user=request.user,
                        plugin__disabled=False,
                    )
                ]
            )
            transaction.on_commit(
                lambda: index_f_and_f(
                    dump.pk,
                    request.user.pk,
                    password=request.data.get("password"),
                    restart=None,
                    move=False,
                )
            )

        return Response(
            status=status.HTTP_200_OK,
            data=ShortDumpSerializer(dump, context={"request": request}).data,
        )


# RESULT
class ResultViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    queryset = Result.objects.all()
    permission_classes = [ParentAuthAndAuthorized]
    lookup_field = "pk"

    def get_serializer_class(self):
        return ShortResultSerializer if self.action == "list" else ResultSerializer

    @action(detail=True, methods=["post"], serializer_class=ResubmitSerializer)
    def resubmit(self, request, pk=None, dump_pk=None):
        result = self.queryset.get(dump__pk=dump_pk, pk=pk)
        result.result = RESULT_STATUS_RUNNING
        request.description = None
        try:
            result.parameter = (
                json.loads(request.data["parameter"])
                if request.data.get("parameter", None)
                else None
            )
        except Exception:
            result.parameter = None
        result.save()
        plugin = result.plugin
        dump = result.dump

        # REMOVE OLD DATA
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        es_client.indices.delete(
            index=f"{dump.index}_{plugin.name.lower()}", ignore=[400, 404]
        )

        transaction.on_commit(
            lambda: plugin_f_and_f(dump, plugin, result.parameter, None)
        )

        return Response(
            status=status.HTTP_200_OK,
            data=ResultSerializer(result, context={"request": request}).data,
        )

    @action(detail=True, methods=["get"])
    def result(self, request, pk=None, dump_pk=None):
        result = self.queryset.get(dump__pk=dump_pk, pk=pk)
        index = f"{result.dump.index}_{result.plugin.name.lower()}"
        es_client = Elasticsearch([settings.ELASTICSEARCH_URL])
        try:
            s = Search(using=es_client, index=index).extra(size=10000)
            results = s.execute()
            info = [hit.to_dict() for hit in results]
        except NotFoundError:
            info = []
        return Response(
            status=status.HTTP_200_OK,
            data=info,
        )

    def get_queryset(self, *args, **kwargs):
        if self.kwargs.get("dump_pk", None):
            return self.queryset.filter(dump__pk=self.kwargs["dump_pk"])
        return self.queryset
