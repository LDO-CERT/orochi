import os
import uuid

from rest_framework.decorators import action
from rest_framework import status, permissions, parsers
from rest_framework.mixins import (
    ListModelMixin,
    RetrieveModelMixin,
    UpdateModelMixin,
    CreateModelMixin,
)
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from orochi.users.api.serializers import UserSerializer
from orochi.website.api.serializers import (
    DumpSerializer,
    ResultSerializer,
    PluginSerializer,
)
from orochi.website.models import Dump, Result, Plugin, UserPlugin
from orochi.website.views import index_f_and_f
from guardian.shortcuts import get_objects_for_user

from django.db import transaction
from django.db.models import Q
from django.conf import settings

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
class DumpViewSet(RetrieveModelMixin, ListModelMixin, CreateModelMixin, GenericViewSet):
    serializer_class = DumpSerializer
    queryset = Dump.objects.all()
    lookup_field = "pk"
    permission_classes = [permissions.IsAuthenticated]
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
            )
            dump.save()

            os.mkdir("{}/{}".format(settings.MEDIA_ROOT, dump.index))
            Result.objects.bulk_create(
                [
                    Result(
                        plugin=up.plugin,
                        dump=dump,
                        result=5 if not up.automatic else 0,
                    )
                    for up in UserPlugin.objects.filter(
                        Q(plugin__operating_system=dump.operating_system)
                        | Q(plugin__operating_system="Other"),
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
class ResultViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    serializer_class = ResultSerializer
    queryset = Result.objects.all()
    lookup_field = "pk"

    def get_queryset(self, *args, **kwargs):
        return self.queryset.filter(dump__pk=self.kwargs["dump_pk"])
