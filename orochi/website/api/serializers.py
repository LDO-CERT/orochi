from rest_framework import serializers
from orochi.website.models import Dump, Result, Plugin, OPERATING_SYSTEM
from orochi.users.api.serializers import UserSerializer


class PluginSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plugin
        fields = [
            "name",
            "operating_system",
            "disabled",
            "local_dump",
            "vt_check",
            "clamav_check",
            "regipy_check",
            "url",
        ]

        extra_kwargs = {"url": {"view_name": "api:plugin-detail", "lookup_field": "pk"}}


class DumpSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    author = UserSerializer(many=False, read_only=True)
    index = serializers.ReadOnlyField()
    upload = serializers.FileField(allow_empty_file=False)

    def get_status(self, obj):
        return obj.get_status_display()

    class Meta:
        model = Dump
        fields = [
            "operating_system",
            "name",
            "index",
            "author",
            "created_at",
            "status",
            "upload",
            "url",
        ]

        extra_kwargs = {"url": {"view_name": "api:dump-detail", "lookup_field": "pk"}}


class ResultSerializer(serializers.ModelSerializer):
    plugin = PluginSerializer(many=False, read_only=True)
    result = serializers.SerializerMethodField()

    def get_result(self, obj):
        return obj.get_result_display()

    class Meta:
        model = Result
        fields = [
            "plugin",
            "result",
            "description",
            "parameter",
            "updated_at",
        ]

        extra_kwargs = {"url": {"view_name": "api:result-detail", "lookup_field": "pk"}}
