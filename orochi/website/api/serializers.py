from rest_framework import serializers
from orochi.website.models import Dump, Result, Plugin
from orochi.users.api.serializers import UserSerializer


class DumpSerializer(serializers.ModelSerializer):
    plugins = serializers.HyperlinkedRelatedField(
        many=True, view_name="api:plugin-detail", read_only=True
    )
    operating_system = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    author = UserSerializer(many=False)

    def get_operating_system(self, obj):
        return obj.get_operating_system_display()

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
            "plugins",
            "upload",
        ]

        extra_kwargs = {"url": {"view_name": "api:dump-detail", "lookup_field": "pk"}}


class PluginSerializer(serializers.ModelSerializer):
    operating_system = serializers.SerializerMethodField()

    def get_operating_system(self, obj):
        return obj.get_operating_system_display()

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
