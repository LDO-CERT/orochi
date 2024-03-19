from django.conf import settings
from rest_framework import serializers
from rest_framework_nested.serializers import NestedHyperlinkedModelSerializer

from orochi.users.api.serializers import ShortUserSerializer
from orochi.website.models import Dump, Plugin, Result


class ImportLocalSerializer(serializers.Serializer):
    filepath = serializers.FilePathField(
        path=settings.LOCAL_UPLOAD_PATH, recursive=True
    )
    name = serializers.CharField()
    operating_system = serializers.ChoiceField(choices=["Linux", "Mac", "Windows"])
    password = serializers.CharField(required=False)


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


class ShortPluginSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plugin
        fields = [
            "name",
            "operating_system",
            "disabled",
            "pk",
            "url",
        ]

        extra_kwargs = {"url": {"view_name": "api:plugin-detail", "lookup_field": "pk"}}


class ResultSerializer(serializers.ModelSerializer):
    plugin = ShortPluginSerializer(many=False, read_only=True)
    status = serializers.SerializerMethodField()
    result = serializers.SerializerMethodField("result_url")
    resubmit = serializers.SerializerMethodField("resubmit_url")

    def get_status(self, obj):
        return obj.get_result_display()

    def result_url(self, obj):
        return "{}result/".format(
            self.context["request"]
            .build_absolute_uri()
            .replace("resubmit/", "")
            .replace("result/", "")
        )

    def resubmit_url(self, obj):
        return "{}resubmit/".format(
            self.context["request"]
            .build_absolute_uri()
            .replace("resubmit/", "")
            .replace("result/", "")
        )

    class Meta:
        model = Result
        read_only_fields = ("description",)
        fields = [
            "plugin",
            "status",
            "description",
            "parameter",
            "updated_at",
            "result",
            "resubmit",
        ]


class ResubmitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Result
        fields = ["parameter"]


class ShortResultSerializer(NestedHyperlinkedModelSerializer):
    plugin = serializers.StringRelatedField(many=False)
    result = serializers.SerializerMethodField()

    parent_lookup_kwargs = {"dump_pk": "dump__pk"}

    def get_result(self, obj):
        return obj.get_result_display()

    class Meta:
        model = Result
        fields = ["plugin", "result", "pk", "url"]
        extra_kwargs = {"url": {"view_name": "api:dump-plugins-detail"}}


class DumpSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    author = ShortUserSerializer(many=False, read_only=True)
    index = serializers.ReadOnlyField()
    banner = serializers.ReadOnlyField()
    upload = serializers.FileField(allow_empty_file=False, write_only=True)
    results = serializers.SerializerMethodField("results_url")

    def get_status(self, obj):
        return obj.get_status_display()

    def results_url(self, obj):
        return "{}results/".format(self.context["request"].build_absolute_uri())

    class Meta:
        model = Dump
        fields = [
            "operating_system",
            "banner",
            "name",
            "index",
            "author",
            "created_at",
            "status",
            "upload",
            "results",
        ]

        extra_kwargs = {
            "upload": {"write_only": True},
        }


class ShortDumpSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    author = ShortUserSerializer(many=False, read_only=True)

    def get_status(self, obj):
        return obj.get_status_display()

    class Meta:
        model = Dump
        fields = [
            "index",
            "operating_system",
            "author",
            "name",
            "created_at",
            "status",
            "pk",
            "url",
        ]

        extra_kwargs = {
            "url": {"view_name": "api:dump-detail", "lookup_field": "pk"},
        }
