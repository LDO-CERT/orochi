from django.contrib.sites.models import Site
from django.conf import settings
from rest_framework import serializers
from orochi.website.models import Dump, Result, Plugin, ExtractedDump, OPERATING_SYSTEM
from orochi.users.api.serializers import ShortUserSerializer
from rest_framework_nested.serializers import NestedHyperlinkedModelSerializer


class ImportLocalSerializer(serializers.Serializer):
    filepath = serializers.FilePathField(
        path="{}/uploads".format(settings.MEDIA_ROOT), recursive=True
    )
    name = serializers.CharField()
    operating_system = serializers.ChoiceField(choices=["Linux", "Mac", "Windows"])


class ExtractedDumpSerializer(serializers.ModelSerializer):
    path = serializers.SerializerMethodField()
    regipy_report = serializers.SerializerMethodField("regipy_report_url")

    def regipy_report_url(self, obj):
        return "{}regipy_report/".format(self.context["request"].build_absolute_uri())

    def get_path(self, obj):
        path = Site.objects.get_current().domain
        return "http://{}{}".format(
            path, obj.path.replace(settings.MEDIA_ROOT, settings.MEDIA_URL.rstrip("/"))
        )

    class Meta:
        model = ExtractedDump
        read_only_fields = ("sha256",)
        fields = ["path", "sha256", "clamav", "vt_report", "regipy_report"]


class ShortExtractedDumpSerializer(NestedHyperlinkedModelSerializer):
    parent_lookup_kwargs = {"dump_pk": "result__dump__pk", "result_pk": "result__pk"}
    path = serializers.SerializerMethodField()

    def get_path(self, obj):
        return obj.path.split("/")[-1]

    class Meta:
        model = ExtractedDump
        fields = ["path", "sha256", "url"]
        extra_kwargs = {
            "url": {"view_name": "api:dump-plugins-ext-detail", "lookup_field": "pk"}
        }


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
    extracted_dumps = serializers.SerializerMethodField("extracted_dumps_url")

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

    def extracted_dumps_url(self, obj):
        return "{}ext-dumps/".format(
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
            "extracted_dumps",
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
    missing_symbols = serializers.ReadOnlyField()
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
            "missing_symbols",
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
