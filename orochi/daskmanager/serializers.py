from rest_framework import serializers

from .models import DaskTask


class DaskTaskSerializer(serializers.HyperlinkedModelSerializer):
    status = serializers.CharField(source="get_status", read_only=True)

    class Meta:
        model = DaskTask
        fields = ("url", "task_key", "status", "result")
