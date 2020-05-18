from django.db import models
from picklefield.fields import PickledObjectField


class DaskTask(models.Model):
    task_key = models.CharField(primary_key=True, max_length=512)
    status = models.CharField(max_length=32, null=True)
    result = PickledObjectField(null=True)

    def __str__(self):
        return self.task_key

    def get_status(self):
        from daskmanager.daskmanager import DaskManager

        if self.status is not None:
            return self.status

        cluster_status = DaskManager().get_future_status(self.task_key)
        if cluster_status == "finished":
            return "saving"
        return cluster_status
