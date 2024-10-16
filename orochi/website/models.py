from colorfield.fields import ColorField
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.db import models

from orochi.website.defaults import RESULT, SERVICES, STATUS, IconEnum, OSEnum


class Service(models.Model):
    name = models.PositiveIntegerField(choices=SERVICES, unique=True)
    url = models.CharField(max_length=250)
    key = models.CharField(max_length=250)
    proxy = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.get_name_display()}"


class Plugin(models.Model):
    name = models.CharField(max_length=250, unique=True)
    operating_system = models.CharField(
        choices=OSEnum.choices, default=OSEnum.LINUX, max_length=10
    )
    disabled = models.BooleanField(default=False)
    comment = models.TextField(blank=True, null=True)
    local_dump = models.BooleanField(default=False)
    vt_check = models.BooleanField(default=False)
    clamav_check = models.BooleanField(default=False)
    regipy_check = models.BooleanField(default=False)
    maxmind_check = models.BooleanField(default=False)
    local = models.BooleanField(default=False)
    local_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return self.name


class UserPlugin(models.Model):
    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="plugins"
    )
    automatic = models.BooleanField(default=False)

    class Meta:
        ordering = ("plugin__name",)

    def __str__(self):
        return self.plugin.name


class Folder(models.Model):
    name = models.CharField(max_length=250)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="folders"
    )

    class Meta:
        unique_together = ["name", "user"]

    def __str__(self):
        return self.name


class Dump(models.Model):
    operating_system = models.CharField(
        choices=OSEnum.choices, default=OSEnum.LINUX, max_length=10
    )
    banner = models.CharField(max_length=500, blank=True, null=True)
    upload = models.FileField(upload_to="uploads")
    regipy_plugins = ArrayField(
        models.JSONField(blank=True, null=True), blank=True, null=True, default=list
    )
    folder = models.ForeignKey(Folder, on_delete=models.SET_NULL, blank=True, null=True)
    comment = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=250)
    index = models.CharField(max_length=250, unique=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    color = ColorField(default="#FF0000")
    status = models.PositiveSmallIntegerField(choices=STATUS, default=1)
    plugins = models.ManyToManyField(Plugin, through="Result")
    md5 = models.CharField(max_length=32, blank=True, null=True)
    sha256 = models.CharField(max_length=64, blank=True, null=True)
    size = models.BigIntegerField(null=True)
    suggested_symbols_path = ArrayField(
        models.CharField(max_length=1000, blank=True, null=True), blank=True, null=True
    )

    def __str__(self):
        return self.name

    class Meta:
        permissions = (("can_see", "Can See"),)
        verbose_name_plural = "Dumps"
        unique_together = ["name", "author"]


class ResultManager(models.Manager):
    def get_by_natural_key(self, dump_name, plugin_name):
        dump = Dump.objects.get(name=dump_name)
        plugin = Plugin.objects.get(name=plugin_name)
        return self.get(dump=dump, plugin=plugin)


class Result(models.Model):
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE)
    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    result = models.PositiveSmallIntegerField(choices=RESULT, default=0)
    description = models.TextField(blank=True, null=True)
    parameter = models.JSONField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ResultManager()

    class Meta:
        unique_together = (
            "dump",
            "plugin",
        )

    def __str__(self):
        return f"{self.dump.name} [{self.plugin.name}]"

    def natural_key(self):
        return (self.dump.name, self.plugin.name)


class Value(models.Model):
    result = models.ForeignKey(Result, on_delete=models.CASCADE)
    value = models.JSONField(blank=True, null=True)
    search_vector = models.GeneratedField(
        expression=SearchVector("value", config="english"),
        output_field=SearchVectorField(),
        db_persist=True,
    )

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        Value.objects.annotate(search_vector_name=SearchVector("value")).filter(
            id=self.id
        ).update(search_vector=models.F("search_vector_value"))

    class Meta:
        indexes = [GinIndex(fields=["search_vector"], name="value_gin_idx")]


class Bookmark(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="bookmarks"
    )
    indexes = models.ManyToManyField(Dump)
    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    name = models.CharField(max_length=250)
    icon = models.CharField(
        choices=IconEnum.choices, default=IconEnum.SS_ORI, max_length=50
    )
    star = models.BooleanField(default=False)
    query = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        unique_together = ["name", "user"]

    @property
    def indexes_list(self):
        return ",".join([p.index for p in self.indexes.all()])

    @property
    def indexes_names_list(self):
        return ", ".join([p.name for p in self.indexes.all()])

    def __str__(self):
        return f"{self.name}"


def user_directory_path(instance, filename):
    return "user_{0}/{1}"


class CustomRule(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="rules"
    )
    name = models.CharField(max_length=250)
    public = models.BooleanField(default=False)
    path = models.CharField(max_length=255)
    default = models.BooleanField(default=False)
