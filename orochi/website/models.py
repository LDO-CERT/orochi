import contextlib
import random
import shutil
from pathlib import Path

from colorfield.fields import ColorField
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.db import models
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone

from orochi.website.defaults import (
    COLOR_PALETTE,
    RESULT,
    SERVICES,
    STATUS,
    IconEnum,
    OSEnum,
)


class Service(models.Model):
    name = models.PositiveIntegerField(choices=SERVICES, unique=True)
    url = models.CharField(max_length=250)
    key = models.CharField(max_length=250)
    proxy = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.get_name_display()}"


from orochi.website.roles import ROLE_ANALYST, ROLE_CHOICES


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
    min_role = models.CharField(
        max_length=20, choices=ROLE_CHOICES, default=ROLE_ANALYST
    )

    def __str__(self):
        return self.name


class UserPlugin(models.Model):
    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="plugins"
    )
    automatic = models.BooleanField(default=False)
    can_execute = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text="Override execution permission (None = follow role, True = allow, False = deny)",
    )

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


class Case(models.Model):
    STATUS_OPEN = "Open"
    STATUS_IN_PROGRESS = "In Progress"
    STATUS_CLOSED = "Closed"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_CLOSED, "Closed"),
    )

    name = models.CharField(max_length=250)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="cases"
    )
    collaborators = models.ManyToManyField(
        settings.AUTH_USER_MODEL, related_name="collaborating_cases", blank=True
    )
    folder = models.ForeignKey(
        Folder, on_delete=models.SET_NULL, blank=True, null=True, related_name="cases"
    )
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=50, choices=STATUS_CHOICES, default=STATUS_OPEN
    )
    is_ctf = models.BooleanField(default=False)
    search_vector = models.GeneratedField(
        expression=SearchVector("name", config="english")
        + SearchVector("description", config="english"),
        output_field=SearchVectorField(),
        db_persist=True,
    )

    class Meta:
        unique_together = ["name", "user"]
        indexes = [GinIndex(fields=["search_vector"], name="case_gin_idx")]

    def __str__(self):
        return self.name


class Evidence(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="evidences")
    dump = models.ForeignKey(
        "Dump",
        on_delete=models.CASCADE,
        related_name="evidences",
        blank=True,
        null=True,
    )
    plugin = models.CharField(max_length=250, blank=True, null=True)
    result_row = models.JSONField(blank=True, null=True)
    extracted_file = models.CharField(max_length=250, blank=True, null=True)

    name = models.CharField(max_length=250, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name or f"Evidence {self.pk}"


class Finding(models.Model):
    SEVERITY_CHOICES = (
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    )
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="findings")
    evidence = models.ForeignKey(
        Evidence,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    severity = models.CharField(
        max_length=20, choices=SEVERITY_CHOICES, default="Medium"
    )
    tags = ArrayField(
        models.CharField(max_length=50), blank=True, null=True, default=list
    )
    note = models.TextField(blank=True, null=True)
    mitre_attack_technique = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        try:
            case_name = self.case.name if self.case else "Unknown"
        except Exception:
            case_name = "Unknown"
        return f"Finding {self.pk} for Case {case_name}"


class TimelineEvent(models.Model):
    case = models.ForeignKey(
        Case, on_delete=models.CASCADE, related_name="timeline_events"
    )
    timestamp = models.DateTimeField()
    event_type = models.CharField(max_length=50)
    description = models.TextField()
    source_evidence = models.ForeignKey(
        Evidence, on_delete=models.SET_NULL, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.timestamp} - {self.event_type}"


class ReportTemplate(models.Model):
    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    template = models.FileField(upload_to="report_templates/")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


@receiver(post_save, sender=Finding)
def create_finding_timeline_event(sender, instance, created, **kwargs):
    if created:
        TimelineEvent.objects.create(
            case=instance.case,
            timestamp=timezone.now(),
            event_type="Finding Created",
            description=f"A new {instance.severity} finding was added.",
            source_evidence=instance.evidence,
        )


@receiver(post_save, sender=Evidence)
def create_evidence_timeline_event(sender, instance, created, **kwargs):
    if created and instance.case:
        TimelineEvent.objects.create(
            case=instance.case,
            timestamp=timezone.now(),
            event_type="Evidence Added",
            description=f"Evidence '{instance.name}' was added to the case.",
            source_evidence=instance,
        )


@receiver(pre_delete, sender=Evidence)
def delete_evidence_timeline_event(sender, instance, **kwargs):
    TimelineEvent.objects.filter(
        source_evidence=instance, event_type="Evidence Added"
    ).delete()


def random_color():
    return random.choice(COLOR_PALETTE)[0]


class Host(models.Model):
    name = models.CharField(max_length=250)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Hosts"


class Dump(models.Model):
    host = models.ForeignKey(
        Host, on_delete=models.SET_NULL, null=True, blank=True, related_name="dumps"
    )
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
    color = ColorField(default=random_color, samples=COLOR_PALETTE, format="hex")
    status = models.PositiveSmallIntegerField(choices=STATUS, default=1)
    plugins = models.ManyToManyField(Plugin, through="Result")
    risk_score = models.IntegerField(default=0)
    md5 = models.CharField(max_length=32, blank=True, null=True)
    sha256 = models.CharField(max_length=64, blank=True, null=True)
    size = models.BigIntegerField(null=True)
    suggested_symbols_path = ArrayField(
        models.CharField(max_length=1000, blank=True, null=True), blank=True, null=True
    )
    search_vector = models.GeneratedField(
        expression=SearchVector("name", config="english")
        + SearchVector("comment", config="english")
        + SearchVector("description", config="english")
        + SearchVector("banner", config="english")
        + SearchVector("md5", config="english")
        + SearchVector("sha256", config="english"),
        output_field=SearchVectorField(),
        db_persist=True,
    )

    def __str__(self):
        return self.name

    class Meta:
        permissions = (("can_see", "Can See"),)
        verbose_name_plural = "Dumps"
        unique_together = ["name", "author"]
        indexes = [GinIndex(fields=["search_vector"], name="dump_gin_idx")]


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
        try:
            dump_name = self.dump.name if self.dump_id else "Unknown"
        except Dump.DoesNotExist:
            dump_name = "Unknown"
        try:
            plugin_name = self.plugin.name if self.plugin_id else "Unknown"
        except Exception:
            plugin_name = "Unknown"
        return f"{dump_name} [{plugin_name}]"

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

    class Meta:
        indexes = [GinIndex(fields=["search_vector"], name="value_gin_idx")]


class ValueAnnotation(models.Model):
    STATUS_CHOICES = (
        ("comment", "Comment"),
        ("false_positive", "False Positive"),
        ("suspicious", "Suspicious"),
        ("verified_threat", "Verified Threat"),
        ("resolved", "Resolved"),
    )
    value = models.ForeignKey(
        Value, on_delete=models.CASCADE, related_name="annotations"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="value_annotations",
    )
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="comment")
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["value", "created_at"]),
        ]

    def __str__(self):
        return f"Annotation #{self.pk} on Value {self.value_id} by {self.user}"


class DumpSecret(models.Model):
    CATEGORY_CHOICES = (
        ("aws", "AWS Credentials"),
        ("private_key", "Private Key (PEM/SSH)"),
        ("jwt", "JWT Token"),
        ("api_key", "API Key / Token"),
        ("db_uri", "Database Connection URI"),
        ("password", "Password / Generic Credential"),
    )
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE, related_name="secrets")
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    rule_name = models.CharField(max_length=150)
    matched_data = models.TextField()
    masked_data = models.TextField()
    offset = models.CharField(max_length=50, blank=True, null=True)
    pid = models.IntegerField(blank=True, null=True)
    process_name = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["dump", "category"]),
        ]

    def __str__(self):
        return f"Secret [{self.category}] in {self.dump.name} ({self.rule_name})"


class TriageFinding(models.Model):
    SEVERITY_CHOICES = (
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Info", "Info"),
    )
    dump = models.ForeignKey(
        Dump, on_delete=models.CASCADE, related_name="triage_findings"
    )
    rule_id = models.CharField(max_length=100)
    rule_name = models.CharField(max_length=255)
    category = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    score = models.IntegerField(default=10)
    mitre_technique = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField()
    evidence_snippet = models.TextField(blank=True, null=True)
    entity = models.CharField(max_length=255, blank=True, null=True)
    raw_data = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-score", "-created_at")
        indexes = [
            models.Index(fields=["dump", "severity"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.rule_name} on {self.dump.name}"


class DumpNarrative(models.Model):
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE, related_name="narratives")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="dump_narratives",
    )
    model_name = models.CharField(max_length=100, default="llama3.2:1b")
    raw_narrative = models.TextField()
    formatted_narrative = models.TextField()
    evidence_hash = models.CharField(max_length=64, blank=True, null=True)
    citations = models.JSONField(default=list, blank=True)
    hallucination_check = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["dump", "-created_at"]),
        ]

    def __str__(self):
        return f"AI Narrative for {self.dump.name} ({self.model_name}) at {self.created_at}"


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


@receiver(pre_delete, sender=Dump)
def delete_dump_related(sender, instance, **kwargs):
    Bookmark.objects.filter(indexes=instance).delete()
    instance.result_set.all().delete()
    dump_dir = Path(settings.MEDIA_ROOT) / instance.index
    if dump_dir.exists():
        shutil.rmtree(dump_dir, ignore_errors=True)
    if instance.upload:
        with contextlib.suppress(Exception):
            instance.upload.delete(save=False)


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


class TaskLog(models.Model):
    task_id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=50, default="Submitted")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    error = models.TextField(blank=True, null=True)
    result = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.name} ({self.task_id})"
