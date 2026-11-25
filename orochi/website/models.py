import contextlib
import hashlib
import hmac
import logging
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
    DUMP_STATUS_COMPLETED,
    DUMP_STATUS_DELETED,
    RESULT,
    SERVICES,
    STATUS,
    IconEnum,
    OSEnum,
    SymbolStatus,
)
from orochi.website.roles import ROLE_ANALYST, ROLE_CHOICES

logger = logging.getLogger(__name__)


class Service(models.Model):
    """External service configuration (VirusTotal, MISP, Ollama, SIEM, TheHive, CAPE, notifications...).

    The ``key`` is stored encrypted with the Django secret key (``enc:`` prefix).
    """

    name = models.PositiveIntegerField(choices=SERVICES, unique=True)
    url = models.CharField(max_length=250)
    key = models.CharField(max_length=500)
    proxy = models.JSONField(null=True, blank=True)
    verify_ssl = models.BooleanField(
        default=True,
        help_text="Verify the TLS certificate of the service. Disable only for self-hosted instances "
        "with self-signed certificates.",
    )

    def __str__(self):
        return f"{self.get_name_display()}"

    @property
    def decrypted_key(self) -> str:
        """Returns the decrypted plaintext key if encrypted, or the raw key."""
        if not self.key:
            return ""
        if self.key.startswith("enc:"):
            try:
                from orochi.website.crypto import decrypt_secret

                return decrypt_secret(self.key[4:])
            except Exception:
                # Never hand the ciphertext out as if it were the credential.
                logger.error(
                    "Cannot decrypt key of service %s: SECRET_KEY changed? "
                    "Add the old key to DJANGO_SECRET_KEY_FALLBACKS or re-enter the key.",
                    self.get_name_display(),
                )
                return ""
        return self.key

    def set_encrypted_key(self, raw_key: str):
        """Encrypts and stores a raw key with AES-GCM."""
        if not raw_key:
            self.key = ""
        else:
            from orochi.website.crypto import encrypt_secret

            self.key = f"enc:{encrypt_secret(raw_key)}"

    def save(self, *args, **kwargs):
        """Encrypt a plaintext ``key`` before saving."""
        if self.key and not self.key.startswith("enc:"):
            self.set_encrypted_key(self.key)
        super().save(*args, **kwargs)


class Plugin(models.Model):
    """Volatility plugin known to Orochi, with OS, enable state and execution options."""

    name = models.CharField(max_length=250, unique=True)
    operating_system = models.CharField(choices=OSEnum.choices, default=OSEnum.LINUX, max_length=10)
    disabled = models.BooleanField(default=False)
    comment = models.TextField(blank=True, null=True)
    local_dump = models.BooleanField(default=False)
    vt_check = models.BooleanField(default=False)
    clamav_check = models.BooleanField(default=False)
    regipy_check = models.BooleanField(default=False)
    maxmind_check = models.BooleanField(default=False)
    local = models.BooleanField(default=False)
    local_date = models.DateField(blank=True, null=True)
    min_role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_ANALYST)

    def __str__(self):
        return self.name


class UserPlugin(models.Model):
    """Per-user plugin preference: whether the plugin runs automatically on new dumps."""

    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="plugins")
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
    """User folder grouping dumps and cases."""

    name = models.CharField(max_length=250)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="folders")

    class Meta:
        unique_together = ["name", "user"]

    def __str__(self):
        return self.name


class Case(models.Model):
    """Investigation case: evidence, findings, timeline and collaborators.

    With ``is_ctf`` the case is also a CTF challenge (questions, discovery objectives, scoring settings);
    ``ctf_template`` marks a participant's private copy of a published challenge.
    """

    STATUS_OPEN = "Open"
    STATUS_IN_PROGRESS = "In Progress"
    STATUS_CLOSED = "Closed"
    STATUS_CHOICES = (
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_CLOSED, "Closed"),
    )
    CTF_MODE_PRACTICE = "practice"
    CTF_MODE_COMPETITION = "competition"
    CTF_MODE_CHOICES = (
        (CTF_MODE_PRACTICE, "Practice (Live Feedback)"),
        (CTF_MODE_COMPETITION, "Competition (Blind)"),
    )

    name = models.CharField(max_length=250)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="cases")
    collaborators = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name="collaborating_cases", blank=True)
    folder = models.ForeignKey(Folder, on_delete=models.SET_NULL, blank=True, null=True, related_name="cases")
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default=STATUS_OPEN)
    is_ctf = models.BooleanField(default=False)
    ctf_mode = models.CharField(max_length=20, choices=CTF_MODE_CHOICES, default=CTF_MODE_PRACTICE)
    ctf_fp_penalty = models.PositiveIntegerField(default=15)
    ctf_first_blood_bonus = models.PositiveIntegerField(default=0)
    ctf_dynamic_scoring = models.BooleanField(default=False)
    # Published challenge: any user can start a private copy (ctf_template points back here)
    ctf_published = models.BooleanField(default=False)
    ctf_template = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ctf_participant_cases",
    )
    ctf_dumps = models.ManyToManyField("Dump", blank=True, related_name="ctf_challenges")
    search_vector = models.GeneratedField(
        expression=SearchVector("name", config="english") + SearchVector("description", config="english"),
        output_field=SearchVectorField(),
        db_persist=True,
    )

    class Meta:
        unique_together = ["name", "user"]
        indexes = [GinIndex(fields=["search_vector"], name="case_gin_idx")]

    def __str__(self):
        return self.name


class Evidence(models.Model):
    """Artifact saved to a case: a plugin row (``result_row``) and/or an extracted file of a dump."""

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
    """Analyst conclusion on an Evidence, with severity and optional MITRE ATT&CK technique."""

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
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="Medium")
    tags = ArrayField(models.CharField(max_length=50), blank=True, null=True, default=list)
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
    """Case timeline entry, created automatically for new evidence and findings or added by analysts."""

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="timeline_events")
    timestamp = models.DateTimeField()
    event_type = models.CharField(max_length=50)
    description = models.TextField()
    source_evidence = models.ForeignKey(Evidence, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.timestamp} - {self.event_type}"


class ReportTemplate(models.Model):
    """Report template (DOCX for docxtpl or HTML Django template) used by the case report."""

    name = models.CharField(max_length=250, unique=True)
    description = models.TextField(blank=True, null=True)
    template = models.FileField(upload_to="report_templates/")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


@receiver(post_save, sender=Finding)
def create_finding_timeline_event(sender, instance, created, **kwargs):
    """Add a ``Finding Created`` timeline event to the case of a new Finding."""
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
    """Add an ``Evidence Added`` timeline event to the case of a new Evidence."""
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
    """Remove the ``Evidence Added`` timeline events of an Evidence being deleted."""
    TimelineEvent.objects.filter(source_evidence=instance, event_type="Evidence Added").delete()


def random_color():
    """Random color from the palette, used as default dump color."""
    return random.choice(COLOR_PALETTE)[0]


class Host(models.Model):
    """Host a memory dump was taken from (several dumps of the same host enable temporal diffs)."""

    name = models.CharField(max_length=250)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Hosts"


class DumpManager(models.Manager):
    """Default manager: dumps in the recycle bin are hidden from every list, lookup and relation."""

    def get_queryset(self):
        return super().get_queryset().exclude(status=DUMP_STATUS_DELETED)


class Dump(models.Model):
    """Uploaded memory image with its processing status, symbols diagnosis, hashes and risk score.

    Deleting a dump moves it to the recycle bin (status Deleted, see :mod:`orochi.website.recycle_bin`): ``objects``
    hides it, ``all_objects`` still sees it until it is restored or purged.
    """

    host = models.ForeignKey(Host, on_delete=models.SET_NULL, null=True, blank=True, related_name="dumps")
    operating_system = models.CharField(choices=OSEnum.choices, default=OSEnum.LINUX, max_length=10)
    banner = models.CharField(max_length=500, blank=True, null=True)
    upload = models.FileField(upload_to="uploads")
    regipy_plugins = ArrayField(models.JSONField(blank=True, null=True), blank=True, null=True, default=list)
    folder = models.ForeignKey(Folder, on_delete=models.SET_NULL, blank=True, null=True)
    comment = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=250)
    index = models.CharField(max_length=250, unique=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    color = ColorField(default=random_color, samples=COLOR_PALETTE, format="hex")
    status = models.PositiveSmallIntegerField(choices=STATUS, default=1)
    symbol_status = models.CharField(
        max_length=20,
        choices=SymbolStatus.choices,
        default=SymbolStatus.UNKNOWN,
        blank=True,
        null=True,
    )
    plugins = models.ManyToManyField(Plugin, through="Result")
    risk_score = models.IntegerField(default=0)
    md5 = models.CharField(max_length=32, blank=True, null=True)
    sha256 = models.CharField(max_length=64, blank=True, null=True)
    size = models.BigIntegerField(null=True)
    suggested_symbols_path = ArrayField(models.CharField(max_length=1000, blank=True, null=True), blank=True, null=True)
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
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    status_before_delete = models.PositiveSmallIntegerField(choices=STATUS, null=True, blank=True)

    objects = DumpManager()
    all_objects = models.Manager()

    def __str__(self):
        return self.name

    @property
    def is_deleted(self) -> bool:
        """True while the dump is in the recycle bin."""
        return self.status == DUMP_STATUS_DELETED

    def soft_delete(self, user=None) -> None:
        """Move the dump to the recycle bin, remembering the status to restore."""
        if self.status != DUMP_STATUS_DELETED:
            self.status_before_delete = self.status
        self.status = DUMP_STATUS_DELETED
        self.deleted_at = timezone.now()
        self.deleted_by = user
        self._lifecycle_change = True
        self.save(update_fields=["status", "status_before_delete", "deleted_at", "deleted_by"])

    def restore(self) -> None:
        """Take the dump out of the recycle bin with the status it had (or reached) when deleted."""
        self.status = self.status_before_delete or DUMP_STATUS_COMPLETED
        self.status_before_delete = None
        self.deleted_at = None
        self.deleted_by = None
        self._lifecycle_change = True
        self.save(update_fields=["status", "status_before_delete", "deleted_at", "deleted_by"])

    def save(self, *args, **kwargs):
        """Keep a dump in the recycle bin when a stale instance (e.g. a running upload task) saves it.

        The status the task wanted to set becomes the status restored later.
        """
        lifecycle_change = getattr(self, "_lifecycle_change", False)
        self._lifecycle_change = False
        if self.pk and not lifecycle_change and self.status != DUMP_STATUS_DELETED:
            row = (
                Dump.all_objects.filter(pk=self.pk, status=DUMP_STATUS_DELETED)
                .values("deleted_at", "deleted_by_id")
                .first()
            )
            if row:
                self.status_before_delete = self.status
                self.status = DUMP_STATUS_DELETED
                self.deleted_at = row["deleted_at"]
                self.deleted_by_id = row["deleted_by_id"]
                if kwargs.get("update_fields") is not None:
                    kwargs["update_fields"] = set(kwargs["update_fields"]) | {
                        "status",
                        "status_before_delete",
                        "deleted_at",
                        "deleted_by",
                    }
        super().save(*args, **kwargs)

    class Meta:
        base_manager_name = "all_objects"
        default_manager_name = "objects"
        permissions = (("can_see", "Can See"),)
        verbose_name_plural = "Dumps"
        unique_together = ["name", "author"]
        indexes = [GinIndex(fields=["search_vector"], name="dump_gin_idx")]


class ResultManager(models.Manager):
    """Manager resolving Results by natural key ``(dump name, plugin name)`` for fixtures."""

    def get_by_natural_key(self, dump_name, plugin_name):
        """Result of the named plugin on the named dump."""
        dump = Dump.objects.get(name=dump_name)
        plugin = Plugin.objects.get(name=plugin_name)
        return self.get(dump=dump, plugin=plugin)


class Result(models.Model):
    """Run of one plugin on one dump: status, description and parameters."""

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
        """``(dump name, plugin name)``."""
        return (self.dump.name, self.plugin.name)


class Value(models.Model):
    """One output row of a plugin Result (JSON), full-text indexed for the global search."""

    result = models.ForeignKey(Result, on_delete=models.CASCADE)
    value = models.JSONField(blank=True, null=True)
    search_vector = models.GeneratedField(
        expression=SearchVector("value", config="english"),
        output_field=SearchVectorField(),
        db_persist=True,
    )

    class Meta:
        indexes = [
            GinIndex(fields=["search_vector"], name="value_gin_idx"),
            GinIndex(fields=["value"], name="value_jsonb_gin_idx"),
            models.Index(fields=["result"], name="value_result_idx"),
        ]


class ValueAnnotation(models.Model):
    """Analyst note on a plugin row: comment, false positive, suspicious or verified threat."""

    STATUS_CHOICES = (
        ("comment", "Comment"),
        ("false_positive", "False Positive"),
        ("suspicious", "Suspicious"),
        ("verified_threat", "Verified Threat"),
        ("resolved", "Resolved"),
    )
    value = models.ForeignKey(Value, on_delete=models.CASCADE, related_name="annotations")
    parent = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="replies",
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
    """Secret or credential found by the secrets scanner: matched value, masked copy for display, PID and offset."""

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
    """Detection rule hit on a dump, with severity, MITRE technique and the matching row."""

    SEVERITY_CHOICES = (
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
        ("Info", "Info"),
    )
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE, related_name="triage_findings")
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
        try:
            dump_label = self.dump.name if self.dump_id else "unassigned"
        except Dump.DoesNotExist:
            dump_label = f"dump #{self.dump_id}"
        return f"[{self.severity}] {self.rule_name} on {dump_label}"


class DumpNarrative(models.Model):
    """AI triage narrative of a dump, with the evidence hash, citations and the hallucination check."""

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


class DumpIOC(models.Model):
    """Indicator of compromise extracted from a dump (IP, domain, URL, hash...) with enrichment data."""

    IOC_TYPE_CHOICES = (
        ("ip", "IP Address"),
        ("domain", "Domain Name"),
        ("url", "URL"),
        ("hash_sha256", "SHA256 Hash"),
        ("hash_md5", "MD5 Hash"),
        ("yara", "YARA Rule Match"),
    )
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE, related_name="iocs")
    ioc_type = models.CharField(max_length=30, choices=IOC_TYPE_CHOICES)
    value = models.CharField(max_length=500)
    source_plugin = models.CharField(max_length=150)
    context = models.JSONField(default=dict, blank=True)
    enrichment = models.JSONField(default=dict, blank=True)
    is_malicious = models.BooleanField(default=False)
    threat_score = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-threat_score", "-created_at")
        indexes = [
            models.Index(fields=["dump", "ioc_type"]),
            models.Index(fields=["dump", "is_malicious"]),
        ]
        unique_together = ("dump", "ioc_type", "value")

    def __str__(self):
        return f"[{self.get_ioc_type_display()}] {self.value} ({self.dump.name})"


class Bookmark(models.Model):
    """Saved plugin view (plugin, dumps, search query) of a user."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="bookmarks")
    indexes = models.ManyToManyField(Dump)
    plugin = models.ForeignKey(Plugin, on_delete=models.CASCADE)
    name = models.CharField(max_length=250)
    icon = models.CharField(choices=IconEnum.choices, default=IconEnum.SS_ORI, max_length=50)
    star = models.BooleanField(default=False)
    query = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        unique_together = ["name", "user"]

    @property
    def indexes_list(self):
        """Comma separated indexes of the bookmarked dumps (for URLs)."""
        return ",".join([p.index for p in self.indexes.all()])

    @property
    def indexes_names_list(self):
        """Comma separated names of the bookmarked dumps (for display)."""
        return ", ".join([p.name for p in self.indexes.all()])

    def __str__(self):
        return f"{self.name}"


@receiver(pre_delete, sender=Dump)
def delete_dump_related(sender, instance, **kwargs):
    """Before deleting a dump, remove its bookmarks, results, media folder and uploaded file."""
    Bookmark.objects.filter(indexes=instance).delete()
    instance.result_set.all().delete()
    dump_dir = Path(settings.MEDIA_ROOT) / instance.index
    if dump_dir.exists():
        shutil.rmtree(dump_dir, ignore_errors=True)
    if instance.upload:
        with contextlib.suppress(Exception):
            instance.upload.delete(save=False)


def user_directory_path(instance, filename):
    """Upload path helper kept only because migration 0033 references it; no current field uses it."""
    return "user_{0}/{1}"


class CustomRule(models.Model):
    """User YARA rule file, private or public to all users."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="rules")
    name = models.CharField(max_length=250)
    public = models.BooleanField(default=False)
    path = models.CharField(max_length=255)
    default = models.BooleanField(default=False)


class TaskLog(models.Model):
    """Background task tracked from submission to completion (status, result, error, owner)."""

    task_id = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=50, default="Submitted")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    error = models.TextField(blank=True, null=True)
    result = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.name} ({self.task_id})"


class Playbook(models.Model):
    """Named set of plugins to run together on a dump for an incident response scenario."""

    playbook_id = models.SlugField(max_length=100, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    operating_system = models.CharField(choices=OSEnum.choices, default=OSEnum.WINDOWS, max_length=10)
    plugins = models.ManyToManyField(Plugin, related_name="playbooks", blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="custom_playbooks",
        null=True,
        blank=True,
    )
    icon = models.CharField(max_length=50, default="fa-bolt")
    color = models.CharField(max_length=50, default="blue")
    tags = models.JSONField(default=list, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.operating_system})"

    @property
    def plugin_names(self):
        """Names of the plugins of the playbook."""
        return list(self.plugins.values_list("name", flat=True))


class UserPlaybookPreference(models.Model):
    """Per-user auto-run preference for any playbook (built-in or custom), mirroring UserPlugin.automatic."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="playbook_preferences",
    )
    playbook_id = models.SlugField(max_length=100)
    auto_run = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "playbook_id")

    def __str__(self):
        return f"{self.user} -> {self.playbook_id} (auto_run={self.auto_run})"


class HuntingRule(models.Model):
    """Declarative Sigma-style YAML hunting rule evaluated over structured Volatility plugin rows (#1545)."""

    SEVERITY_CHOICES = (
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    )
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=120, unique=True)
    description = models.TextField(blank=True, default="")
    enabled = models.BooleanField(default=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="High")
    score = models.PositiveSmallIntegerField(default=30)
    mitre_technique = models.CharField(max_length=100, blank=True, default="")
    plugin_filter = models.CharField(
        max_length=255,
        default="*",
        help_text="Volatility plugin suffix (e.g. 'cmdline.CmdLine') or '*' for all plugins.",
    )
    yaml_content = models.TextField(help_text="Sigma-style YAML rule with title, logsource, and detection blocks.")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="hunting_rules",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return f"{self.name} ({self.severity})"


class ForensicNode(models.Model):
    """Node of the case forensic graph (process, socket, user, hash...) built from plugin results."""

    NODE_TYPES = (
        ("process", "Process"),
        ("socket", "Network Socket"),
        ("user", "User / Token"),
        ("hash", "File Hash / IOC"),
        ("file", "File / Artifact"),
        ("registry", "Registry Key"),
    )
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="graph_nodes")
    dump = models.ForeignKey(Dump, on_delete=models.CASCADE, related_name="nodes")
    node_type = models.CharField(max_length=30, choices=NODE_TYPES)
    label = models.CharField(max_length=255)
    canonical_id = models.CharField(max_length=255)
    attributes = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    is_malicious = models.BooleanField(default=False)

    class Meta:
        unique_together = ("case", "canonical_id")
        indexes = [
            models.Index(fields=["case", "node_type"]),
            models.Index(fields=["canonical_id"]),
        ]

    def __str__(self):
        return f"{self.label} ({self.node_type})"


class ForensicEdge(models.Model):
    """Relation between two forensic graph nodes (spawns, injects, connects, authenticates...)."""

    EDGE_TYPES = (
        ("spawns", "Spawned Process"),
        ("injects", "Memory Injection"),
        ("connects", "Network Connection"),
        ("authenticates", "Authentication / Token"),
        ("writes", "File Write"),
    )
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="graph_edges")
    source = models.ForeignKey(ForensicNode, on_delete=models.CASCADE, related_name="out_edges")
    target = models.ForeignKey(ForensicNode, on_delete=models.CASCADE, related_name="in_edges")
    edge_type = models.CharField(max_length=30, choices=EDGE_TYPES)
    timestamp = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [models.Index(fields=["case", "edge_type"])]

    def __str__(self):
        return f"{self.source.label} --[{self.edge_type}]--> {self.target.label}"


class CaseNote(models.Model):
    """Markdown note written by an analyst on a case."""

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="notes")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="case_notes")
    title = models.CharField(max_length=255)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} by {self.author}"


class CTFQuestion(models.Model):
    """Jeopardy question of a CTF case; only the SHA-256 of the normalized answer is stored."""

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="ctf_questions")
    question_text = models.TextField()
    points = models.PositiveIntegerField(default=100)
    answer_hash = models.CharField(max_length=64)
    order = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self):
        try:
            case_label = self.case.name if self.case_id else "unassigned"
        except Case.DoesNotExist:
            case_label = f"case #{self.case_id}"
        return f"CTF Q{self.order} ({self.points} pts) - {case_label}"

    @staticmethod
    def normalize_answer(raw_answer: str) -> str:
        """Answers are compared case-insensitively, ignoring surrounding whitespace."""
        cleaned = (raw_answer or "").strip().lower()
        return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()

    def set_answer(self, raw_answer: str) -> None:
        """Store the hash of ``raw_answer`` (normalized: stripped and lower-cased)."""
        self.answer_hash = self.normalize_answer(raw_answer)

    def check_answer(self, candidate: str) -> bool:
        """Constant-time comparison of a candidate answer with the stored hash."""
        return hmac.compare_digest(self.answer_hash, self.normalize_answer(candidate))


class CTFHint(models.Model):
    """Hint of a question; unlocking it costs ``cost`` points on that question."""

    question = models.ForeignKey(CTFQuestion, on_delete=models.CASCADE, related_name="hints")
    hint_text = models.TextField()
    cost = models.PositiveIntegerField(default=10)
    unlocked_by = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="unlocked_ctf_hints",
        blank=True,
    )

    class Meta:
        ordering = ["cost", "id"]

    def __str__(self):
        return f"Hint (-{self.cost} pts) for Q{self.question_id}"


class CTFSubmission(models.Model):
    """Answer submitted to a question, with verdict and points (one correct submission per user)."""

    question = models.ForeignKey(CTFQuestion, on_delete=models.CASCADE, related_name="submissions")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ctf_submissions",
    )
    submitted_answer = models.CharField(max_length=500)
    is_correct = models.BooleanField(default=False)
    awarded_points = models.IntegerField(default=0)
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-submitted_at"]
        indexes = [
            models.Index(fields=["question", "user", "is_correct"]),
        ]
        constraints = [
            # A question is scored once per user, even with concurrent submissions
            models.UniqueConstraint(
                fields=["question", "user"],
                condition=models.Q(is_correct=True),
                name="ctf_single_correct_submission",
            ),
        ]

    def __str__(self):
        status = "CORRECT" if self.is_correct else "WRONG"
        return f"{self.user} -> Q{self.question_id} [{status}] ({self.awarded_points} pts)"


class CTFObjective(models.Model):
    """Ground-truth forensic artifact to discover, matched on canonical entity criteria."""

    ENTITY_PROCESS = "process"
    ENTITY_NETWORK = "network"
    ENTITY_INJECTION = "injection"
    ENTITY_REGISTRY = "registry"
    ENTITY_FILE = "file"
    ENTITY_YARA = "yara"
    ENTITY_GENERIC = "generic"
    ENTITY_TYPE_CHOICES = (
        (ENTITY_PROCESS, "Process"),
        (ENTITY_NETWORK, "Network"),
        (ENTITY_INJECTION, "Memory Injection"),
        (ENTITY_REGISTRY, "Registry / Persistence"),
        (ENTITY_FILE, "File / Artifact"),
        (ENTITY_YARA, "YARA Match"),
        (ENTITY_GENERIC, "Generic / Regex"),
    )

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="ctf_objectives")
    title = models.CharField(max_length=250)
    description = models.TextField(blank=True, default="")
    entity_type = models.CharField(max_length=20, choices=ENTITY_TYPE_CHOICES, default=ENTITY_GENERIC)
    criteria = models.JSONField(default=dict, blank=True)
    points = models.PositiveIntegerField(default=100)
    required_mitre = models.CharField(max_length=50, blank=True, default="")
    mitre_bonus = models.PositiveIntegerField(default=25)
    order = models.PositiveIntegerField(default=1)
    source_evidence = models.ForeignKey(
        Evidence,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ctf_objectives",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self):
        return f"Objective #{self.order}: {self.title} [{self.entity_type}] ({self.points} pts)"


class CTFObjectiveHint(models.Model):
    """Hint of a discovery objective; unlocking it costs ``cost`` points on that objective."""

    objective = models.ForeignKey(CTFObjective, on_delete=models.CASCADE, related_name="hints")
    hint_text = models.TextField()
    cost = models.PositiveIntegerField(default=10)
    unlocked_by = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="unlocked_ctf_objective_hints",
        blank=True,
    )

    class Meta:
        ordering = ["cost", "id"]

    def __str__(self):
        return f"Hint (-{self.cost} pts) for objective {self.objective_id}"


class CTFDiscoverySubmission(models.Model):
    """Artifact submitted against the objectives: TP, FP or duplicate, with points and bonuses."""

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="ctf_discovery_submissions")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ctf_discovery_submissions",
    )
    objective = models.ForeignKey(
        CTFObjective,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="submissions",
    )
    evidence = models.ForeignKey(
        Evidence,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ctf_discovery_submissions",
    )
    plugin = models.CharField(max_length=250, blank=True, default="")
    result_row = models.JSONField(default=dict, blank=True)
    canonical_entity = models.JSONField(default=dict, blank=True)
    submitted_mitre = models.CharField(max_length=50, blank=True, default="")
    is_tp = models.BooleanField(default=False)
    is_fp = models.BooleanField(default=False)
    is_duplicate = models.BooleanField(default=False)
    is_first_blood = models.BooleanField(default=False)
    mitre_matched = models.BooleanField(default=False)
    awarded_points = models.IntegerField(default=0)
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-submitted_at"]
        indexes = [
            models.Index(fields=["case", "user", "is_tp"]),
            models.Index(fields=["case", "objective", "is_tp"]),
        ]

    def __str__(self):
        label = "TP" if self.is_tp else ("DUP" if self.is_duplicate else "FP")
        return f"{self.user} -> Case {self.case_id} [{label}] ({self.awarded_points:+d} pts)"
