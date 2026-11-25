from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from ninja import Field, ModelSchema, Schema
from ninja.orm import create_schema
from ninja.pagination import PaginationBase
from pydantic import field_validator

from orochi.website.defaults import OSEnum
from orochi.website.models import Bookmark, Case, CustomRule, Dump, Folder, Host, Plugin
from orochi.ya.models import Rule


class RULE_ACTION(StrEnum):
    """Action on custom rules: publish or unpublish."""

    PUBLISH = "Publish"
    UNPUBLISH = "Unpublish"


###################################################
# Auth
###################################################
UsernameSchemaMixin = create_schema(get_user_model(), fields=[get_user_model().USERNAME_FIELD])

EmailSchemaMixin = create_schema(get_user_model(), fields=[get_user_model().EMAIL_FIELD])


class LoginIn(UsernameSchemaMixin):
    """Login credentials."""

    password: str


class RequestPasswordResetIn(EmailSchemaMixin):
    """Email address to send the password reset link to."""

    pass


class SetPasswordIn(UsernameSchemaMixin):
    """New password (twice) with the reset token."""

    new_password1: str
    new_password2: str
    token: str


class ChangePasswordIn(Schema):
    """Current password and the new one (twice)."""

    old_password: str
    new_password1: str
    new_password2: str


class APITokenCreateIn(Schema):
    """Name of the API token to create."""

    name: str


class APITokenOut(Schema):
    """API token metadata (the secret itself is never returned again)."""

    id: int
    name: str
    token_prefix: str
    created_at: datetime
    last_used_at: datetime | None = None
    is_active: bool


class APITokenCreatedOut(APITokenOut):
    """Newly created API token, including the raw secret shown only once."""

    token: str


###################################################
# General
###################################################
class ErrorsOut(Schema):
    """Error payload: a message, a list or field errors."""

    errors: str | list[str] | dict[str, str | list[str]]


class SuccessResponse(Schema):
    """Generic success message."""

    message: str


###################################################
# Utils
###################################################
class WorkerInfo(Schema):
    """Dask worker status: address, threads, memory and running tasks."""

    name: str
    address: str
    nthreads: int = 1
    memory_limit: int = 0
    executing: int = 0


class TaskLogItem(Schema):
    """TaskLog row as returned by the task API."""

    task_id: str
    name: str
    status: str
    created_at: str
    updated_at: str
    result: str | None = None
    error: str | None = None


class LiveDaskTask(Schema):
    """Task currently known to the Dask scheduler."""

    task_id: str
    name: str
    task_type: str
    dump_name: str | None = None
    dump_id: int | None = None
    dump_index: str | None = None
    plugin_name: str | None = None
    worker: str | None = None
    state: str = "Running"
    duration: float = 0.0
    started_at: str | None = None
    description: str | None = None
    can_kill: bool = True


class TaskInfoOut(Schema):
    """Details of one task: state, worker, dump, timing and error."""

    task_id: str
    name: str
    task_type: str
    state: str
    worker: str | None = None
    duration: float = 0.0
    started_at: str | None = None
    dump_id: int | None = None
    dump_name: str | None = None
    dump_index: str | None = None
    dump_os: str | None = None
    plugin_name: str | None = None
    plugin_params: Any | None = None
    description: str | None = None
    can_kill: bool = True
    error: str | None = None
    result: str | None = None
    extra: dict | None = None


class DaskStatusOut(Schema):
    """Cluster overview: running and queued tasks, workers."""

    running: int = 0
    queued: int = 0
    workers_count: int = 0
    workers: list[WorkerInfo] = []
    live_tasks: list[LiveDaskTask] = []
    recent_tasks: list[TaskLogItem] = []


class UnifiedTaskOut(Schema):
    """Task from TaskLog or the Dask scheduler in a common shape."""

    task_id: str
    name: str
    task_type: str
    state: str
    worker: str | None = None
    duration: float = 0.0
    started_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    dump_id: int | None = None
    dump_name: str | None = None
    dump_index: str | None = None
    dump_os: str | None = None
    plugin_name: str | None = None
    description: str | None = None
    can_kill: bool = True
    can_retry: bool = False
    error: str | None = None
    result: str | None = None


class TaskFilterQuery(Schema):
    """Filters of the task list (status, type, dump, text)."""

    status: str | None = None
    task_type: str | None = None
    dump_id: int | None = None
    search: str | None = None
    limit: int = 50
    offset: int = 0


class TaskListOut(Schema):
    """Task list with total and filtered counts."""

    total: int
    filtered: int
    tasks: list[UnifiedTaskOut]


class TaskSummaryOut(Schema):
    """Task counts per state."""

    running: int
    queued: int
    completed: int
    failed: int
    total: int
    workers_count: int
    workers: list[WorkerInfo] = []


class BulkTaskKillIn(Schema):
    """Tasks to cancel: explicit ids, or all running / queued ones."""

    task_ids: list[str] | None = None
    all_running: bool = False
    all_queued: bool = False
    dump_id: int | None = None


class TaskPruneIn(Schema):
    """Delete finished TaskLog rows older than ``days`` (optionally by status, or all)."""

    days: int = 7
    status: str | None = None
    all: bool = False


###################################################
# Users
###################################################
class GroupSchema(ModelSchema):
    """Django group (role)."""

    class Meta:
        model = Group
        fields = ["id", "name"]


class UserOutSchema(ModelSchema):
    """User with groups and effective Orochi role."""

    groups: list[GroupSchema] = []
    role: str | None = "Analyst"

    class Meta:
        model = get_user_model()
        fields = ["id", "username", "first_name", "last_name"]

    @staticmethod
    def resolve_role(obj):
        """Effective Orochi role of the user."""
        from orochi.website.roles import get_user_role

        return get_user_role(obj)


class UserInSchema(ModelSchema):
    """User creation / update payload with optional role."""

    role: str | None = None

    class Meta:
        model = get_user_model()
        fields = [
            "username",
            "email",
            "first_name",
            "last_name",
            "password",
        ]


###################################################
# Plugins
###################################################
class PluginOutSchema(ModelSchema):
    """Plugin as returned by the API."""

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
            "maxmind_check",
            "local",
            "local_date",
            "min_role",
        ]


class PluginInSchema(ModelSchema):
    """Editable plugin options."""

    class Meta:
        model = Plugin
        fields = [
            "operating_system",
            "disabled",
            "local_dump",
            "vt_check",
            "clamav_check",
            "regipy_check",
            "maxmind_check",
            "local",
            "local_date",
            "min_role",
        ]


class PluginInstallSchema(Schema):
    """Install a custom plugin from a URL (optionally in background)."""

    plugin_url: str
    operating_system: OSEnum
    async_mode: bool = True


class PluginUploadOutSchema(Schema):
    """Result of a plugin upload with the installed plugin names."""

    message: str
    installed_plugins: list[str] = []


class CommunityPluginItemSchema(Schema):
    """Plugin of the community catalog (orochi_plugins)."""

    author: str
    name: str
    repo_url: str
    zip_path: str
    download_url: str | None = None
    last_update: str
    operating_system: str
    installed: bool = False
    installed_names: list[str] = []
    description: str = ""


class CommunityPluginCatalogOutSchema(Schema):
    """Community catalog as DataTables rows and structured items."""

    data: list[list[Any]] = []
    items: list[CommunityPluginItemSchema] = []
    source_url: str


class PluginSourceOutSchema(Schema):
    """Source code of an installed plugin."""

    name: str
    filename: str
    source: str


class PluginParametersOutSchema(Schema):
    """Parameter of a plugin, as needed to build the run form."""

    optional: bool
    name: str
    mode: str
    type: str
    choices: list[str] | None = None


###################################################
# Folder
###################################################
class FolderSchema(ModelSchema):
    """Folder name."""

    class Meta:
        model = Folder
        fields = ["name"]


class FolderFullSchema(ModelSchema):
    """Folder with its owner."""

    user: UserOutSchema = None

    class Meta:
        model = Folder
        fields = ["name"]


###################################################
# Host
###################################################
class HostSchema(ModelSchema):
    """Host name."""

    class Meta:
        model = Host
        fields = ["name"]


class HostFullSchema(ModelSchema):
    """Host with id and description."""

    description: str | None = None

    class Meta:
        model = Host
        fields = ["id", "name", "description"]


###################################################
# Case
###################################################
class CaseSchema(ModelSchema):
    """Case name and description."""

    description: str | None = None

    class Meta:
        model = Case
        fields = ["name"]


class CaseFullSchema(ModelSchema):
    """Case with status, CTF flag and collaborator ids."""

    description: str | None = None
    status: str | None = None
    is_ctf: bool | None = False
    collaborators: list[int] | None = None

    class Meta:
        model = Case
        fields = ["id", "name", "description", "status", "is_ctf"]

    @staticmethod
    def resolve_collaborators(obj):
        """Primary keys of the case collaborators."""
        return [c.pk for c in obj.collaborators.all()]


class CaseUpdateSchema(Schema):
    """Partial case update (name, description, status, collaborators, CTF flag)."""

    name: str | None = None
    description: str | None = None
    status: str | None = None
    collaborators: list[int] | None = None
    is_ctf: bool | None = None


###################################################
# CTF (#1542)
###################################################
class CTFHintIn(Schema):
    """Hint text and point cost."""

    hint_text: str = Field(..., min_length=1)
    cost: int = Field(10, ge=0)


class CTFQuestionIn(Schema):
    """New CTF question with answer (stored hashed), points, order and hints."""

    question_text: str = Field(..., min_length=1)
    answer: str = Field(..., min_length=1, max_length=500)
    points: int = Field(100, ge=0)
    order: int = Field(1, ge=0)
    hints: list[CTFHintIn] = []

    @field_validator("question_text", "answer")
    @classmethod
    def not_blank(cls, value: str) -> str:
        """Reject blank question text or answer."""
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()


class CTFAnswerIn(Schema):
    """Answer submitted to a CTF question."""

    answer: str = Field(..., min_length=1, max_length=500)


class CTFObjectiveIn(Schema):
    """New discovery objective: entity type, criteria, points, MITRE bonus and hints."""

    title: str = Field(..., min_length=1, max_length=250)
    description: str = ""
    entity_type: str = "generic"
    criteria: dict = Field(..., min_length=1)
    points: int = Field(100, ge=0)
    required_mitre: str = ""
    mitre_bonus: int = Field(25, ge=0)
    order: int = Field(1, ge=1)
    hints: list[CTFHintIn] = []

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, value: str) -> str:
        """Reject blank titles."""
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()


class CTFDiscoveryIn(Schema):
    """Artifact to grade: plugin row, extracted file or Evidence id, with optional MITRE ID."""

    plugin: str = ""
    result_row: dict = Field(default_factory=dict)
    extracted_file: str = ""
    submitted_mitre: str = ""
    evidence_id: int | None = None


class CTFSettingsIn(Schema):
    """Partial update of CTF scoring settings and publication."""

    ctf_mode: str | None = None
    ctf_fp_penalty: int | None = Field(None, ge=0)
    ctf_first_blood_bonus: int | None = Field(None, ge=0, le=200)
    ctf_dynamic_scoring: bool | None = None
    ctf_published: bool | None = None


class CTFScenarioImportIn(Schema):
    """YAML or JSON scenario to import, optionally replacing existing items."""

    payload: str = Field(..., min_length=1)
    replace_existing: bool = False


###################################################
# Dump
###################################################
def normalize_name_or_obj(v):
    """Accept a folder / host as name, object with ``name`` or dict with ``name`` and return the name."""
    if v is None:
        return None
    if hasattr(v, "name"):
        v = v.name
    elif isinstance(v, dict):
        v = v.get("name") or v.get("id")
    if v is None:
        return None
    s = str(v).strip()
    return s or None


class DumpIn(ModelSchema):
    """New dump upload metadata (folder and host by name)."""

    folder: str | dict | int | None = None
    host: str | dict | int | None = None
    local_folder: str | None = None
    password: str | None = None
    original_name: str | None = None

    @field_validator("folder", "host", mode="before")
    @classmethod
    def parse_name_or_obj(cls, v):
        """Normalize folder and host to their names."""
        return normalize_name_or_obj(v)

    class Meta:
        model = Dump
        fields = [
            "operating_system",
            "description",
            "comment",
            "name",
            "color",
        ]


class DumpEditIn(ModelSchema):
    """Dump metadata update, including authorized users."""

    folder: str | dict | int | None = None
    host: str | dict | int | None = None
    authorized_users: list[int] | None = None

    @field_validator("folder", "host", mode="before")
    @classmethod
    def parse_name_or_obj(cls, v):
        """Normalize folder and host to their names."""
        return normalize_name_or_obj(v)

    class Meta:
        model = Dump
        fields = ["comment", "name", "color", "status"]


class DumpSchema(ModelSchema):
    """Dump as returned by the API."""

    folder: FolderSchema | None = None
    host: HostSchema | None = None
    author: UserOutSchema = None
    has_auto: bool = False

    class Meta:
        model = Dump
        fields = [
            "id",
            "index",
            "name",
            "color",
            "operating_system",
            "upload",
            "status",
            "description",
        ]


class RegipyPluginSchema(Schema):
    """Output of a regipy plugin on a registry hive."""

    plugin: str = None
    hive: str = None
    data: dict | list[dict] = None


class DumpInfoSchema(ModelSchema):
    """Dump details including regipy plugin output."""

    folder: FolderSchema | None = None
    host: HostSchema | None = None
    regipy_plugins: list[RegipyPluginSchema] | None = None
    suggested_symbols_path: list[str] | None = None
    author: UserOutSchema = None

    class Meta:
        model = Dump
        fields = [
            "index",
            "name",
            "comment",
            "description",
            "color",
            "operating_system",
            "md5",
            "sha256",
            "size",
            "upload",
            "banner",
        ]


###################################################
# Plugins [from Results]
###################################################
class ResultSmallOutSchema(Schema):
    """Plugin result summary of a dump."""

    name: str = Field(..., alias="plugin__name")
    comment: str | None = Field(..., alias="plugin__comment")
    id: int = Field(..., alias="plugin__id")
    min_role: str | None = "Analyst"
    can_execute: bool | None = True


###################################################
# Bookmarks
###################################################
class BookmarksEditInSchema(ModelSchema):
    """Editable bookmark fields."""

    class Meta:
        model = Bookmark
        fields = ["name", "icon", "query"]


class BookmarksSchema(ModelSchema):
    """Bookmark with owner and dumps."""

    user: UserOutSchema = None
    indexes: list[DumpSchema] = []

    class Meta:
        model = Bookmark
        fields = ["id", "name", "icon", "star", "query"]


class BookmarksInSchema(Schema):
    """New bookmark from the current view."""

    selected_indexes: str = None
    name: str = None
    star: bool = False
    icon: str = None
    selected_plugin: str = None
    query: str | None = None


###################################################
# CustomRules
###################################################
class User(ModelSchema):
    """Username only."""

    class Meta:
        model = get_user_model()
        fields = ["username"]


class RuleData(Schema):
    """Custom rule row of the rules table."""

    id: int
    name: str
    path: str
    user: str
    public: bool
    default: bool


class CustomRuleEditInSchema(ModelSchema):
    """Custom rule visibility."""

    class Meta:
        model = CustomRule
        fields = ["public"]


class CustomRulePagination(PaginationBase):
    """DataTables pagination for custom rules."""

    class Input(Schema):
        """DataTables paging input."""

        start: int
        length: int

    class Output(Schema):
        """DataTables response."""

        draw: int
        recordsTotal: int
        recordsFiltered: int
        data: list[RuleData]

    items_attribute: str = "data"

    def paginate_queryset(self, queryset, pagination: Input, **params):
        """Slice the queryset and wrap it in a DataTables response."""
        request = params["request"]
        return {
            "draw": request.draw,
            "recordsTotal": request.total,
            "recordsFiltered": queryset.count(),
            "data": [
                RuleData(
                    **{
                        "id": x.pk,
                        "name": x.name,
                        "path": x.path,
                        "user": x.user.username,
                        "public": x.public,
                        "default": x.default,
                    }
                )
                for x in queryset[pagination.start : pagination.start + pagination.length]
            ],
        }


###################################################
# Rules
###################################################
class RuleBuildSchema(Schema):
    """Build a custom rule from the selected rules."""

    rule_ids: list[int]
    rulename: str


class RulesOutSchema(ModelSchema):
    """YARA rule as returned by the API."""

    class Meta:
        model = Rule
        fields = ["id", "path", "enabled", "compiled", "ruleset", "created", "updated"]


class ListStr(Schema):
    """List of rule ids."""

    rule_ids: list[int]


class ListStrAction(Schema):
    """Rule ids with publish / unpublish action."""

    rule_ids: list[int]
    action: RULE_ACTION


class RuleEditInSchena(Schema):
    """New source of a rule."""

    text: str


class RuleOut(Schema):
    """YARA rule row of the rules table."""

    id: int
    ruleset_name: str
    ruleset_description: str | None = None
    path_name: str
    headline: str | None = None


class RulesetFeedOut(Schema):
    """YARA ruleset feed with sync state."""

    id: int
    name: str
    url: str | None = None
    description: str | None = None
    enabled: bool
    cloned: bool
    auto_update: bool
    rules_count: int
    last_sync: datetime | None = None
    last_sync_status: str | None = None
    last_sync_error: str | None = None


class RulesetFeedSyncIn(Schema):
    """Sync one ruleset (or all) and optionally rebuild the default rule."""

    ruleset_id: int | None = None
    compile_default: bool = True
    force: bool = False


class RulesetToggleAutoUpdateIn(Schema):
    """Enable or disable automatic updates of a ruleset."""

    auto_update: bool


class YaraLiveTestIn(Schema):
    """YARA live test: rule source or rule ids, and the data to scan."""

    rule_source: str | None = None
    custom_rule_id: int | None = None
    rule_ids: list[int] | None = None
    target_mode: str = "text"  # "text" | "dump_files" | "db_artifacts"
    sample_text: str | None = None
    dump_indexes: list[str] | None = None
    save_sidecars: bool = False


class YaraGenerateFromArtifactIn(Schema):
    """Generate a YARA rule from a memory artifact (hex dump or strings)."""

    rule_name: str = "Orochi_Generated_Rule"
    hex_dump: str | None = None
    strings: list[str] | None = None
    description: str = "Auto-generated YARA rule from memory forensic artifact"
    dump_name: str | None = None
    process_name: str | None = None
    pid: int | str | None = None
    mitre_technique: str | None = None
    save_to_ruleset: bool = False


###################################################
# Datatables
###################################################
class TableFilter(Schema):
    """DataTables search and ordering parameters."""

    search: str | None = None
    order_column: int | None = 1
    order_dir: str = Field("asc", pattern="^(asc|desc)$")


class RulePagination(PaginationBase):
    """DataTables pagination for YARA rules."""

    class Input(Schema):
        """DataTables paging input."""

        start: int
        length: int

    class Output(Schema):
        """DataTables response."""

        draw: int
        recordsTotal: int
        recordsFiltered: int
        data: list[RuleOut]

    items_attribute: str = "data"

    def paginate_queryset(self, queryset, pagination: Input, **params):
        """Slice the queryset and build escaped DataTables rows."""
        from django.utils.html import escape

        request = params["request"]
        items = []
        for x in queryset[pagination.start : pagination.start + pagination.length]:
            if request.search:
                headline = x.headline
            else:
                compact = " ".join((x.rule or "").split())
                preview = compact[:180] + (" ..." if len(compact) > 180 else "")
                headline = escape(preview)
            items.append(
                RuleOut(
                    **{
                        "id": x.pk,
                        "ruleset_name": x.ruleset.name,
                        "ruleset_description": x.ruleset.description,
                        "path_name": Path(x.path).name,
                        "headline": headline,
                    }
                )
            )
        return {
            "draw": request.draw,
            "recordsTotal": request.total,
            "recordsFiltered": queryset.count(),
            "data": items,
        }


###################################################
# Symbols
###################################################
class SymbolsBannerIn(Schema):
    """Symbol files chosen for a dump banner."""

    path: list[str] = []
    index: str | None = None
    operating_system: OSEnum | None = None
    banner: str | None = None


class UploadFileInfo(Schema):
    """Uploaded file name or file in the local upload folder."""

    original_name: str | None = None
    local_folder: str | None = None


class UploadFileIn(Schema):
    """Uploaded symbol files."""

    info: list[UploadFileInfo] | None = []


class ISFIn(Schema):
    """ISF path or URL to download."""

    path: str


class DwarfGenerateIn(Schema):
    """Build an ISF with dwarf2json from a kernel ELF (and optional System.map)."""

    elf_path: str | None = None
    system_map_path: str | None = None
    output_name: str | None = None
    dump_index: str | None = None


class BtfGenerateIn(Schema):
    """Build an ISF with btf2json from a BTF file (System.map and banner optional)."""

    btf_path: str | None = None
    system_map_path: str | None = None
    banner: str | None = None
    output_name: str | None = None
    dump_index: str | None = None


class SymbolsOut(Schema):
    """Symbol file row of the symbols table."""

    id: str
    path: str
    action: tuple[str, str]


class CustomSymbolsPagination(PaginationBase):
    """DataTables pagination for symbol files."""

    class Input(Schema):
        """DataTables paging input."""

        start: int = 0
        length: int = 10

    class Output(Schema):
        """DataTables response."""

        draw: int | None = None
        recordsTotal: int
        recordsFiltered: int
        data: list[SymbolsOut]

    items_attribute: str = "data"

    def paginate_queryset(self, queryset, pagination: Input, **params):
        """Slice the symbol list and wrap it in a DataTables response."""
        request = params.get("request")
        draw = getattr(request, "draw", 1) if request else 1
        total = getattr(request, "total", len(queryset)) if request else len(queryset)
        start = pagination.start or 0
        length = pagination.length if pagination.length is not None and pagination.length > 0 else 10
        return {
            "draw": draw if draw is not None else 1,
            "recordsTotal": total,
            "recordsFiltered": len(queryset),
            "data": [
                SymbolsOut(**{"id": x.id, "path": x.path, "action": x.action}) for x in queryset[start : start + length]
            ],
        }


###################################################
# Value Annotations
###################################################
class ValueAnnotationIn(Schema):
    """Annotation of a plugin row: status and comment."""

    status: str = "comment"
    comment: str


class ValueAnnotationOut(Schema):
    """Stored annotation of a plugin row."""

    id: int
    value_id: int
    user: str
    status: str
    comment: str
    created_at: str


###################################################
# Secrets & Detection Triage
###################################################
class DumpSecretOut(Schema):
    """Secret found in a dump (masked value, rule, process, offset)."""

    id: int
    category: str
    category_display: str
    rule_name: str
    masked_data: str
    offset: str | None = None
    pid: int | None = None
    process_name: str | None = None
    created_at: str


class TriageFindingOut(Schema):
    """Detection rule hit with severity, MITRE technique and evidence row."""

    id: int
    rule_id: str
    rule_name: str
    category: str
    severity: str
    score: int
    mitre_technique: str | None = None
    description: str
    evidence_snippet: str | None = None
    entity: str | None = None
    created_at: str


class TriageReportOut(Schema):
    """Triage report of a dump: risk score, level, counts and findings."""

    dump_index: str
    dump_name: str
    risk_score: int
    risk_level: str
    total_findings: int
    severity_counts: dict[str, int]
    mitre_techniques: list[str]
    findings: list[TriageFindingOut]


class PromoteFindingIn(Schema):
    """Promote a triage item to a case Finding (existing case or new case name)."""

    case_id: int | None = None
    new_case_name: str | None = None
    item_type: str
    item_id: int
    severity: str | None = "Medium"
    mitre_technique: str | None = None
    note: str | None = None
    tags: list[str] | None = []


###################################################
# Timeline Feed
###################################################
class TimelineThreatOut(Schema):
    """Detection hit attached to a timeline event."""

    severity: str
    rule_name: str
    mitre: str | None = None
    entity: str | None = None


class TimelineEventOut(Schema):
    """Timeline event with timestamp, category, description and threats."""

    id: int | str | None = None
    value_id: int | None = None
    dump_name: str
    dump_index: str
    dump_color: str
    timestamp_iso: str
    timestamp_display: str
    relative_delta: str | None = None
    delta_seconds: float | None = None
    plugin: str
    category: str
    category_name: str
    category_icon: str
    category_color: str
    description: str
    macb: str | None = None
    threat: TimelineThreatOut | None = None


class TimelineBucketOut(Schema):
    """Histogram bucket of the timeline."""

    index: int
    start: str
    start_iso: str
    end_iso: str
    start_ts: float | None = None
    end_ts: float | None = None
    count: int
    height_pct: int
    category_counts: dict[str, int]
    has_threat: bool | None = False
    threat_count: int | None = 0


class TimelineCategoryOut(Schema):
    """Timeline category with event count."""

    key: str
    name: str
    count: int
    icon: str
    color: str
    badge_bg: str
    badge_text: str
    border: str


class TimelineStatsOut(Schema):
    """Timeline statistics: events, time span, peak velocity, threats."""

    total_events: int
    earliest_date: str | None = None
    latest_date: str | None = None
    timespan_display: str
    categories_count: int
    max_density: int
    threat_count: int | None = 0


class TimelineReportOut(Schema):
    """Timeline of a dump: stats, categories, buckets and events."""

    dump_index: str
    dump_name: str
    stats: TimelineStatsOut
    categories: list[TimelineCategoryOut]
    histogram: list[TimelineBucketOut]
    events: list[TimelineEventOut]


###################################################
# AI Triage Narrative
###################################################
class DumpNarrativeOut(Schema):
    """AI narrative of a dump with citations and hallucination check."""

    id: int
    dump_index: str
    dump_name: str
    model_name: str
    created_at: str
    evidence_hash: str | None = None
    raw_narrative: str
    formatted_narrative: str
    hallucination_check: dict[str, Any] = {}
    citations: list[dict[str, Any]] = []


###################################################
# IOC Extraction & Threat Intel
###################################################
class DumpIOCOut(Schema):
    """Indicator of compromise with sources and enrichment."""

    id: int
    ioc_type: str
    ioc_type_display: str
    value: str
    source_plugin: str
    context: dict[str, Any] = {}
    enrichment: dict[str, Any] = {}
    is_malicious: bool = False
    threat_score: int = 0
    created_at: str


class DumpIOCReportOut(Schema):
    """IOC report of a dump with counts."""

    dump_index: str
    dump_name: str
    total_count: int
    malicious_count: int
    type_counts: dict[str, int]
    iocs: list[DumpIOCOut]


class ExportMISPIn(Schema):
    """MISP export: an extracted file and/or IOCs."""

    filepath: str | None = None
    ioc_ids: list[int] | None = None
    export_all_iocs: bool | None = False


class ExportMISPOut(Schema):
    """Result of a MISP export."""

    success: bool
    message: str | None = "MISP export completed"
    event_id: int | str | None = None
    event_uuid: str | None = None
    exported_count: int | None = None


###################################################
# Network Graph & Geo-Map
###################################################
class NetworkNodeOut(Schema):
    """Node of the network graph (process or endpoint)."""

    id: str
    label: str
    name: str
    type: str
    pid: int | None = None
    risk: str = "Normal"
    is_suspicious: bool = False
    connections: int = 0
    country_code: str | None = None
    country_name: str | None = None
    asn: str | None = None
    asn_org: str | None = None


class NetworkEdgeOut(Schema):
    """Connection between two network graph nodes."""

    id: str
    from_: str = Field(..., alias="from")
    to: str
    proto: str
    state: str
    port: int
    is_suspicious: bool = False
    label: str


class NetworkGeoPointOut(Schema):
    """Geolocated remote IP for the map."""

    latitude: float
    longitude: float
    ip: str
    country_code: str
    country_name: str
    city: str = ""
    asn: str = ""
    asn_org: str = ""
    connections_count: int
    processes: list[str]
    ports: list[int]
    is_suspicious: bool = False


class NetworkSocketOut(Schema):
    """Socket row with process, state, geo data and suspicious flag."""

    proto: str
    local_addr: str
    local_port: int
    foreign_addr: str
    foreign_port: int
    state: str
    pid: int
    process: str
    created: str = ""
    is_external: bool = False
    is_listening: bool = False
    is_suspicious: bool = False
    service: str = ""
    country_code: str = "XX"
    country_name: str = ""
    city: str = ""
    asn: str = ""
    asn_org: str = ""


class NetworkStatsOut(Schema):
    """Socket counts: total, external, listening, suspicious."""

    total_sockets: int
    external_connections: int
    listening_ports: int
    suspicious_connections: int
    unique_countries: int
    unique_remote_hosts: int


class NetworkReportOut(Schema):
    """Network report of a dump: stats, graph, map points and sockets."""

    dump: dict[str, Any]
    stats: NetworkStatsOut
    nodes: list[NetworkNodeOut]
    edges: list[NetworkEdgeOut]
    geo_points: list[NetworkGeoPointOut]
    sockets: list[NetworkSocketOut]


###################################################
# Playbooks (Issue #1544)
###################################################
class PlaybookOut(Schema):
    """Playbook with its plugins."""

    id: str
    name: str
    description: str
    operating_system: str
    plugins: list[str]
    icon: str = "fa-bolt"
    color: str = "blue"
    tags: list[str] = []
    is_custom: bool = False
    can_delete: bool = False
    author: str = "System"


class PlaybookCreateIn(Schema):
    """New playbook: name, OS and plugin names."""

    name: str
    operating_system: str
    plugin_names: list[str]
    description: str = ""
    icon: str = "fa-bolt"
    color: str = "indigo"
    tags: list[str] = []


class PlaybookUpdateIn(Schema):
    """Partial playbook update."""

    name: str | None = None
    operating_system: str | None = None
    plugin_names: list[str] | None = None
    description: str | None = None
    icon: str | None = None
    color: str | None = None
    tags: list[str] | None = None


class PlaybookLaunchOut(Schema):
    """Plugins launched by a playbook on a dump."""

    dump_index: str
    dump_name: str
    playbook_id: str
    playbook_name: str
    task_id: str
    message: str


###################################################
# Forensic Graph & Timeline
###################################################
class CaseGraphNodeOut(Schema):
    """Node of the case forensic graph."""

    id: str
    label: str
    type: str
    attributes: dict = {}
    first_seen: datetime | None = None
    is_malicious: bool = False


class CaseGraphEdgeOut(Schema):
    """Edge of the case forensic graph."""

    source: str
    target: str
    type: str
    timestamp: datetime | None = None
    metadata: dict = {}


class CaseGraphOut(Schema):
    """Case forensic graph."""

    nodes: list[CaseGraphNodeOut]
    edges: list[CaseGraphEdgeOut]


class CaseTimelineItemOut(Schema):
    """Case timeline entry."""

    id: int | None = None
    timestamp: datetime
    event_type: str
    description: str
    source_dump: str | None = None
    source_plugin: str | None = None
    source_evidence_id: int | None = None
    metadata: dict = {}


###################################################
# Case Notes
###################################################
class CaseNoteIn(Schema):
    """New case note."""

    title: str
    content: str


class CaseNoteUpdateIn(Schema):
    """Partial case note update."""

    title: str | None = None
    content: str | None = None


class CaseNoteOut(Schema):
    """Case note with author."""

    id: int
    case_id: int
    author_id: int
    author_username: str
    title: str
    content: str
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def resolve_author_username(obj):
        """Username of the author, or ``Unknown`` when deleted."""
        return obj.author.username if obj.author else "Unknown"

    @staticmethod
    def resolve_case_id(obj):
        """Id of the note's case."""
        return obj.case.id if obj.case else 0
