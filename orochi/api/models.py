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
    PUBLISH = "Publish"
    UNPUBLISH = "Unpublish"


###################################################
# Auth
###################################################
UsernameSchemaMixin = create_schema(get_user_model(), fields=[get_user_model().USERNAME_FIELD])

EmailSchemaMixin = create_schema(get_user_model(), fields=[get_user_model().EMAIL_FIELD])


class LoginIn(UsernameSchemaMixin):
    password: str


class RequestPasswordResetIn(EmailSchemaMixin):
    pass


class SetPasswordIn(UsernameSchemaMixin):
    new_password1: str
    new_password2: str
    token: str


class ChangePasswordIn(Schema):
    old_password: str
    new_password1: str
    new_password2: str


###################################################
# General
###################################################
class ErrorsOut(Schema):
    errors: str | list[str] | dict[str, str | list[str]]


class SuccessResponse(Schema):
    message: str


###################################################
# Utils
###################################################
class WorkerInfo(Schema):
    name: str
    address: str
    nthreads: int = 1
    memory_limit: int = 0
    executing: int = 0


class TaskLogItem(Schema):
    task_id: str
    name: str
    status: str
    created_at: str
    updated_at: str
    result: str | None = None
    error: str | None = None


class LiveDaskTask(Schema):
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
    running: int = 0
    queued: int = 0
    workers_count: int = 0
    workers: list[WorkerInfo] = []
    live_tasks: list[LiveDaskTask] = []
    recent_tasks: list[TaskLogItem] = []


###################################################
# Users
###################################################
class GroupSchema(ModelSchema):
    class Meta:
        model = Group
        fields = ["id", "name"]


class UserOutSchema(ModelSchema):
    groups: list[GroupSchema] = []
    role: str | None = "Analyst"

    class Meta:
        model = get_user_model()
        fields = ["id", "username", "first_name", "last_name"]

    @staticmethod
    def resolve_role(obj):
        from orochi.website.roles import get_user_role

        return get_user_role(obj)


class UserInSchema(ModelSchema):
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
    plugin_url: str
    operating_system: OSEnum


class PluginParametersOutSchema(Schema):
    optional: bool
    name: str
    mode: str
    type: str
    choices: list[str] | None = None


###################################################
# Folder
###################################################
class FolderSchema(ModelSchema):
    class Meta:
        model = Folder
        fields = ["name"]


class FolderFullSchema(ModelSchema):
    user: UserOutSchema = None

    class Meta:
        model = Folder
        fields = ["name"]


###################################################
# Host
###################################################
class HostSchema(ModelSchema):
    class Meta:
        model = Host
        fields = ["name"]


class HostFullSchema(ModelSchema):
    description: str | None = None

    class Meta:
        model = Host
        fields = ["id", "name", "description"]


###################################################
# Case
###################################################
class CaseSchema(ModelSchema):
    class Meta:
        model = Case
        fields = ["name"]


class CaseFullSchema(ModelSchema):
    description: str | None = None
    status: str | None = None
    is_ctf: bool | None = False
    collaborators: list[int] | None = None

    class Meta:
        model = Case
        fields = ["id", "name", "description", "status", "is_ctf"]

    @staticmethod
    def resolve_collaborators(obj):
        return [c.pk for c in obj.collaborators.all()]


class CaseUpdateSchema(Schema):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    collaborators: list[int] | None = None
    is_ctf: bool | None = None


###################################################
# Dump
###################################################
def normalize_name_or_obj(v):
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
    folder: str | dict | int | None = None
    host: str | dict | int | None = None
    local_folder: str | None = None
    password: str | None = None
    original_name: str | None = None

    @field_validator("folder", "host", mode="before")
    @classmethod
    def parse_name_or_obj(cls, v):
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
    folder: str | dict | int | None = None
    host: str | dict | int | None = None
    authorized_users: list[int] | None = None

    @field_validator("folder", "host", mode="before")
    @classmethod
    def parse_name_or_obj(cls, v):
        return normalize_name_or_obj(v)

    class Meta:
        model = Dump
        fields = ["comment", "name", "color", "status"]


class DumpSchema(ModelSchema):
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
    plugin: str = None
    hive: str = None
    data: dict | list[dict] = None


class DumpInfoSchema(ModelSchema):
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
    name: str = Field(..., alias="plugin__name")
    comment: str | None = Field(..., alias="plugin__comment")
    id: int = Field(..., alias="plugin__id")
    min_role: str | None = "Analyst"
    can_execute: bool | None = True


###################################################
# Bookmarks
###################################################
class BookmarksEditInSchema(ModelSchema):
    class Meta:
        model = Bookmark
        fields = ["name", "icon", "query"]


class BookmarksSchema(ModelSchema):
    user: UserOutSchema = None
    indexes: list[DumpSchema] = []

    class Meta:
        model = Bookmark
        fields = ["id", "name", "icon", "star", "query"]


class BookmarksInSchema(Schema):
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
    class Meta:
        model = get_user_model()
        fields = ["username"]


class RuleData(Schema):
    id: int
    name: str
    path: str
    user: str
    public: bool
    default: bool


class CustomRuleEditInSchema(ModelSchema):
    class Meta:
        model = CustomRule
        fields = ["public"]


class CustomRulePagination(PaginationBase):
    class Input(Schema):
        start: int
        length: int

    class Output(Schema):
        draw: int
        recordsTotal: int
        recordsFiltered: int
        data: list[RuleData]

    items_attribute: str = "data"

    def paginate_queryset(self, queryset, pagination: Input, **params):
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
    rule_ids: list[int]
    rulename: str


class RulesOutSchema(ModelSchema):
    class Meta:
        model = Rule
        fields = ["id", "path", "enabled", "compiled", "ruleset", "created", "updated"]


class ListStr(Schema):
    rule_ids: list[int]


class ListStrAction(Schema):
    rule_ids: list[int]
    action: RULE_ACTION


class RuleEditInSchena(Schema):
    text: str


class RuleOut(Schema):
    id: int
    ruleset_name: str
    ruleset_description: str | None = None
    path_name: str
    headline: str | None = None


###################################################
# Datatables
###################################################
class TableFilter(Schema):
    search: str = None
    order_column: int = 1
    order_dir: str = Field("asc", pattern="^(asc|desc)$")


class RulePagination(PaginationBase):
    class Input(Schema):
        start: int
        length: int

    class Output(Schema):
        draw: int
        recordsTotal: int
        recordsFiltered: int
        data: list[RuleOut]

    items_attribute: str = "data"

    def paginate_queryset(self, queryset, pagination: Input, **params):
        request = params["request"]
        return {
            "draw": request.draw,
            "recordsTotal": request.total,
            "recordsFiltered": queryset.count(),
            "data": [
                RuleOut(
                    **{
                        "id": x.pk,
                        "ruleset_name": x.ruleset.name,
                        "ruleset_description": x.ruleset.description,
                        "path_name": Path(x.path).name,
                        "headline": x.headline if request.search else "",
                    }
                )
                for x in queryset[pagination.start : pagination.start + pagination.length]
            ],
        }


###################################################
# Symbols
###################################################
class SymbolsBannerIn(Schema):
    path: list[str] = []
    index: str
    operating_system: OSEnum
    banner: str = None


class UploadFileInfo(Schema):
    original_name: str | None = None
    local_folder: str | None = None


class UploadFileIn(Schema):
    info: list[UploadFileInfo] | None = []


class ISFIn(Schema):
    path: str


class SymbolsOut(Schema):
    id: str
    path: str
    action: tuple[str, str]


class CustomSymbolsPagination(PaginationBase):
    class Input(Schema):
        start: int
        length: int

    class Output(Schema):
        draw: int
        recordsTotal: int
        recordsFiltered: int
        data: list[SymbolsOut]

    items_attribute: str = "data"

    def paginate_queryset(self, queryset, pagination: Input, **params):
        request = params["request"]
        return {
            "draw": request.draw,
            "recordsTotal": request.total,
            "recordsFiltered": len(queryset),
            "data": [
                SymbolsOut(**{"id": x.id, "path": x.path, "action": x.action})
                for x in queryset[pagination.start : pagination.start + pagination.length]
            ],
        }


###################################################
# Value Annotations
###################################################
class ValueAnnotationIn(Schema):
    status: str = "comment"
    comment: str


class ValueAnnotationOut(Schema):
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
    dump_index: str
    dump_name: str
    risk_score: int
    risk_level: str
    total_findings: int
    severity_counts: dict[str, int]
    mitre_techniques: list[str]
    findings: list[TriageFindingOut]


class PromoteFindingIn(Schema):
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
    severity: str
    rule_name: str
    mitre: str | None = None
    entity: str | None = None


class TimelineEventOut(Schema):
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
    key: str
    name: str
    count: int
    icon: str
    color: str
    badge_bg: str
    badge_text: str
    border: str


class TimelineStatsOut(Schema):
    total_events: int
    earliest_date: str | None = None
    latest_date: str | None = None
    timespan_display: str
    categories_count: int
    max_density: int
    threat_count: int | None = 0


class TimelineReportOut(Schema):
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
