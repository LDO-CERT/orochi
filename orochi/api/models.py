from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from ninja import Field, ModelSchema, Schema
from ninja.orm import create_schema
from ninja.pagination import PaginationBase

from orochi.website.defaults import OSEnum
from orochi.website.models import Bookmark, CustomRule, Dump, Folder, Plugin
from orochi.ya.models import Rule


class RULE_ACTION(str, Enum):
    PUBLISH = "Publish"
    UNPUBLISH = "Unpublish"


###################################################
# Auth
###################################################
UsernameSchemaMixin = create_schema(
    get_user_model(), fields=[get_user_model().USERNAME_FIELD]
)

EmailSchemaMixin = create_schema(
    get_user_model(), fields=[get_user_model().EMAIL_FIELD]
)


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
    errors: str | List[str] | Dict[str, str | List[str]]


class SuccessResponse(Schema):
    message: str


###################################################
# Utils
###################################################
class DaskStatusOut(Schema):
    running: int = 0


###################################################
# Users
###################################################
class GroupSchema(ModelSchema):
    class Meta:
        model = Group
        fields = ["id", "name"]


class UserOutSchema(ModelSchema):
    groups: List[GroupSchema] = []

    class Meta:
        model = get_user_model()
        fields = ["id", "username", "first_name", "last_name"]


class UserInSchema(ModelSchema):
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
        ]


class PluginInstallSchema(Schema):
    plugin_url: str
    operating_system: OSEnum


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
# Dump
###################################################
class DumpIn(ModelSchema):
    folder: Optional[FolderSchema] = None
    local_folder: Optional[str] = None
    password: Optional[str] = None
    original_name: Optional[str] = None

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
    folder: Optional[FolderSchema] = None
    authorized_users: Optional[List[int]] = None

    class Meta:
        model = Dump
        fields = ["comment", "name", "color", "status"]


class DumpSchema(ModelSchema):
    folder: Optional[FolderSchema] = None
    author: UserOutSchema = None

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
    data: dict | List[dict] = None


class DumpInfoSchema(ModelSchema):
    folder: Optional[FolderSchema] = None
    regipy_plugins: Optional[List[RegipyPluginSchema]] = None
    suggested_symbols_path: Optional[List[str]] = None
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
    comment: Optional[str] = Field(..., alias="plugin__comment")
    id: int = Field(..., alias="plugin__id")


###################################################
# Bookmarks
###################################################
class BookmarksEditInSchema(ModelSchema):

    class Meta:
        model = Bookmark
        fields = ["name", "icon", "query"]


class BookmarksSchema(ModelSchema):
    user: UserOutSchema = None
    indexes: List[DumpSchema] = []

    class Meta:
        model = Bookmark
        fields = ["id", "name", "icon", "star", "query"]


class BookmarksInSchema(Schema):
    selected_indexes: str = None
    name: str = None
    star: bool = False
    icon: str = None
    selected_plugin: str = None
    query: Optional[str] = None


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
        data: List[RuleData]

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
                for x in queryset[
                    pagination.start : pagination.start + pagination.length
                ]
            ],
        }


###################################################
# Rules
###################################################
class RuleBuildSchema(Schema):
    rule_ids: List[int]
    rulename: str


class RulesOutSchema(ModelSchema):
    class Meta:
        model = Rule
        fields = ["id", "path", "enabled", "compiled", "ruleset", "created", "updated"]


class ListStr(Schema):
    rule_ids: List[int]


class ListStrAction(Schema):
    rule_ids: List[int]
    action: RULE_ACTION


class RuleEditInSchena(Schema):
    text: str


class RuleOut(Schema):
    id: int
    ruleset_name: str
    ruleset_description: str
    path_name: str
    headline: Optional[str] = None


class RuleFilter(Schema):
    search: str = None
    order_column: int = 1
    order_dir: str = Field("asc", pattern="^(asc|desc)$")


class CustomPagination(PaginationBase):
    class Input(Schema):
        start: int
        length: int

    class Output(Schema):
        draw: int
        recordsTotal: int
        recordsFiltered: int
        data: List[RuleOut]

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
                for x in queryset[
                    pagination.start : pagination.start + pagination.length
                ]
            ],
        }


###################################################
# Symbols
###################################################


class SymbolsBannerIn(Schema):
    path: List[str] = []
    index: str
    operating_system: OSEnum
    banner: str = None


class UploadFileInfo(Schema):
    original_name: Optional[str] = None
    local_folder: Optional[str] = None


class UploadFileIn(Schema):
    info: Optional[List[UploadFileInfo]] = []


class ISFIn(Schema):
    path: str
