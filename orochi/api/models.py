from datetime import datetime
from typing import Dict, List, Optional

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from ninja import ModelSchema, Schema
from ninja.orm import create_schema

from orochi.website.models import Dump, Folder, Plugin, Result

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
            "yara_check",
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
            "yara_check",
            "maxmind_check",
            "local",
            "local_date",
        ]


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
class DumpSchema(ModelSchema):

    folder: Optional[FolderSchema] = None

    class Meta:
        model = Dump
        fields = [
            "index",
            "name",
            "color",
            "operating_system",
            "author",
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
# Result
###################################################
class PluginSmallSchema(ModelSchema):
    class Meta:
        model = Plugin
        fields = ["name", "comment"]


class DumpSmallSchema(ModelSchema):
    class Meta:
        model = Dump
        fields = ["index", "name"]


class ResultSmallOutSchema(ModelSchema):
    plugin: PluginSmallSchema = None
    dump: DumpSmallSchema = None
    updated_at: datetime = None

    class Meta:
        model = Result
        fields = ["result", "parameter", "description"]
