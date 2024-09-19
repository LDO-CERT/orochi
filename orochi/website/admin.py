from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db.models import JSONField
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django_admin_listfilter_dropdown.filters import RelatedDropdownFilter
from django_admin_multiple_choice_list_filter.list_filters import (
    MultipleChoiceListFilter,
)
from django_file_form.model_admin import FileFormAdmin
from django_file_form.models import TemporaryUploadedFile
from django_json_widget.widgets import JSONEditorWidget
from guardian.admin import GuardedModelAdminMixin
from guardian.shortcuts import assign_perm, get_perms, remove_perm
from import_export import fields, resources
from import_export.admin import ExportActionMixin, ImportExportModelAdmin
from import_export.mixins import BaseImportExportMixin
from import_export.widgets import ForeignKeyWidget

from orochi.website.defaults import RESULT
from orochi.website.forms import (
    PluginCreateAdminForm,
    PluginEditAdminForm,
    SelectDumpExportForm,
    UserListForm,
)
from orochi.website.models import (
    Bookmark,
    CustomRule,
    Dump,
    Plugin,
    Result,
    Service,
    UserPlugin,
    Value,
)


class ResultListFilter(MultipleChoiceListFilter):
    title = "Result"
    parameter_name = "result__in"

    def lookups(self, request, model_admin):
        return RESULT


@admin.register(Bookmark)
class BookmarkAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "get_indexes_names",
        "plugin",
        "query",
        "star",
        "user",
    )
    search_fields = ("indexes__name", "plugin__name", "user__username", "query")
    list_filter = (
        "star",
        ("plugin", RelatedDropdownFilter),
        ("user", RelatedDropdownFilter),
    )

    def get_indexes_names(self, obj):
        return ", ".join([p.name for p in obj.indexes.all()])


class ResultResource(resources.ModelResource):
    dump = fields.Field(
        column_name="dump",
        attribute="dump",
        widget=ForeignKeyWidget(Dump, field="name"),
    )

    plugin = fields.Field(
        column_name="plugin",
        attribute="plugin",
        widget=ForeignKeyWidget(Plugin, field="name"),
    )

    def __init__(self, **kwargs):
        super().__init__()
        self.dump_ids = kwargs.get("dump_ids")

    def filter_export(self, queryset, **kwargs):
        if self.dump_ids:
            return queryset.filter(dump__pk__in=self.dump_ids)
        return queryset.all()

    class Meta:
        model = Result
        import_id_fields = ("dump", "plugin")
        exclude = ("id",)


@admin.register(Result)
class ResultAdmin(ImportExportModelAdmin):
    list_display = ("dump", "plugin", "result")
    search_fields = ("dump__name", "plugin__name")
    resource_classes = [ResultResource]
    export_form_class = SelectDumpExportForm
    formfield_overrides = {
        JSONField: {"widget": JSONEditorWidget},
    }
    list_filter = (
        ("dump", RelatedDropdownFilter),
        ResultListFilter,
        "updated_at",
        ("plugin", RelatedDropdownFilter),
    )

    def get_export_resource_kwargs(self, request, **kwargs):
        if export_form := kwargs.get("export_form"):
            kwargs.update(dump_ids=export_form.cleaned_data["dump"])
        return kwargs


class ValueResource(resources.ModelResource):
    result = fields.Field(
        column_name="result",
        attribute="result",
        widget=ForeignKeyWidget(Result, use_natural_foreign_keys=True),
    )

    def __init__(self, **kwargs):
        super().__init__()
        self.dump_ids = kwargs.get("dump_ids")

    def filter_export(self, queryset, **kwargs):
        if self.dump_ids:
            return queryset.filter(result__dump__pk__in=self.dump_ids)
        return queryset.all()

    class Meta:
        model = Value
        import_id_fields = ("result", "value")
        exclude = ("id",)
        skip_diff = True
        use_bulk = True
        batch_size = 10000
        force_init_instance = True


@admin.register(Value)
class ValueAdmin(ImportExportModelAdmin):
    list_display = ("result__dump__name", "result__plugin__name")
    search_fields = ("result__dump__name", "result__plugin__name")
    resource_classes = [ValueResource]
    export_form_class = SelectDumpExportForm
    skip_import_confirm = True
    formfield_overrides = {
        JSONField: {"widget": JSONEditorWidget},
    }
    list_filter = (
        ("result__dump", RelatedDropdownFilter),
        ("result__plugin", RelatedDropdownFilter),
    )

    def get_export_resource_kwargs(self, request, **kwargs):
        if export_form := kwargs.get("export_form"):
            kwargs.update(dump_ids=export_form.cleaned_data["dump"])
        return kwargs


class AuthorWidget(ForeignKeyWidget):
    def clean(self, value, row=None, *args, **kwargs):
        return (
            get_user_model().objects.get_or_create(name=value)
            if value and value != ""
            else get_user_model().objects.first()
        )


class DumpResource(resources.ModelResource):
    author = fields.Field(
        column_name="author",
        attribute="author",
        widget=AuthorWidget(settings.AUTH_USER_MODEL, field="name"),
    )

    class Meta:
        model = Dump
        import_id_fields = ("name",)
        exclude = ("id", "plugins", "folder")


@admin.register(Dump)
class DumpAdmin(ImportExportModelAdmin, GuardedModelAdminMixin, ExportActionMixin):
    actions = ["assign_to_users", "remove_from_users"]
    list_display = ("name", "author", "index", "status", "get_auth_users")
    search_fields = ["author__name", "name", "index"]
    list_filter = ("author", "status", "created_at")
    exclude = ("suggested_symbols_path", "regipy_plugins", "banner")
    resource_classes = [DumpResource]

    def get_auth_users(self, obj):
        auth_users = [
            user.username
            for user in get_user_model().objects.all()
            if "can_see" in get_perms(user, obj)
        ]
        return ", ".join(auth_users)

    get_auth_users.short_description = "Authorized Users"

    def assign_to_users(self, request, queryset):
        if "apply" in request.POST:
            users = request.POST.getlist("authorized_users")
            for item in queryset:
                for user_pk in users:
                    user = get_user_model().objects.get(pk=user_pk)
                    assign_perm("can_see", user, item)
            self.message_user(
                request, f"{len(queryset)} dumps added to {len(users)} users"
            )
            return HttpResponseRedirect(request.get_full_path())
        form = UserListForm(
            initial={"_selected_action": queryset.values_list("id", flat=True)}
        )
        return render(
            request,
            "admin/dump_intermediate.html",
            context={
                "items": queryset,
                "form": form,
                "title": "Assign dumps to users",
                "action": "assign_to_users",
            },
        )

    def remove_from_users(self, request, queryset):
        if "apply" in request.POST:
            users = request.POST.getlist("authorized_users")
            for item in queryset:
                for user_pk in users:
                    user = get_user_model().objects.get(pk=user_pk)
                    remove_perm("can_see", user, item)
            self.message_user(
                request, f"{len(queryset)} dumps removed from {len(users)} users"
            )
            return HttpResponseRedirect(request.get_full_path())
        form = UserListForm(
            initial={"_selected_action": queryset.values_list("id", flat=True)}
        )
        return render(
            request,
            "admin/dump_intermediate.html",
            context={
                "items": queryset,
                "form": form,
                "title": "Remove dumps from users",
                "action": "remove_from_users",
            },
        )

    assign_to_users.short_description = "Assign dump to users"
    remove_from_users.short_description = "Remove dumps from users"

    def get_queryset(self, request):
        return super(DumpAdmin, self).get_queryset(request).prefetch_related("plugins")


@admin.register(UserPlugin)
class UserPluginAdmin(admin.ModelAdmin):
    actions = ["enable", "disable"]

    def enable(self, request, queryset):
        for item in queryset:
            item.automatic = False
            item.save()

    def disable(self, request, queryset):
        for item in queryset:
            item.automatic = True
            item.save()

    enable.short_description = "Enable selected plugins"
    disable.short_description = "Disable selected plugins"

    readonly_fields = (
        "user",
        "plugin",
    )

    list_display = (
        "user",
        "plugin",
        "automatic",
    )
    list_filter = (
        "plugin__operating_system",
        "automatic",
        "user__username",
        "plugin__name",
    )
    search_fields = ["plugin__name", "user__username"]


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("get_name_display", "url")


@admin.register(Plugin)
class PluginAdmin(FileFormAdmin):
    form = PluginEditAdminForm
    add_form = PluginCreateAdminForm

    list_display = ("name", "comment", "operating_system", "disabled", "local")
    list_filter = (
        "disabled",
        "operating_system",
        "local_dump",
        "vt_check",
        "clamav_check",
        "regipy_check",
        "local",
    )
    search_fields = ("name",)

    def get_form(self, request, obj=None, **kwargs):
        defaults = {}
        if obj is None:
            defaults["form"] = self.add_form
        defaults |= kwargs
        return super().get_form(request, obj, **defaults)


@admin.register(CustomRule)
class CustomRulePluginAdmin(admin.ModelAdmin):
    list_display = ("name", "path", "public", "default", "user")
    list_filter = ("public", "default", "user")
    search_fields = ("name",)


admin.site.unregister(Group)
admin.site.unregister(TemporaryUploadedFile)

admin.site.site_header = "Orochi Admin"
admin.site.site_title = "Orochi Admin Portal"
admin.site.index_title = "Welcome to Orochi"
