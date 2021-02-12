from django.contrib import admin
from django.contrib.auth.models import Group
from django.db import models
from guardian.admin import GuardedModelAdmin
from django_admin_listfilter_dropdown.filters import RelatedDropdownFilter
from django_admin_multiple_choice_list_filter.list_filters import (
    MultipleChoiceListFilter,
)
from allauth.socialaccount.models import SocialAccount, SocialToken, SocialApp

from orochi.website.models import (
    Bookmark,
    Dump,
    Plugin,
    ExtractedDump,
    UserPlugin,
    Service,
    Result,
    RESULT,
)

from django_file_form.models import TemporaryUploadedFile
from django_json_widget.widgets import JSONEditorWidget


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


@admin.register(Result)
class ResultAdmin(admin.ModelAdmin):
    list_display = ("dump", "plugin", "result")
    search_fields = ("dump__name", "plugin__name")
    list_filter = (
        "dump",
        ResultListFilter,
        "updated_at",
        ("plugin", RelatedDropdownFilter),
    )


@admin.register(Dump)
class DumpAdmin(GuardedModelAdmin):
    list_display = ("name", "author", "index", "status")
    search_fields = ["author__name", "name", "index"]
    list_filter = ("author", "status", "created_at")

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


@admin.register(ExtractedDump)
class ExtractedDumpAdmin(admin.ModelAdmin):
    formfield_overrides = {
        models.JSONField: {
            "widget": JSONEditorWidget(options={"mode": "view", "modes": ["view"]})
        },
    }

    list_display = ("result", "sha256", "path")
    list_filter = ("clamav",)
    search_fields = ("sha256",)

    readonly_fields = (
        "result",
        "sha256",
        "clamav",
        "vt_report",
        "path",
    )


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("get_name_display", "url")


@admin.register(Plugin)
class PluginAdmin(admin.ModelAdmin):
    list_display = ("name", "operating_system", "disabled")
    list_filter = (
        "disabled",
        "operating_system",
        "local_dump",
        "vt_check",
        "clamav_check",
        "regipy_check",
    )
    search_fields = ("name",)


admin.site.unregister(Group)
admin.site.unregister(SocialAccount)
admin.site.unregister(SocialToken)
admin.site.unregister(SocialApp)
admin.site.unregister(TemporaryUploadedFile)

admin.site.site_header = "Orochi Admin"
admin.site.site_title = "Orochi Admin Portal"
admin.site.index_title = "Welcome to Orochi"
