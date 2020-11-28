from django.contrib import admin
from django.contrib.auth.models import Group
from django.db import models
from guardian.admin import GuardedModelAdmin
from allauth.socialaccount.models import SocialAccount, SocialToken, SocialApp
from django.contrib.sites.models import Site

from orochi.website.models import (
    Dump,
    Plugin,
    ExtractedDump,
    UserPlugin,
    Service,
    Result,
)

from django_file_form.models import TemporaryUploadedFile
from django_json_widget.widgets import JSONEditorWidget


@admin.register(Result)
class ResultAdmin(admin.ModelAdmin):
    list_display = ("dump", "plugin", "result")
    search_fields = ("dump", "plugin")
    list_filter = ("dump", "plugin", "result", "updated_at")


@admin.register(Dump)
class DumpAdmin(GuardedModelAdmin):
    list_display = ("name", "author", "index", "status")
    search_fields = ["author", "name", "index"]
    list_filter = ("author", "status", "missing_symbols", "created_at")
    readonly_fields = ("banner",)

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


# admin.site.unregister(Site)
admin.site.unregister(Group)
admin.site.unregister(SocialAccount)
admin.site.unregister(SocialToken)
admin.site.unregister(SocialApp)
admin.site.unregister(TemporaryUploadedFile)

admin.site.site_header = "Orochi Admin"
admin.site.site_title = "Orochi Admin Portal"
admin.site.index_title = "Welcome to Orochi"
