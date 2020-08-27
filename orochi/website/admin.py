from django.contrib import admin
from django.contrib.auth.models import Group
from django.db import models
from guardian.admin import GuardedModelAdmin
from allauth.socialaccount.models import SocialAccount, SocialToken, SocialApp
from orochi.website.models import Dump, Plugin, ExtractedDump, UserPlugin, Service
from django_file_form.models import UploadedFile
from django_json_widget.widgets import JSONEditorWidget


class PluginInline(admin.TabularInline):
    model = Dump.plugins.through
    extra = 0


@admin.register(Dump)
class DumpAdmin(GuardedModelAdmin):
    list_display = ("name", "author", "index", "status")
    search_fields = ["author", "name", "index"]
    list_filter = ("author", "status", "created_at")
    inlines = [
        PluginInline,
    ]


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

    def get_queryset(self, request):
        qs = super(UserPluginAdmin, self).get_queryset(request)
        return qs.filter(user=request.user)

    enable.short_description = "Enable selected plugins"
    disable.short_description = "Disable selected plugins"

    list_display = (
        "user",
        "plugin",
        "automatic",
    )
    list_filter = ("plugin__operating_system", "automatic")
    search_fields = ["plugin__name"]


@admin.register(ExtractedDump)
class ExtractedDumpAdmin(admin.ModelAdmin):
    formfield_overrides = {
        models.JSONField: {"widget": JSONEditorWidget},
    }

    list_display = ("result", "sha256", "path")
    list_filter = ("clamav",)

    readonly_fields = (
        "result",
        "sha256",
        "clamav",
        "vt_score",
        "vt_report",
        "path",
    )


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("get_name_display", "url")


@admin.register(Plugin)
class PluginAdmin(admin.ModelAdmin):
    list_display = ("name", "operating_system", "disabled")
    list_filter = ("disabled", "operating_system")
    search_fields = ("name",)


admin.site.unregister(Group)
admin.site.unregister(SocialAccount)
admin.site.unregister(SocialToken)
admin.site.unregister(SocialApp)
admin.site.unregister(UploadedFile)

admin.site.site_header = "Orochi Admin"
admin.site.site_title = "Orochi Admin Portal"
admin.site.index_title = "Welcome to Orochi"
