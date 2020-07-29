from django.contrib import admin
from django.contrib.auth.models import Group
from guardian.admin import GuardedModelAdmin

from .models import Dump, Plugin, ExtractedDump


class PluginInline(admin.TabularInline):
    model = Dump.plugins.through
    extra = 0


class DumpAdmin(GuardedModelAdmin):
    list_display = ("name", "author", "index", "status")
    search_fields = ["author", "name", "index"]
    list_filter = ("author", "status", "created_at")
    inlines = [
        PluginInline,
    ]


class PluginAdmin(admin.ModelAdmin):

    actions = ["enable", "disable"]

    def enable(self, request, queryset):
        for item in queryset:
            item.disabled = False
            item.save()

    def disable(self, request, queryset):
        for item in queryset:
            item.disabled = True
            item.save()

    enable.short_description = "Enable selected plugins"
    disable.short_description = "Disable selected plugins"

    list_display = ("name", "operating_system", "disabled")
    list_filter = ("operating_system", "disabled")
    search_fields = ["name"]


class ExtractedDumpAdmin(admin.ModelAdmin):
    list_display = ("result", "sha256", "path", "clamav")
    list_filter = ("clamav",)


admin.site.register(Plugin, PluginAdmin)
admin.site.register(Dump, DumpAdmin)
admin.site.register(ExtractedDump, ExtractedDumpAdmin)

admin.site.unregister(Group)

admin.site.site_header = "Orochi Admin"
admin.site.site_title = "Orochi Admin Portal"
admin.site.index_title = "Welcome to Orochi"
