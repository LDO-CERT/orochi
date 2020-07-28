from django.contrib import admin
from guardian.admin import GuardedModelAdmin

from .models import Dump, Plugin, ExtractedDump


class PluginInline(admin.TabularInline):
    model = Dump.plugins.through


class DumpAdmin(GuardedModelAdmin):
    list_display = ("name", "author", "index", "status")
    search_fields = ["author", "name", "index"]
    list_filter = ("author", "status", "created_at")
    inlines = [
        PluginInline,
    ]


class PluginAdmin(admin.ModelAdmin):
    list_display = ("name", "operating_system", "disabled")
    list_filter = ("operating_system", "disabled")


class ExtractedDumpAdmin(admin.ModelAdmin):
    list_display = ("result", "sha256", "path", "clamav")
    list_filter = ("clamav",)


admin.site.register(Plugin, PluginAdmin)
admin.site.register(Dump, DumpAdmin)
admin.site.register(ExtractedDump, ExtractedDumpAdmin)
