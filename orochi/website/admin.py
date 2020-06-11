from django.contrib import admin
from guardian.admin import GuardedModelAdmin

from .models import Dump, Plugin


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


admin.site.register(Plugin, PluginAdmin)
admin.site.register(Dump, DumpAdmin)
