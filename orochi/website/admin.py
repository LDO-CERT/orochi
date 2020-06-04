from django.contrib import admin
from guardian.admin import GuardedModelAdmin

from .models import Analysis, Plugin


class PluginInline(admin.TabularInline):
    model = Analysis.plugins.through


class AnalysisAdmin(GuardedModelAdmin):
    list_display = ("name", "author", "index", "status")
    search_fields = ["author", "name", "index"]
    list_filter = ("author", "status", "created_at")
    inlines = [
        PluginInline,
    ]


admin.site.register(Plugin)
admin.site.register(Analysis, AnalysisAdmin)
