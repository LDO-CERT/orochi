from django.contrib import admin
from guardian.admin import GuardedModelAdmin

from .models import Analysis


class AnalysisAdmin(GuardedModelAdmin):
    list_display = ("name", "author", "index", "status")
    search_fields = ["author", "name", "index"]
    list_filter = ("author", "status", "created_at")


admin.site.register(Analysis, AnalysisAdmin)
