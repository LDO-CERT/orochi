import yara_x
from django.contrib import admin

from orochi.ya.models import Rule, Ruleset


@admin.register(Ruleset)
class RulesetAdmin(admin.ModelAdmin):

    actions = ["enable", "disable"]

    def enable(self, request, queryset):
        for item in queryset:
            item.enabled = True
            item.save()

    def disable(self, request, queryset):
        for item in queryset:
            item.enabled = False
            item.save()

    enable.short_description = "Enable selected ruleset"
    disable.short_description = "Disable selected ruleset"

    list_display = ("name", "url", "count_rules", "description", "enabled")
    exclude = ("created", "updated", "user", "cloned")

    list_filter = (
        "enabled",
        "user__username",
    )
    search_fields = ["name", "description"]


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):

    actions = ["enable", "disable", "recompile"]

    def enable(self, request, queryset):
        for item in queryset:
            item.enabled = True
            item.save()

    def disable(self, request, queryset):
        for item in queryset:
            item.enabled = False
            item.save()

    def recompile(self, request, queryset):
        for item in queryset:
            compiled = False
            item.enabled = True
            item.error = None
            # TRY LOADING COMPILED, IF FAILS TRY LOAD
            try:
                _ = yara_x.Rules.deserialize_from(str(item.path))
                compiled = True
            except Exception:
                try:
                    with open(str(item.path), "r") as fp:
                        _ = yara_x.compile(fp.read())
                except Exception as e:
                    item.error = e
                    item.enabled = False
            item.compiled = compiled
            item.save()

    enable.short_description = "Enable selected rule(s)"
    disable.short_description = "Disable selected rule(s)"
    recompile.short_description = "Recompile selected rule(s)"

    list_display = ("ruleset", "path", "enabled")
    readonly_fields = ("created", "updated", "path", "compiled", "error")
    exclude = ("search_vector",)
    list_filter = ("enabled", "compiled", "ruleset__name")
    search_fields = ["path", "ruleset__name"]
