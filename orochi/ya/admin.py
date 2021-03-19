from django.contrib import admin
from orochi.ya.models import Ruleset, Rule


@admin.register(Ruleset)
class RulesetPluginAdmin(admin.ModelAdmin):

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

    list_display = ("name", "url", "count_rules", "description", "enabled", "user")
    readonly_fields = ("created", "updated")
    list_filter = (
        "enabled",
        "user__username",
    )
    search_fields = ["name", "description"]


@admin.register(Rule)
class RulePluginAdmin(admin.ModelAdmin):

    actions = ["enable", "disable"]

    def enable(self, request, queryset):
        for item in queryset:
            item.enabled = True
            item.save()

    def disable(self, request, queryset):
        for item in queryset:
            item.enabled = False
            item.save()

    enable.short_description = "Enable selected rule"
    disable.short_description = "Disable selected rule"

    list_display = ("ruleset", "path", "enabled")
    readonly_fields = ("created", "updated", "path", "compiled")
    list_filter = ("enabled", "compiled", "ruleset__name")
    search_fields = ["path", "ruleset__name"]