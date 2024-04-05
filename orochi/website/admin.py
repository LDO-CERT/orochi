from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from django.contrib import admin
from django.contrib.auth.models import Group
from django_admin_listfilter_dropdown.filters import RelatedDropdownFilter
from django_admin_multiple_choice_list_filter.list_filters import (
    MultipleChoiceListFilter,
)
from django_file_form.model_admin import FileFormAdmin
from django_file_form.models import TemporaryUploadedFile
from guardian.admin import GuardedModelAdmin

from orochi.website.defaults import RESULT
from orochi.website.forms import PluginCreateAdminForm, PluginEditAdminForm
from orochi.website.models import (
    Bookmark,
    CustomRule,
    Dump,
    Plugin,
    Result,
    Service,
    UserPlugin,
)


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
    exclude = ("suggested_symbols_path", "regipy_plugins", "banner")

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


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("get_name_display", "url")


@admin.register(Plugin)
class PluginAdmin(FileFormAdmin):
    form = PluginEditAdminForm
    add_form = PluginCreateAdminForm

    list_display = ("name", "comment", "operating_system", "disabled", "local")
    list_filter = (
        "disabled",
        "operating_system",
        "local_dump",
        "vt_check",
        "clamav_check",
        "regipy_check",
        "local",
    )
    search_fields = ("name",)

    def get_form(self, request, obj=None, **kwargs):
        defaults = {}
        if obj is None:
            defaults["form"] = self.add_form
        defaults |= kwargs
        return super().get_form(request, obj, **defaults)


@admin.register(CustomRule)
class CustomRulePluginAdmin(admin.ModelAdmin):
    list_display = ("name", "path", "public", "user")
    list_filter = ("public", "user")
    search_fields = ("name",)


admin.site.unregister(Group)
admin.site.unregister(SocialAccount)
admin.site.unregister(SocialToken)
admin.site.unregister(SocialApp)
admin.site.unregister(TemporaryUploadedFile)

admin.site.site_header = "Orochi Admin"
admin.site.site_title = "Orochi Admin Portal"
admin.site.index_title = "Welcome to Orochi"
