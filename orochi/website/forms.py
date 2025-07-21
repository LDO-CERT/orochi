from datetime import datetime

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.postgres.forms import SimpleArrayField
from django.forms.widgets import CheckboxInput
from django_file_form.forms import (
    FileFormMixin,
    MultipleUploadedFileField,
    UploadedFileField,
)
from import_export.forms import ExportForm

from orochi.utils.plugin_install import plugin_install
from orochi.website.defaults import (
    DUMP_STATUS_MISSING_SYMBOLS,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
)
from orochi.website.models import Bookmark, Dump, Folder, Plugin, Result, UserPlugin


######################################
# EXPORT
######################################
class SelectDumpExportForm(ExportForm):
    dump = forms.ModelMultipleChoiceField(
        widget=forms.CheckboxSelectMultiple,
        queryset=Dump.objects.all(),
    )


######################################
# FOLDERS
######################################
class FolderForm(forms.ModelForm):
    class Meta:
        model = Folder
        fields = ("name",)


######################################
# BOOKMARKS
######################################
class BookmarkForm(FileFormMixin, forms.ModelForm):
    selected_indexes = forms.CharField(widget=forms.HiddenInput(), required=False)
    selected_plugin = forms.CharField(widget=forms.HiddenInput(), required=False)
    query = forms.CharField(widget=forms.HiddenInput(), required=False)
    star = forms.BooleanField(
        widget=CheckboxInput(attrs={"class": "form-check-input"}), required=False
    )

    class Meta:
        model = Bookmark
        fields = (
            "icon",
            "name",
            "star",
            "selected_indexes",
            "selected_plugin",
            "query",
        )


class EditBookmarkForm(forms.ModelForm):

    class Meta:
        model = Bookmark
        fields = ("icon", "name", "query")


######################################
# DUMPS
######################################
class DumpForm(FileFormMixin, forms.ModelForm):
    upload = UploadedFileField(required=False)
    password = forms.CharField(required=False)
    local_folder = forms.FilePathField(
        path=settings.LOCAL_UPLOAD_PATH, required=False, recursive=True
    )

    class Meta:
        model = Dump
        fields = (
            "upload",
            "local_folder",
            "name",
            "folder",
            "operating_system",
            "comment",
            "password",
            "color",
        )

    def __init__(self, current_user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["folder"] = forms.ModelChoiceField(
            queryset=Folder.objects.filter(user=current_user), required=False
        )
        self.fields["local_folder"] = forms.FilePathField(
            path=settings.LOCAL_UPLOAD_PATH, required=False, recursive=True
        )


class EditDumpForm(forms.ModelForm):
    authorized_users = forms.TypedMultipleChoiceField(
        required=False,
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super(EditDumpForm, self).__init__(*args, **kwargs)
        self.fields["authorized_users"].choices = [
            (x.pk, x.username) for x in get_user_model().objects.exclude(pk=user.pk)
        ]
        self.fields["folder"] = forms.ModelChoiceField(
            queryset=Folder.objects.filter(user=user), required=False
        )

    class Meta:
        model = Dump
        fields = (
            "name",
            "folder",
            "color",
            "status",
            "comment",
            "index",
            "authorized_users",
        )
        widgets = {"index": forms.HiddenInput()}


######################################
# PLUGIN PARAMETERS
######################################
class ParametersForm(forms.Form):
    def __init__(self, *args, **kwargs):
        dynamic_fields = kwargs.pop("dynamic_fields")
        super(ParametersForm, self).__init__(*args, **kwargs)

        if dynamic_fields:
            for field in dynamic_fields:
                if field["mode"] == "single":
                    if field["type"] == "file":
                        self.fields[field["name"]] = forms.FileField(
                            required=not field["optional"]
                        )
                    elif field["type"] == "str":
                        if field.get("choices", None):
                            choices = [(None, "--")] if field["optional"] else []
                            choices += [(k, k) for k in field["choices"]]
                            self.fields[field["name"]] = forms.ChoiceField(
                                choices=choices,
                                required=not field["optional"],
                            )
                        else:
                            self.fields[field["name"]] = forms.CharField(
                                required=not field["optional"],
                            )
                    elif field["type"] == "int":
                        self.fields[field["name"]] = forms.IntegerField(
                            required=not field["optional"]
                        )
                    elif field["type"] == "bool":
                        self.fields[field["name"]] = forms.BooleanField(
                            required=not field["optional"]
                        )
                else:
                    self.fields[field["name"]] = forms.CharField(
                        required=not field["optional"],
                    )
                    self.fields[field["name"]].help_text = (
                        f"""List of '{field["type"]}' comma separated"""
                    )


######################################
# SYMBOLS MANAGEMENT
######################################
class SymbolISFForm(forms.Form):
    path = forms.CharField(required=True)


class SymbolPackageForm(FileFormMixin, forms.Form):
    packages = MultipleUploadedFileField(required=True)


class SymbolUploadForm(FileFormMixin, forms.Form):
    symbols = MultipleUploadedFileField(required=True)


class SymbolBannerForm(FileFormMixin, forms.ModelForm):
    path = SimpleArrayField(forms.CharField(required=False))

    def __init__(self, *args, **kwargs):
        super(SymbolBannerForm, self).__init__(*args, **kwargs)
        self.fields["banner"].widget.attrs["readonly"] = True

    class Meta:
        model = Dump
        fields = (
            "index",
            "operating_system",
            "banner",
            "path",
        )
        widgets = {
            "index": forms.HiddenInput(),
            "operating_system": forms.HiddenInput(),
        }


######################################
# ADMIN USERLIST
######################################
class UserListForm(forms.Form):
    _selected_action = forms.CharField(widget=forms.MultipleHiddenInput)
    authorized_users = forms.TypedMultipleChoiceField(
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super(UserListForm, self).__init__(*args, **kwargs)
        self.fields["authorized_users"].choices = [
            (x.pk, x.username) for x in get_user_model().objects.all()
        ]


######################################
# CREATE PLUGIN FROM ADMIN
######################################
class PluginCreateAdminForm(FileFormMixin, forms.ModelForm):
    plugin = UploadedFileField(required=True)

    class Meta:
        model = Plugin
        fields = [
            "plugin",
            "comment",
            "operating_system",
            "disabled",
            "local_dump",
            "vt_check",
            "clamav_check",
            "regipy_check",
            "maxmind_check",
        ]

    def save(self, commit=True):
        plugin_zip = self.cleaned_data["plugin"]
        if plugin_names := plugin_install(plugin_zip.file.path):
            plugin_data = plugin_names[0]
            plugin_name, plugin_class = list(plugin_data.items())[0]
            plugin_obj = super(PluginCreateAdminForm, self).save(commit=commit)
            plugin_obj.comment = self.cleaned_data["comment"] or plugin_class.__doc__
            plugin_obj.name = plugin_name
            plugin_obj.local = True
            plugin_obj.local_date = datetime.now()
            plugin_obj.save()
            for user in get_user_model().objects.all():
                UserPlugin.objects.get_or_create(user=user, plugin__id=plugin_obj.id)
            for dump in Dump.objects.all():
                if plugin_obj.operating_system in [dump.operating_system, "Other"]:
                    Result.objects.update_or_create(
                        dump=dump,
                        plugin__id=plugin_obj.id,
                        defaults={
                            "result": (
                                RESULT_STATUS_NOT_STARTED
                                if dump.status != DUMP_STATUS_MISSING_SYMBOLS
                                else RESULT_STATUS_DISABLED
                            )
                        },
                    )
            self.save_m2m()
            return plugin_obj


class PluginEditAdminForm(FileFormMixin, forms.ModelForm):
    class Meta:
        model = Plugin
        fields = [
            "disabled",
            "comment",
            "local_dump",
            "vt_check",
            "clamav_check",
            "regipy_check",
            "maxmind_check",
            "local",
        ]
