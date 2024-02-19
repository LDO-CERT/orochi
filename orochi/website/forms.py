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

from orochi.utils.plugin_install import plugin_install
from orochi.website.models import Bookmark, Dump, Folder, Plugin


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
    selected_bookmark = forms.CharField(widget=forms.HiddenInput())

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
    mode = forms.CharField(widget=forms.HiddenInput(), required=False, initial="upload")

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
            "mode",
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
    selected_plugin = forms.CharField(widget=forms.HiddenInput())
    selected_indexes = forms.CharField(widget=forms.HiddenInput())
    selected_names = forms.CharField(widget=forms.HiddenInput())

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
                    elif field["type"] == str:
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
                    elif field["type"] == int:
                        self.fields[field["name"]] = forms.IntegerField(
                            required=not field["optional"]
                        )
                    elif field["type"] == bool:
                        self.fields[field["name"]] = forms.BooleanField(
                            required=not field["optional"]
                        )
                else:
                    self.fields[field["name"]] = forms.CharField(
                        required=not field["optional"],
                    )
                    self.fields[field["name"]].help_text = (
                        "List of '{}' comma separated".format(field["type"].__name__)
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
        ]

    def save(self, commit=True):
        plugin = self.cleaned_data["plugin"]
        plugin_name = plugin_install(plugin.file.path)
        plugin = super(PluginCreateAdminForm, self).save(commit=commit)
        plugin.name = plugin_name
        plugin.local = True
        plugin.local_date = datetime.now()
        plugin.save()
        return plugin


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
        ]
