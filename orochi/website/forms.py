import os
import re
import subprocess
import zipfile
import uuid
from pathlib import Path

import volatility3.plugins
from volatility3 import framework
from volatility3.framework import contexts

from django import forms
from django.forms.widgets import CheckboxInput
from orochi.website.models import Bookmark, Dump, ExtractedDump, Plugin
from django.contrib.auth import get_user_model
from django_file_form.forms import (
    FileFormMixin,
    UploadedFileField,
    MultipleUploadedFileField,
)
from django.conf import settings
from django.contrib.postgres.forms import SimpleArrayField
from distributed import get_client


class DumpForm(FileFormMixin, forms.ModelForm):
    upload = UploadedFileField()

    class Meta:
        model = Dump
        fields = ("upload", "name", "operating_system", "color")


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

    class Meta:
        model = Dump
        fields = ("name", "color", "index", "authorized_users")
        widgets = {"index": forms.HiddenInput()}


class ParametersForm(forms.Form):
    selected_plugin = forms.CharField(widget=forms.HiddenInput())
    selected_name = forms.CharField(widget=forms.HiddenInput())
    selected_index = forms.CharField(widget=forms.HiddenInput())

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
                    self.fields[
                        field["name"]
                    ].help_text = "List of '{}' comma separated".format(
                        field["type"].__name__
                    )


class SymbolForm(FileFormMixin, forms.ModelForm):
    METHODS = (
        (0, "Suggested path"),
        (1, "Upload linux packages"),
        (2, "Upload symbol"),
    )

    method = forms.IntegerField(label="Method", widget=forms.Select(choices=METHODS))
    path = SimpleArrayField(forms.CharField(required=False))
    packages = MultipleUploadedFileField(required=False)
    symbol = UploadedFileField(required=False)

    def __init__(self, *args, **kwargs):
        super(SymbolForm, self).__init__(*args, **kwargs)
        self.fields["banner"].widget.attrs["readonly"] = True

    class Meta:
        model = Dump
        fields = (
            "index",
            "operating_system",
            "banner",
            "method",
            "path",
            "packages",
            "symbol",
        )
        widgets = {
            "index": forms.HiddenInput(),
            "operating_system": forms.HiddenInput(),
        }


class MispExportForm(forms.ModelForm):
    selected_exdump = forms.CharField(widget=forms.HiddenInput())
    selected_index_name = forms.CharField()
    selected_plugin_name = forms.CharField()

    def __init__(self, *args, **kwargs):
        super(MispExportForm, self).__init__(*args, **kwargs)
        self.fields["path"].widget.attrs["readonly"] = True
        self.fields["sha256"].widget.attrs["readonly"] = True
        self.fields["clamav"].widget.attrs["readonly"] = True
        self.fields["vt_report"].widget.attrs["readonly"] = True
        self.fields["selected_index_name"].widget.attrs["readonly"] = True
        self.fields["selected_plugin_name"].widget.attrs["readonly"] = True

    class Meta:
        model = ExtractedDump
        fields = (
            "selected_exdump",
            "path",
            "selected_index_name",
            "selected_plugin_name",
            "sha256",
            "clamav",
            "vt_report",
        )


class PluginCreateAdminForm(FileFormMixin, forms.ModelForm):

    plugin = UploadedFileField(required=True)

    class Meta:
        model = Plugin
        fields = [
            "plugin",
            "operating_system",
            "disabled",
            "local_dump",
            "vt_check",
            "clamav_check",
            "regipy_check",
        ]

    def save(self, commit=True):
        plugin = self.cleaned_data["plugin"]

        bash_script = None
        reqs_script = False
        py_name = None

        plugin_folder = Path(settings.VOLATILITY_PLUGIN_PATH)
        tmp_folder = plugin_folder / str(uuid.uuid4())
        os.mkdir(tmp_folder)

        with zipfile.ZipFile(plugin.file.path, "r") as f:
            for name in f.namelist():
                if name.endswith(".sh"):
                    bash_script = f.read(name)
                elif name.lower() == "requirements.txt":
                    reqs_script = True
                    with open(tmp_folder / "requirements.txt", "wb") as reqs:
                        reqs.write(f.read(name))
                elif name.endswith(".py"):
                    with open(plugin_folder / name, "wb") as reqs:
                        reqs.write(f.read(name))
                    py_name = Path(name).stem

        if bash_script:
            os.system("apt update")
            os.system(bash_script)
        if reqs_script:
            os.system("pip install -r {}/requirements.txt".format(tmp_folder))

        _ = contexts.Context()
        _ = framework.import_files(volatility3.plugins, True)
        available_plugins = framework.list_plugins()

        for plugin in available_plugins:
            if plugin.startswith("custom.{}".format(py_name)):
                self.cleaned_data["name"] = plugin

        def install(bash_script, reqs_script, tmp_folder):
            if bash_script:
                os.system("apt update")
                os.system(bash_script)
            if reqs_script:
                os.system("pip install -r {}/requirements.txt".format(tmp_folder))
                os.system("rm -rf {}".format(tmp_folder))

        dask_client = get_client(address="tcp://scheduler:8786")
        dask_client.run(install, bash_script, reqs_script, tmp_folder)
        plugin = super(PluginCreateAdminForm, self).save(commit=commit)

        for available_plugin in available_plugins:
            if available_plugin.startswith("custom.{}".format(py_name)):
                plugin.name = available_plugin
                plugin.save()

        return plugin


class PluginEditAdminForm(FileFormMixin, forms.ModelForm):
    class Meta:
        model = Plugin
        fields = [
            "disabled",
            "local_dump",
            "vt_check",
            "clamav_check",
            "regipy_check",
        ]
