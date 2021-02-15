import re
from django import forms
from django.forms import widgets
from django.forms.widgets import CheckboxInput
from orochi.website.models import Bookmark, Dump, ExtractedDump
from django.contrib.auth import get_user_model
from django_file_form.forms import FileFormMixin, UploadedFileField


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


class SymbolForm(forms.ModelForm):
    path = forms.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super(SymbolForm, self).__init__(*args, **kwargs)
        self.fields["banner"].widget.attrs["readonly"] = True

    class Meta:
        model = Dump
        fields = ("index", "operating_system", "banner", "path")
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
