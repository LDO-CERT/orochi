from django import forms
from orochi.website.models import Dump
from django.contrib.auth import get_user_model
from django_file_form.forms import FileFormMixin, UploadedFileField


class DumpForm(FileFormMixin, forms.ModelForm):
    upload = UploadedFileField()

    class Meta:
        model = Dump
        fields = ("upload", "name", "operating_system", "color")


class EditDumpForm(forms.ModelForm):
    authorized_users = forms.TypedMultipleChoiceField(required=False,)

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super(EditDumpForm, self).__init__(*args, **kwargs)
        self.fields["authorized_users"].choices = [
            (x.pk, x.username) for x in get_user_model().objects.exclude(pk=user.pk)
        ]

    class Meta:
        model = Dump
        fields = ("name", "operating_system", "color", "index", "authorized_users")
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
                                choices=choices, required=not field["optional"],
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

