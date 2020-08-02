from django import forms
from .models import Dump
from django_file_form.forms import FileFormMixin, UploadedFileField


class DumpForm(FileFormMixin, forms.ModelForm):
    upload = UploadedFileField()

    class Meta:
        model = Dump
        fields = ("upload", "name", "operating_system", "color")


class EditDumpForm(forms.ModelForm):
    class Meta:
        model = Dump
        fields = ("name", "operating_system", "color", "index")
        widgets = {"index": forms.HiddenInput()}


class ParametersForm(forms.Form):

    plugin = forms.CharField(widget=forms.HiddenInput())
    name = forms.CharField(widget=forms.HiddenInput())
    index = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        dynamic_fields = kwargs.pop("dynamic_fields")
        super(ParametersForm, self).__init__(*args, **kwargs)
        if dynamic_fields:
            for field in dynamic_fields:
                if field["mode"] == "single":
                    if field["type"] == str:
                        self.fields[field["name"]] = forms.CharField(
                            required=not field["optional"]
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
                    print("NOT IMPLEMENTED YET")
