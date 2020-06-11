from django import forms
from .models import Dump
from django_file_form.forms import FileFormMixin, UploadedFileField


class DumpForm(FileFormMixin, forms.ModelForm):
    upload = UploadedFileField()

    class Meta:
        model = Dump
        fields = ("upload", "name", "operating_system", "color")
