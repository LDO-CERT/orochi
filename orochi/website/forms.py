from django import forms
from .models import Analysis
from django_file_form.forms import FileFormMixin, UploadedFileField


class AnalysisForm(FileFormMixin, forms.ModelForm):
    upload = UploadedFileField()

    class Meta:
        model = Analysis
        fields = ("upload", "name", "operating_system", "color")
