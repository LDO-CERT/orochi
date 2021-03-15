from django import forms
from django_file_form.forms import (
    FileFormMixin,
    MultipleUploadedFileField,
)


class RuleForm(FileFormMixin, forms.Form):
    rules = MultipleUploadedFileField(required=False)

    def __init__(self, *args, **kwargs):
        super(RuleForm, self).__init__(*args, **kwargs)

    class Meta:
        fields = ("rules",)
