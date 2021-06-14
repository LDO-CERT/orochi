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


class EditRuleForm(forms.Form):
    text = forms.CharField(widget=forms.Textarea)
    pk = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super(EditRuleForm, self).__init__(*args, **kwargs)

    class Meta:
        fields = ("text", "pk")
