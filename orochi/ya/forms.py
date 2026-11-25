from django import forms
from django_file_form.forms import FileFormMixin, MultipleUploadedFileField


class RuleForm(FileFormMixin, forms.Form):
    """Upload one or more YARA rule files."""

    rules = MultipleUploadedFileField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    class Meta:
        fields = ("rules",)


class EditRuleForm(forms.Form):
    """Edit the source of an existing YARA rule."""

    text = forms.CharField(widget=forms.Textarea)
    pk = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    class Meta:
        fields = ("text", "pk")
