import contextlib
import json
from datetime import datetime

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.postgres.forms import SimpleArrayField
from django.db.models import Q
from django.forms.widgets import CheckboxInput
from django.utils.translation import gettext_lazy as _
from django_file_form.forms import (
    FileFormMixin,
    MultipleUploadedFileField,
    UploadedFileField,
)
from import_export.forms import ExportForm

from orochi.utils.plugin_install import plugin_install
from orochi.website.defaults import (
    DUMP_STATUS_MISSING_SYMBOLS,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
)
from orochi.website.models import (
    Bookmark,
    Case,
    Dump,
    Evidence,
    Finding,
    Folder,
    Host,
    Plugin,
    Result,
    UserPlugin,
)


class SelectDumpExportForm(ExportForm):
    dump = forms.ModelMultipleChoiceField(
        widget=forms.CheckboxSelectMultiple,
        queryset=Dump.objects.all(),
    )


class FolderForm(forms.ModelForm):
    class Meta:
        model = Folder
        fields = ("name",)


######################################
# CASES / EVIDENCE
######################################
class CaseForm(forms.ModelForm):
    status = forms.ChoiceField(
        choices=Case.STATUS_CHOICES,
        required=False,
        initial=Case.STATUS_OPEN,
    )
    collaborators = forms.ModelMultipleChoiceField(
        queryset=get_user_model().objects.none(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        help_text=_("Select team members to collaborate on this case."),
    )

    class Meta:
        model = Case
        fields = ("name", "description", "status", "collaborators", "folder", "is_ctf")

    def __init__(self, current_user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_user = current_user
        exclude_pks = {self.current_user.pk}
        if self.instance and self.instance.pk and self.instance.user:
            exclude_pks.add(self.instance.user.pk)
        self.fields["collaborators"].queryset = (
            get_user_model()
            .objects.filter(is_active=True)
            .exclude(pk__in=exclude_pks)
            .exclude(username="AnonymousUser")
            .order_by("username")
        )
        self.fields["folder"] = forms.CharField(
            required=False,
            widget=forms.TextInput(
                attrs={"list": "folders_list", "autocomplete": "off"}
            ),
        )
        if self.instance and self.instance.pk:
            if self.instance.folder:
                self.initial["folder"] = self.instance.folder.name
            if self.instance.status:
                self.initial["status"] = self.instance.status
            self.initial["collaborators"] = self.instance.collaborators.all()

    def clean_folder(self):
        if folder_name := self.cleaned_data.get("folder"):
            folder, _ = Folder.objects.get_or_create(
                name=folder_name, user=self.current_user
            )
            return folder
        return None

    def get_folders(self):
        return Folder.objects.filter(user=self.current_user)


class DumpChoiceField(forms.ModelChoiceField):
    def to_python(self, value):
        if value in self.empty_values:
            return None
        if isinstance(value, self.queryset.model):
            return value
        try:
            key = self.to_field_name or "pk"
            val_str = str(value).strip()
            if val_str.isdigit():
                return self.queryset.get(**{key: int(val_str)})
            else:
                return self.queryset.get(index=val_str)
        except (ValueError, TypeError, self.queryset.model.DoesNotExist) as e:
            raise forms.ValidationError(
                self.error_messages["invalid_choice"],
                code="invalid_choice",
                params={"value": value},
            ) from e

    def prepare_value(self, value):
        return value.pk if hasattr(value, "_meta") else value


class EvidenceForm(forms.ModelForm):
    dump = DumpChoiceField(
        queryset=Dump.objects.all(),
        required=False,
        widget=forms.HiddenInput(),
    )

    class Meta:
        model = Evidence
        fields = (
            "name",
            "description",
            "case",
            "dump",
            "plugin",
            "result_row",
            "extracted_file",
        )
        widgets = {
            "dump": forms.HiddenInput(),
            "plugin": forms.HiddenInput(),
            "result_row": forms.HiddenInput(),
            "extracted_file": forms.HiddenInput(),
        }

    def __init__(self, current_user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_user = current_user
        self.fields["case"] = forms.CharField(
            required=True,
            widget=forms.TextInput(
                attrs={
                    "list": "cases_datalist",
                    "autocomplete": "off",
                    "placeholder": "Pick existing case or enter new case name",
                }
            ),
        )
        self.fields["dump"] = DumpChoiceField(
            queryset=Dump.objects.all(),
            required=False,
            widget=forms.HiddenInput(),
        )

        if self.instance and self.instance.pk and self.instance.case:
            self.initial["case"] = self.instance.case.name
        elif "case" in self.initial and self.initial["case"]:
            c_val = self.initial["case"]
            if isinstance(c_val, Case):
                self.initial["case"] = c_val.name
            elif str(c_val).isdigit():
                if c_obj := Case.objects.filter(
                    Q(user=current_user) | Q(collaborators=current_user),
                    pk=int(c_val),
                ).first():
                    self.initial["case"] = c_obj.name

    def clean_case(self):
        case_val = self.cleaned_data.get("case")
        if not case_val:
            raise forms.ValidationError("Case is required.")
        if isinstance(case_val, Case):
            return case_val
        val_str = str(case_val).strip()
        if not val_str:
            raise forms.ValidationError("Case is required.")

        # 1. Try finding case by pk if numeric
        if val_str.isdigit():
            case_obj = Case.objects.filter(
                Q(user=self.current_user) | Q(collaborators=self.current_user),
                pk=int(val_str),
            ).first()
            if case_obj:
                return case_obj

        # 2. Try finding case by name
        case_obj = Case.objects.filter(
            Q(user=self.current_user) | Q(collaborators=self.current_user),
            name=val_str,
        ).first()
        if case_obj:
            return case_obj

        # 3. If not found, create new case for current_user
        case_obj, _ = Case.objects.get_or_create(name=val_str, user=self.current_user)
        return case_obj

    def get_cases(self):
        return (
            Case.objects.filter(
                Q(user=self.current_user) | Q(collaborators=self.current_user)
            )
            .distinct()
            .order_by("name")
        )

    def clean_result_row(self):
        data = self.cleaned_data.get("result_row")
        if isinstance(data, str):
            with contextlib.suppress(Exception):
                return json.loads(data)
        return data

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get("name") or not str(cleaned_data.get("name")).strip():
            plugin = cleaned_data.get("plugin") or "Artifact"
            dump = cleaned_data.get("dump")
            result_row = cleaned_data.get("result_row") or {}
            identifier = ""
            if isinstance(result_row, dict):
                for k in (
                    "ImageFileName",
                    "Name",
                    "PID",
                    "Process",
                    "Path",
                    "Offset",
                    "Command",
                ):
                    if k in result_row and result_row[k]:
                        identifier = f" {k}:{result_row[k]}"
                        break
            dump_str = f" ({dump.name})" if dump else ""
            cleaned_data["name"] = f"[{plugin}]{identifier}{dump_str}"[:250]
        return cleaned_data


class FindingForm(forms.ModelForm):
    class Meta:
        model = Finding
        fields = (
            "severity",
            "tags",
            "note",
            "mitre_attack_technique",
            "evidence",
            "case",
        )
        widgets = {
            "evidence": forms.HiddenInput(),
            "case": forms.HiddenInput(),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["tags"].widget = forms.TextInput(
            attrs={"placeholder": "Comma-separated tags"}
        )
        self.fields["mitre_attack_technique"].widget = forms.TextInput(
            attrs={
                "placeholder": "e.g. T1055, T1059.001",
                "list": "mitre-techniques-list",
            }
        )
        self.fields["mitre_attack_technique"].label = "MITRE ATT&CK Technique(s)"
        self.fields["mitre_attack_technique"].help_text = (
            "Select or enter technique IDs (e.g. T1055, T1059.001)"
        )


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

    class Meta:
        model = Dump
        fields = (
            "upload",
            "local_folder",
            "name",
            "folder",
            "host",
            "operating_system",
            "comment",
            "password",
            "color",
        )

    def __init__(self, current_user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_user = current_user
        self.fields["folder"] = forms.CharField(
            required=False,
            widget=forms.TextInput(
                attrs={"list": "folders_list", "autocomplete": "off"}
            ),
        )
        self.fields["host"] = forms.CharField(
            required=False,
            widget=forms.TextInput(attrs={"list": "hosts_list", "autocomplete": "off"}),
        )
        self.fields["local_folder"] = forms.FilePathField(
            path=settings.LOCAL_UPLOAD_PATH, required=False, recursive=True
        )

        if self.instance and self.instance.pk:
            if self.instance.folder:
                self.initial["folder"] = self.instance.folder.name
            if self.instance.host:
                self.initial["host"] = self.instance.host.name

    def clean_folder(self):
        if folder_name := self.cleaned_data.get("folder"):
            folder, _ = Folder.objects.get_or_create(
                name=folder_name, user=self.current_user
            )
            return folder
        return None

    def clean_host(self):
        if host_name := self.cleaned_data.get("host"):
            host, _ = Host.objects.get_or_create(name=host_name)
            return host
        return None

    def get_folders(self):
        return Folder.objects.filter(user=self.current_user)

    def get_hosts(self):
        return Host.objects.all()


class EditDumpForm(forms.ModelForm):
    authorized_users = forms.TypedMultipleChoiceField(
        required=False,
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super(EditDumpForm, self).__init__(*args, **kwargs)
        self.user = user
        self.fields["authorized_users"].choices = [
            (x.pk, x.username) for x in get_user_model().objects.exclude(pk=user.pk)
        ]
        self.fields["folder"] = forms.CharField(
            required=False,
            widget=forms.TextInput(
                attrs={"list": "folders_list", "autocomplete": "off"}
            ),
        )
        self.fields["host"] = forms.CharField(
            required=False,
            widget=forms.TextInput(attrs={"list": "hosts_list", "autocomplete": "off"}),
        )

        if self.instance and self.instance.pk:
            if self.instance.folder:
                self.initial["folder"] = self.instance.folder.name
            if self.instance.host:
                self.initial["host"] = self.instance.host.name

    def clean_folder(self):
        if folder_name := self.cleaned_data.get("folder"):
            folder, _ = Folder.objects.get_or_create(name=folder_name, user=self.user)
            return folder
        return None

    def clean_host(self):
        if host_name := self.cleaned_data.get("host"):
            host, _ = Host.objects.get_or_create(name=host_name)
            return host
        return None

    def get_folders(self):
        return Folder.objects.filter(user=self.user)

    def get_hosts(self):
        return Host.objects.all()

    class Meta:
        model = Dump
        fields = (
            "name",
            "folder",
            "host",
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
                    elif field["type"] == "str":
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
                    elif field["type"] == "int":
                        self.fields[field["name"]] = forms.IntegerField(
                            required=not field["optional"]
                        )
                    elif field["type"] == "bool":
                        self.fields[field["name"]] = forms.BooleanField(
                            required=not field["optional"]
                        )
                else:
                    self.fields[field["name"]] = forms.CharField(
                        required=not field["optional"],
                    )
                    self.fields[field["name"]].help_text = (
                        f"""List of '{field["type"]}' comma separated"""
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
# ADMIN USERLIST
######################################
class UserListForm(forms.Form):
    _selected_action = forms.CharField(widget=forms.MultipleHiddenInput)
    authorized_users = forms.TypedMultipleChoiceField(
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super(UserListForm, self).__init__(*args, **kwargs)
        self.fields["authorized_users"].choices = [
            (x.pk, x.username) for x in get_user_model().objects.all()
        ]


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
            "maxmind_check",
        ]

    def save(self, commit=True):
        plugin_zip = self.cleaned_data["plugin"]
        if plugin_names := plugin_install(plugin_zip.file.path):
            plugin_data = plugin_names[0]
            plugin_name, plugin_class = list(plugin_data.items())[0]
            plugin_obj = super(PluginCreateAdminForm, self).save(commit=commit)
            plugin_obj.comment = self.cleaned_data["comment"] or plugin_class.__doc__
            plugin_obj.name = plugin_name
            plugin_obj.local = True
            plugin_obj.local_date = datetime.now()
            plugin_obj.save()
            for user in get_user_model().objects.all():
                UserPlugin.objects.get_or_create(user=user, plugin__id=plugin_obj.id)
            for dump in Dump.objects.all():
                if plugin_obj.operating_system in [dump.operating_system, "Other"]:
                    Result.objects.update_or_create(
                        dump=dump,
                        plugin__id=plugin_obj.id,
                        defaults={
                            "result": (
                                RESULT_STATUS_NOT_STARTED
                                if dump.status != DUMP_STATUS_MISSING_SYMBOLS
                                else RESULT_STATUS_DISABLED
                            )
                        },
                    )
            self.save_m2m()
            return plugin_obj


class PluginEditAdminForm(FileFormMixin, forms.ModelForm):
    class Meta:
        model = Plugin
        fields = [
            "min_role",
            "disabled",
            "comment",
            "local_dump",
            "vt_check",
            "clamav_check",
            "regipy_check",
            "maxmind_check",
            "local",
        ]
