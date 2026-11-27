import contextlib
import json
from datetime import datetime

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.postgres.forms import SimpleArrayField
from django.forms.widgets import CheckboxInput
from django.utils.translation import gettext_lazy as _
from django_file_form.forms import (
    FileFormMixin,
    MultipleUploadedFileField,
    UploadedFileField,
)
from guardian.shortcuts import get_objects_for_user
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
    """Pick the dumps to export."""

    dump = forms.ModelMultipleChoiceField(
        widget=forms.CheckboxSelectMultiple,
        queryset=Dump.objects.all(),
    )


class FolderForm(forms.ModelForm):
    """Create a folder (name only)."""

    class Meta:
        model = Folder
        fields = ("name",)


######################################
# CASES / EVIDENCE
######################################
class CaseForm(forms.ModelForm):
    """Create or edit a case; the folder is typed by name and created for the user when new."""

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
            widget=forms.TextInput(attrs={"list": "folders_list", "autocomplete": "off"}),
        )
        if self.instance and self.instance.pk:
            if self.instance.folder:
                self.initial["folder"] = self.instance.folder.name
            if self.instance.status:
                self.initial["status"] = self.instance.status
            self.initial["collaborators"] = self.instance.collaborators.all()

    def clean_folder(self):
        """Return the user's folder with that name, creating it when missing."""
        if folder_name := self.cleaned_data.get("folder"):
            folder, _ = Folder.objects.get_or_create(name=folder_name, user=self.current_user)
            return folder
        return None

    def get_folders(self):
        """Folders of the current user, offered as suggestions."""
        return Folder.objects.filter(user=self.current_user)


class DumpChoiceField(forms.ModelChoiceField):
    """Dump selector accepting a primary key or a dump index."""

    def to_python(self, value):
        """Resolve the posted value as Dump instance, primary key or index; unknown values are invalid."""
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
        """Render a Dump as its primary key."""
        return value.pk if hasattr(value, "_meta") else value


class EvidenceForm(forms.ModelForm):
    """Save a plugin row or extracted file as Evidence of a case the user can access."""

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
        # Only dumps the user can see may be attached as evidence.
        self.fields["dump"] = DumpChoiceField(
            queryset=get_objects_for_user(current_user, "website.can_see", klass=Dump),
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
                if c_obj := Case.objects.visible_to(current_user).filter(pk=int(c_val)).first():
                    self.initial["case"] = c_obj.name

    def clean_case(self):
        """Resolve the case by primary key or name among the user's cases; an unknown name creates a new case."""
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
            case_obj = Case.objects.visible_to(self.current_user).filter(pk=int(val_str)).first()
            if case_obj:
                return case_obj

        # 2. Try finding case by name
        case_obj = Case.objects.visible_to(self.current_user).filter(name=val_str).first()
        if case_obj:
            return case_obj

        # 3. If not found, create new case for current_user
        case_obj, _ = Case.objects.get_or_create(name=val_str, user=self.current_user)
        return case_obj

    def get_cases(self):
        """Cases the user owns or collaborates on, by name."""
        return Case.objects.visible_to(self.current_user).order_by("name")

    def clean_result_row(self):
        """Accept the row as JSON text or as already parsed data."""
        data = self.cleaned_data.get("result_row")
        if isinstance(data, str):
            with contextlib.suppress(Exception):
                return json.loads(data)
        return data

    def clean(self):
        """Default the Evidence name to ``<plugin>: <identifier>`` (process, PID, path...) when left blank."""
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
    """Create or edit a Finding: severity, tags, note and MITRE ATT&CK technique."""

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
        self.fields["tags"].widget = forms.TextInput(attrs={"placeholder": "Comma-separated tags"})
        self.fields["mitre_attack_technique"].widget = forms.TextInput(
            attrs={
                "placeholder": "e.g. T1055, T1059.001",
                "list": "mitre-techniques-list",
            }
        )
        self.fields["mitre_attack_technique"].label = "MITRE ATT&CK Technique(s)"
        self.fields["mitre_attack_technique"].help_text = "Select or enter technique IDs (e.g. T1055, T1059.001)"


######################################
# BOOKMARKS
######################################
class BookmarkForm(FileFormMixin, forms.ModelForm):
    """Save the current plugin view (dumps, plugin, search query) as a bookmark."""

    selected_indexes = forms.CharField(widget=forms.HiddenInput(), required=False)
    selected_plugin = forms.CharField(widget=forms.HiddenInput(), required=False)
    query = forms.CharField(widget=forms.HiddenInput(), required=False)
    star = forms.BooleanField(widget=CheckboxInput(attrs={"class": "form-check-input"}), required=False)

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
    """Rename a bookmark or change its icon and query."""

    class Meta:
        model = Bookmark
        fields = ("icon", "name", "query")


######################################
# DUMPS
######################################
class DumpForm(FileFormMixin, forms.ModelForm):
    """Upload a memory dump (file, archive with password, or file from the local upload folder)."""

    upload = UploadedFileField(required=False)
    password = forms.CharField(required=False)
    local_folder = forms.FilePathField(
        path=settings.LOCAL_UPLOAD_PATH, required=False, recursive=True, label="Server file"
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
        widgets = {"comment": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, current_user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_user = current_user
        self.fields["folder"] = forms.CharField(
            required=False,
            widget=forms.TextInput(attrs={"list": "folders_list", "autocomplete": "off"}),
        )
        self.fields["host"] = forms.CharField(
            required=False,
            widget=forms.TextInput(attrs={"list": "hosts_list", "autocomplete": "off"}),
        )
        self.fields["local_folder"] = forms.FilePathField(
            path=settings.LOCAL_UPLOAD_PATH, required=False, recursive=True, label="Server file"
        )

        if self.instance and self.instance.pk:
            if self.instance.folder:
                self.initial["folder"] = self.instance.folder.name
            if self.instance.host:
                self.initial["host"] = self.instance.host.name

    def clean_folder(self):
        """Return the user's folder with that name, creating it when missing."""
        if folder_name := self.cleaned_data.get("folder"):
            folder, _ = Folder.objects.get_or_create(name=folder_name, user=self.current_user)
            return folder
        return None

    def clean_host(self):
        """Return the host with that name, creating it when missing."""
        if host_name := self.cleaned_data.get("host"):
            host, _ = Host.objects.get_or_create(name=host_name)
            return host
        return None

    def get_folders(self):
        """Folders of the current user, offered as suggestions."""
        return Folder.objects.filter(user=self.current_user)

    def get_hosts(self):
        """Known hosts, offered as suggestions."""
        return Host.objects.all()


class EditDumpForm(forms.ModelForm):
    """Edit dump metadata and the users allowed to see it."""

    authorized_users = forms.TypedMultipleChoiceField(
        required=False,
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        self.user = user
        self.fields["authorized_users"].choices = [
            (x.pk, x.username) for x in get_user_model().objects.exclude(pk=user.pk)
        ]
        self.fields["folder"] = forms.CharField(
            required=False,
            widget=forms.TextInput(attrs={"list": "folders_list", "autocomplete": "off"}),
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
        """Return the user's folder with that name, creating it when missing."""
        if folder_name := self.cleaned_data.get("folder"):
            folder, _ = Folder.objects.get_or_create(name=folder_name, user=self.user)
            return folder
        return None

    def clean_host(self):
        """Return the host with that name, creating it when missing."""
        if host_name := self.cleaned_data.get("host"):
            host, _ = Host.objects.get_or_create(name=host_name)
            return host
        return None

    def get_folders(self):
        """Folders of the current user, offered as suggestions."""
        return Folder.objects.filter(user=self.user)

    def get_hosts(self):
        """Known hosts, offered as suggestions."""
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
        widgets = {
            "index": forms.HiddenInput(),
            "comment": forms.Textarea(attrs={"rows": 3}),
        }


######################################
# PLUGIN PARAMETERS
######################################
class ParametersForm(forms.Form):
    """Plugin parameter form built at runtime from the plugin requirements (``dynamic_fields``)."""

    def __init__(self, *args, **kwargs):
        dynamic_fields = kwargs.pop("dynamic_fields")
        super().__init__(*args, **kwargs)

        if dynamic_fields:
            for field in dynamic_fields:
                if field["mode"] == "single":
                    if field["type"] == "file":
                        self.fields[field["name"]] = forms.FileField(required=not field["optional"])
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
                        self.fields[field["name"]] = forms.IntegerField(required=not field["optional"])
                    elif field["type"] == "bool":
                        self.fields[field["name"]] = forms.BooleanField(required=not field["optional"])
                else:
                    self.fields[field["name"]] = forms.CharField(
                        required=not field["optional"],
                    )
                    self.fields[field["name"]].help_text = f"""List of '{field["type"]}' comma separated"""


######################################
# SYMBOLS MANAGEMENT
######################################
class SymbolISFForm(forms.Form):
    """Download an ISF symbol file from a URL or path."""

    path = forms.CharField(required=True)


class SymbolPackageForm(FileFormMixin, forms.Form):
    """Upload Linux kernel packages to build symbols from."""

    packages = MultipleUploadedFileField(required=True)


class SymbolUploadForm(FileFormMixin, forms.Form):
    """Upload ready-made ISF symbol files."""

    symbols = MultipleUploadedFileField(required=True)


class SymbolBannerForm(FileFormMixin, forms.ModelForm):
    """Pick the symbol files matching a dump banner."""

    path = SimpleArrayField(forms.CharField(required=False))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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
    """Admin action form choosing the users allowed to see the selected dumps."""

    _selected_action = forms.CharField(widget=forms.MultipleHiddenInput)
    authorized_users = forms.TypedMultipleChoiceField(
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["authorized_users"].choices = [(x.pk, x.username) for x in get_user_model().objects.all()]


######################################
# CREATE PLUGIN FROM ADMIN
######################################
class PluginCreateAdminForm(FileFormMixin, forms.ModelForm):
    """Admin form installing custom Volatility plugins from a ``.zip`` archive."""

    plugin = UploadedFileField(
        required=True,
        help_text="Upload a .zip archive containing one or more Volatility 3 Python plugin (.py) files.",
    )

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

    def clean_plugin(self):
        """Validate and install the uploaded archive, remembering the installed plugin names."""
        plugin_zip = self.cleaned_data.get("plugin")
        if not plugin_zip:
            raise forms.ValidationError("A .zip plugin archive is required.")
        file_path = getattr(getattr(plugin_zip, "file", None), "path", None) or getattr(plugin_zip, "path", None)
        filename = getattr(plugin_zip, "name", "") or ""
        if not filename.lower().endswith(".zip"):
            raise forms.ValidationError("Plugin archive must be a .zip file containing Volatility 3 .py plugins.")
        if not file_path:
            raise forms.ValidationError("Uploaded plugin file could not be read from temporary storage.")
        plugin_names = plugin_install(file_path)
        if not plugin_names:
            raise forms.ValidationError(
                "Failed to install plugin from archive. Ensure it is a valid .zip containing a Volatility 3 "
                "PluginInterface subclass with no syntax/import errors."
            )
        self._installed_plugins = plugin_names
        return plugin_zip

    def save(self, commit=True):
        """Return the first installed Plugin, linking every plugin to all users and compatible dumps."""
        plugin_names = getattr(self, "_installed_plugins", None)
        if not plugin_names:
            plugin_zip = self.cleaned_data["plugin"]
            file_path = getattr(getattr(plugin_zip, "file", None), "path", None) or getattr(plugin_zip, "path", None)
            plugin_names = plugin_install(file_path)
        if not plugin_names:
            raise forms.ValidationError("Failed to install plugin from archive.")

        def _sync_plugin_relations(plg_obj):
            """Create UserPlugin rows for every user and Result rows for dumps with a compatible OS."""
            for user in get_user_model().objects.all():
                UserPlugin.objects.get_or_create(user=user, plugin=plg_obj)
            for dump in Dump.objects.all():
                if plg_obj.operating_system in [dump.operating_system, "Other"] or dump.operating_system in [
                    plg_obj.operating_system,
                    "Other",
                ]:
                    Result.objects.update_or_create(
                        dump=dump,
                        plugin=plg_obj,
                        defaults={
                            "result": (
                                RESULT_STATUS_NOT_STARTED
                                if dump.status != DUMP_STATUS_MISSING_SYMBOLS
                                else RESULT_STATUS_DISABLED
                            )
                        },
                    )

        plugin_data = plugin_names[0]
        plugin_name, plugin_class = list(plugin_data.items())[0]
        plugin_obj = super().save(commit=False)
        plugin_obj.comment = self.cleaned_data["comment"] or (plugin_class.__doc__ if plugin_class else None)
        plugin_obj.name = plugin_name
        plugin_obj.local = True
        plugin_obj.local_date = datetime.now()
        if commit:
            # Handle upsert if a plugin with the same name already exists
            existing = Plugin.objects.filter(name=plugin_name).first()
            if existing and not plugin_obj.pk:
                plugin_obj.pk = existing.pk
            plugin_obj.save()
            _sync_plugin_relations(plugin_obj)
            self.save_m2m()

            # Register any additional plugins bundled in the same ZIP archive
            for extra_data in plugin_names[1:]:
                extra_name, extra_cls = list(extra_data.items())[0]
                extra_obj, _ = Plugin.objects.update_or_create(
                    name=extra_name,
                    defaults={
                        "comment": self.cleaned_data["comment"] or (extra_cls.__doc__ if extra_cls else None),
                        "operating_system": plugin_obj.operating_system,
                        "local": True,
                        "local_date": datetime.now(),
                        "disabled": plugin_obj.disabled,
                        "local_dump": plugin_obj.local_dump,
                        "vt_check": plugin_obj.vt_check,
                        "clamav_check": plugin_obj.clamav_check,
                        "regipy_check": plugin_obj.regipy_check,
                        "maxmind_check": plugin_obj.maxmind_check,
                    },
                )
                _sync_plugin_relations(extra_obj)
        return plugin_obj


class PluginEditAdminForm(FileFormMixin, forms.ModelForm):
    """Admin form for plugin options: minimum role, enable state, comment and post-processing checks."""

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


def parse_hint_lines(raw: str, default_cost: int = 10) -> list[tuple[str, int]]:
    """Parse CTF hints, one per line with an optional cost before a "|": "25 | Look at netscan"."""
    hints = []
    for line in (raw or "").splitlines():
        if not line.strip():
            continue
        cost, sep, text = line.partition("|")
        if not sep:
            cost, text = str(default_cost), line
        try:
            cost = int(cost.strip())
        except ValueError as exc:
            raise forms.ValidationError(f'Invalid hint cost in "{line.strip()}".') from exc
        if cost < 0 or not text.strip():
            raise forms.ValidationError(f'Invalid hint "{line.strip()}".')
        hints.append((text.strip(), cost))
    return hints


class CTFQuestionForm(forms.Form):
    """Question form of the case CTF panel (#1542)."""

    DEFAULT_HINT_COST = 10

    question_text = forms.CharField(widget=forms.Textarea(attrs={"rows": 2}), max_length=2000)
    answer = forms.CharField(max_length=500, help_text="Compared case-insensitively. Only its hash is stored.")
    points = forms.IntegerField(min_value=0, initial=100)
    order = forms.IntegerField(min_value=0, initial=1)
    hints = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 2}),
        required=False,
        help_text='One hint per line, optional cost before a "|": "25 | Look at netscan".',
    )

    def clean_question_text(self):
        """Reject blank questions."""
        if not (value := self.cleaned_data["question_text"].strip()):
            raise forms.ValidationError("The question cannot be blank.")
        return value

    def clean_answer(self):
        """Reject blank answers."""
        if not (value := self.cleaned_data["answer"].strip()):
            raise forms.ValidationError("The answer cannot be blank.")
        return value

    def clean_hints(self):
        """Parse the hint lines into ``(text, cost)`` pairs."""
        return parse_hint_lines(self.cleaned_data.get("hints", ""), self.DEFAULT_HINT_COST)


class SandboxSubmitForm(forms.Form):
    """Submission of an extracted file to CAPE / Cuckoo (#1551)."""

    index = forms.CharField(widget=forms.HiddenInput())
    path = forms.CharField(widget=forms.HiddenInput())
    machine = forms.CharField(
        required=False, max_length=100, help_text="Analysis VM name. Empty: let the sandbox choose."
    )
    tags = forms.CharField(required=False, max_length=200, help_text="Comma separated, e.g. win10,x64.")


class CTFObjectiveForm(forms.Form):
    """Ground-truth forensic discovery objective form for CTF mode."""

    ENTITY_CHOICES = (
        ("process", "Process (PID / Name)"),
        ("network", "Network (Foreign IP / Port / Proto)"),
        ("injection", "Memory Injection (PID / Base Address)"),
        ("registry", "Registry / Persistence (Key Path / Value)"),
        ("file", "File / Artifact (Name / Path / Hash)"),
        ("yara", "YARA Match (Rule / PID)"),
        ("generic", "Generic / Regex / JSON Predicate"),
    )

    title = forms.CharField(max_length=250)
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 2}), required=False)
    entity_type = forms.ChoiceField(choices=ENTITY_CHOICES, initial="process")
    criteria = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text='JSON criteria, e.g. {"pid": 4820, "name": "svchost.exe"} or {"foreign_ip": "198.51.100.23", "foreign_port": 4444}',
    )
    points = forms.IntegerField(min_value=0, initial=100)
    required_mitre = forms.CharField(
        max_length=50, required=False, help_text="Optional MITRE ATT&CK ID for bonus points (e.g. T1055)."
    )
    mitre_bonus = forms.IntegerField(min_value=0, initial=25, required=False)
    order = forms.IntegerField(min_value=1, initial=1)
    hints = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 2}),
        required=False,
        help_text='One hint per line, optional cost before a "|": "25 | Check netscan for unusual ports".',
    )

    def clean_hints(self):
        """Parse the hint lines into ``(text, cost)`` pairs."""
        return parse_hint_lines(self.cleaned_data.get("hints", ""))

    def clean_title(self):
        """Reject blank titles."""
        value = self.cleaned_data["title"].strip()
        if not value:
            raise forms.ValidationError("Title cannot be blank.")
        return value

    def clean_criteria(self):
        """Require a non-empty JSON object."""
        raw = (self.cleaned_data.get("criteria") or "").strip()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise forms.ValidationError(f"Criteria must be valid JSON: {exc}") from exc
        if not isinstance(parsed, dict) or not parsed:
            raise forms.ValidationError("Criteria must be a non-empty JSON object.")
        return parsed

    def clean_mitre_bonus(self):
        """Default the MITRE bonus to 25 points when left empty."""
        val = self.cleaned_data.get("mitre_bonus")
        return 25 if val is None else val
