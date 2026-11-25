"""Portable, integrity-verified Case Bundle (.orochi.zip) export and import (Issue #1539).

The manifest lists every member with its SHA-256: import refuses a bundle whose members do not match it. The
manifest is not signed, so this detects corruption and edits of single members, not a bundle rebuilt on purpose.
On import, dumps are linked only when the importing user can already see them, and the extracted files and plugin
results of the bundle are restored under ``MEDIA_ROOT/case_bundles/<case id>/``.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import volatility3
from django.conf import settings
from django.db import transaction

from orochi.website.models import (
    Case,
    CaseNote,
    Dump,
    Evidence,
    Finding,
    Result,
    TimelineEvent,
    Value,
)
from orochi.website.storage import resolve_path_within, sanitize_filename

BUNDLE_FORMAT_VERSION = "1.0"
MAX_BUNDLE_UNCOMPRESSED_BYTES = 2 * 1024**3


class BundleIntegrityError(ValueError):
    """Raised when a case bundle is malformed, has path traversal, or fails SHA-256 verification."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def _safe_archive_path(name: str) -> str:
    norm = name.replace("\\", "/")
    if not norm or norm.startswith("/") or ".." in norm.split("/"):
        raise BundleIntegrityError(f"Unsafe archive member path: '{name}'")
    return norm


def export_case_bundle(case: Case) -> bytes:
    """Serialize a Case into a portable, SHA-256-manifested .orochi.zip archive (#1539)."""
    members: dict[str, bytes] = {}

    evidences = list(case.evidences.select_related("dump").order_by("pk"))
    findings = list(case.findings.select_related("evidence").order_by("pk"))
    notes = list(case.notes.select_related("author").order_by("created_at"))
    timeline_events = list(case.timeline_events.order_by("timestamp"))

    dumps_by_pk: dict[int, Dump] = {}
    for ev in evidences:
        if ev.dump:
            dumps_by_pk[ev.dump.pk] = ev.dump

    members["case.json"] = _json_bytes(
        {
            "original_id": case.pk,
            "name": case.name,
            "description": case.description or "",
            "status": case.status,
            "is_ctf": case.is_ctf,
            "owner": case.user.username,
            "created_at": case.created_at.isoformat(),
        }
    )

    members["dumps.json"] = _json_bytes(
        [
            {
                "index": str(d.index),
                "name": d.name,
                "operating_system": d.operating_system,
                "banner": d.banner or "",
                "md5": d.md5 or "",
                "sha256": d.sha256 or "",
                "size": d.size,
                "symbol_status": d.symbol_status,
            }
            for d in dumps_by_pk.values()
        ]
    )

    # Export extracted files referenced by evidences (validated within MEDIA_ROOT)
    media_root = Path(settings.MEDIA_ROOT).resolve()
    exported_files_map: dict[int, str] = {}
    for ev in evidences:
        candidate = None
        if ev.result_row and isinstance(ev.result_row, dict) and ev.result_row.get("down_path"):
            candidate = ev.result_row["down_path"]
        elif ev.extracted_file:
            candidate = ev.extracted_file
        if candidate:
            try:
                resolved = resolve_path_within(candidate, [media_root], must_exist_file=True)
                safe_name = sanitize_filename(resolved.name)
                arc_path = f"files/{ev.pk}_{safe_name}"
                members[arc_path] = resolved.read_bytes()
                exported_files_map[ev.pk] = arc_path
            except Exception:
                continue

    members["evidences.json"] = _json_bytes(
        [
            {
                "original_id": ev.pk,
                "dump_index": str(ev.dump.index) if ev.dump else None,
                "dump_name": ev.dump.name if ev.dump else None,
                "plugin": ev.plugin,
                "result_row": ev.result_row,
                "extracted_file": exported_files_map.get(ev.pk) or ev.extracted_file,
                "name": ev.name or "",
                "description": ev.description or "",
                "created_at": ev.created_at.isoformat(),
            }
            for ev in evidences
        ]
    )

    members["findings.json"] = _json_bytes(
        [
            {
                "original_id": f.pk,
                "evidence_original_id": f.evidence_id,
                "severity": f.severity,
                "tags": list(f.tags or []),
                "note": f.note or "",
                "mitre_attack_technique": f.mitre_attack_technique or "",
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ]
    )

    members["notes.json"] = _json_bytes(
        [
            {
                "original_id": n.pk,
                "title": n.title,
                "content": n.content,
                "author": n.author.username,
                "created_at": n.created_at.isoformat(),
            }
            for n in notes
        ]
    )

    members["timeline.json"] = _json_bytes(
        [
            {
                "timestamp": te.timestamp.isoformat(),
                "event_type": te.event_type,
                "description": te.description,
                "source_evidence_original_id": te.source_evidence_id,
            }
            for te in timeline_events
        ]
    )

    # Export plugin results referenced by case evidences
    seen_results: set[tuple[int, str]] = set()
    for ev in evidences:
        if not ev.dump or not ev.plugin:
            continue
        key = (ev.dump.pk, ev.plugin)
        if key in seen_results:
            continue
        seen_results.add(key)
        res = Result.objects.filter(dump=ev.dump, plugin__name=ev.plugin).select_related("plugin").first()
        if res:
            rows = list(Value.objects.filter(result=res).values_list("value", flat=True)[:5000])
            safe_plugin = sanitize_filename(res.plugin.name.replace("/", "_"))
            arc_name = f"results/{ev.dump.index}_{safe_plugin}.json"
            members[arc_name] = _json_bytes(
                {
                    "dump_index": str(ev.dump.index),
                    "plugin": res.plugin.name,
                    "status": res.get_result_display(),
                    "parameter": res.parameter,
                    "updated_at": res.updated_at.isoformat(),
                    "rows": rows,
                }
            )

    manifest = {
        "format_version": BUNDLE_FORMAT_VERSION,
        "exported_at": datetime.now(UTC).isoformat(),
        "volatility_version": getattr(volatility3, "__version__", "unknown"),
        "members": {
            path: {"sha256": _sha256_bytes(content), "size": len(content)} for path, content in sorted(members.items())
        },
    }
    manifest_bytes = _json_bytes(manifest)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        for path, content in sorted(members.items()):
            zf.writestr(path, content)
    return buf.getvalue()


def verify_case_bundle(zip_bytes: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Validate zip structure and verify every member's SHA-256 against manifest.json."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except zipfile.BadZipFile as exc:
        raise BundleIntegrityError("Uploaded file is not a valid ZIP archive.") from exc

    with zf:
        names = [_safe_archive_path(n) for n in zf.namelist()]
        if sum(info.file_size for info in zf.infolist()) > MAX_BUNDLE_UNCOMPRESSED_BYTES:
            raise BundleIntegrityError("Bundle is too large once uncompressed.")
        if "manifest.json" not in names:
            raise BundleIntegrityError("Bundle is missing required manifest.json.")

        try:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        except Exception as exc:
            raise BundleIntegrityError(f"Invalid manifest.json: {exc}") from exc

        manifest_members = manifest.get("members")
        if not isinstance(manifest_members, dict) or not manifest_members:
            raise BundleIntegrityError("manifest.json has no members map.")

        archive_non_manifest = {n for n in names if n != "manifest.json"}
        expected_paths = set(manifest_members.keys())
        if archive_non_manifest != expected_paths:
            missing = expected_paths - archive_non_manifest
            extra = archive_non_manifest - expected_paths
            raise BundleIntegrityError(f"Manifest member mismatch (missing={sorted(missing)}, extra={sorted(extra)}).")

        verified_files: dict[str, bytes] = {}
        for path, meta in manifest_members.items():
            raw = zf.read(path)
            actual_hash = _sha256_bytes(raw)
            expected_hash = meta.get("sha256")
            if actual_hash != expected_hash:
                raise BundleIntegrityError(
                    f"Integrity check failed for '{path}': expected sha256 {expected_hash}, got {actual_hash}."
                )
            verified_files[path] = raw

    return manifest, verified_files


def import_case_bundle(zip_bytes: bytes, user, *, name_override: str | None = None) -> Case:
    """Verify integrity and import a .orochi.zip Case Bundle into the current instance (#1539)."""
    from guardian.shortcuts import get_objects_for_user

    manifest, files = verify_case_bundle(zip_bytes)
    visible_dumps = get_objects_for_user(user, "website.can_see", klass=Dump)

    case_data = json.loads(files["case.json"].decode("utf-8"))
    evidences_data = json.loads(files.get("evidences.json", b"[]").decode("utf-8"))
    findings_data = json.loads(files.get("findings.json", b"[]").decode("utf-8"))
    notes_data = json.loads(files.get("notes.json", b"[]").decode("utf-8"))
    timeline_data = json.loads(files.get("timeline.json", b"[]").decode("utf-8"))

    base_name = (name_override or case_data.get("name") or "Imported Case").strip()
    case_name = base_name
    suffix = 1
    while Case.objects.filter(name=case_name, user=user).exists():
        case_name = f"{base_name} (imported {suffix})"
        suffix += 1

    with transaction.atomic():
        new_case = Case.objects.create(
            name=case_name,
            user=user,
            description=case_data.get("description") or "",
            status=case_data.get("status") or Case.STATUS_OPEN,
            is_ctf=bool(case_data.get("is_ctf", False)),
        )

        # Restore extracted files and plugin results carried by the bundle
        import_dir = Path(settings.MEDIA_ROOT) / "case_bundles" / str(new_case.pk)
        restored: dict[str, str] = {}
        for member, content in files.items():
            if not member.startswith(("files/", "results/")):
                continue
            target = resolve_path_within(import_dir / member, [import_dir])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            restored[member] = str(target)

        # Remove auto-generated signal timeline events during replay so imported timeline is clean
        ev_map: dict[int, Evidence] = {}
        for ev_item in evidences_data:
            dump_obj = None
            if ev_item.get("dump_index"):
                # Link only dumps this user may already see: a bundle cannot grant access to other dumps
                dump_obj = visible_dumps.filter(index=ev_item["dump_index"]).first()
            # Only files carried in the bundle are kept; any other path in the bundle is ignored
            bundle_file = ev_item.get("extracted_file")
            restored_file = restored.get(bundle_file) if bundle_file else None
            ev = Evidence.objects.create(
                case=new_case,
                dump=dump_obj,
                plugin=ev_item.get("plugin"),
                result_row=ev_item.get("result_row"),
                extracted_file=restored_file,
                name=ev_item.get("name") or "",
                description=ev_item.get("description") or "",
            )
            if ev_item.get("original_id") is not None:
                ev_map[ev_item["original_id"]] = ev

        for f_item in findings_data:
            linked_ev = ev_map.get(f_item.get("evidence_original_id"))
            Finding.objects.create(
                case=new_case,
                evidence=linked_ev,
                severity=f_item.get("severity") or "Medium",
                tags=f_item.get("tags") or [],
                note=f_item.get("note") or "",
                mitre_attack_technique=f_item.get("mitre_attack_technique") or None,
            )

        for n_item in notes_data:
            CaseNote.objects.create(
                case=new_case,
                author=user,
                title=n_item.get("title") or "Imported Note",
                content=n_item.get("content") or "",
            )

        # Replay imported timeline events (replacing signal-generated activity entries)
        TimelineEvent.objects.filter(case=new_case).delete()
        for t_item in timeline_data:
            ts_str = t_item.get("timestamp")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(UTC)
            except Exception:
                ts = datetime.now(UTC)
            TimelineEvent.objects.create(
                case=new_case,
                timestamp=ts,
                event_type=t_item.get("event_type") or "Imported Event",
                description=t_item.get("description") or "",
                source_evidence=ev_map.get(t_item.get("source_evidence_original_id")),
            )

        # Custody record of the import itself
        TimelineEvent.objects.create(
            case=new_case,
            timestamp=datetime.now(UTC),
            event_type="Bundle Imported",
            description=(
                f"Imported by {user.username} from bundle exported at {manifest.get('exported_at', 'unknown')} "
                f"(format {manifest.get('format_version', '?')}, Volatility {manifest.get('volatility_version', '?')}, "
                f"{len(manifest.get('members', {}))} verified members)."
            ),
        )

    return new_case
