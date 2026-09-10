import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from django.conf import settings
from django.core.management.base import CommandError
from django.template.loader import render_to_string

from orochi.website.management.commands.update_vendor_js import (
    Command as UpdateVendorCommand,
)

pytestmark = pytest.mark.django_db


def get_static_root():
    if hasattr(settings, "STATICFILES_DIRS") and settings.STATICFILES_DIRS:
        return Path(settings.STATICFILES_DIRS[0])
    return Path(settings.APPS_DIR) / "static"


# ==============================================================================
# 1. Manifest Structure and Schema Tests
# ==============================================================================
def test_vendor_manifest_structure_and_syntax():
    manifest_path = get_static_root() / "vendor_manifest.json"
    assert manifest_path.exists(), f"vendor_manifest.json not found at {manifest_path}"

    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)

    assert isinstance(manifest, dict), "Manifest root must be a JSON object/dict"
    assert len(manifest) >= 5, "Manifest should include key vendored libraries"

    required_keys = ["npm_package", "version", "files"]
    for pkg_name, pkg_data in manifest.items():
        for req_key in required_keys:
            assert req_key in pkg_data, f"Package '{pkg_name}' missing key '{req_key}'"

        assert isinstance(pkg_data["files"], list) and len(pkg_data["files"]) > 0, (
            f"Package '{pkg_name}' must declare at least one file"
        )

        for file_spec in pkg_data["files"]:
            assert "target" in file_spec, f"File in '{pkg_name}' missing 'target'"
            assert "cdn_url_template" in file_spec, f"File in '{pkg_name}' missing 'cdn_url_template'"
            assert "{version}" in file_spec["cdn_url_template"], (
                f"File in '{pkg_name}' CDN template missing '{{version}}' placeholder"
            )
            assert "min_size_bytes" in file_spec and file_spec["min_size_bytes"] > 0
            assert "required_tokens" in file_spec and isinstance(file_spec["required_tokens"], list)


# ==============================================================================
# 2. Existing Vendored Assets Integrity Tests
# ==============================================================================
def test_vendored_static_assets_exist_and_match_signatures():
    static_root = get_static_root()
    manifest_path = static_root / "vendor_manifest.json"

    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)

    for pkg_name, pkg_data in manifest.items():
        # Test all active packages that have files on disk
        for file_spec in pkg_data["files"]:
            target_path = static_root / file_spec["target"]
            assert target_path.exists(), f"Target vendored file does not exist: {target_path}"

            size = target_path.stat().st_size
            # If the file is not an uninitialized 0-byte stub, assert content integrity
            if size > 0:
                assert size >= file_spec["min_size_bytes"], (
                    f"File {file_spec['target']} is unexpectedly small ({size} bytes, "
                    f"expected min {file_spec['min_size_bytes']})"
                )
                content = target_path.read_text(encoding="utf-8", errors="replace")
                for token in file_spec.get("required_tokens", []):
                    assert token in content, (
                        f"Signature token '{token}' not found in {file_spec['target']} for package '{pkg_name}'"
                    )


# ==============================================================================
# 3. Management Command: --check Flag Tests
# ==============================================================================
def test_update_vendor_js_check_command_output():
    cmd = UpdateVendorCommand()

    with patch.object(cmd, "fetch_latest_version") as mock_fetch:
        mock_fetch.return_value = "99.0.0"

        # Capture output
        mock_stdout = MagicMock()
        cmd.stdout = mock_stdout
        cmd.handle(check=True, update=False, package=None, manifest=None)

        # Confirm stdout contains table headers
        calls = [c[0][0] for c in mock_stdout.write.call_args_list if c[0]]
        output_text = "\n".join(calls)
        assert "Checking Vendor JS/CSS Updates" in output_text
        assert "marked" in output_text
        assert "datatables" in output_text
        assert "Update available" in output_text


# ==============================================================================
# 4. Management Command: Safe Update & Atomic Swap Tests
# ==============================================================================
def test_update_vendor_js_safe_update_success(tmp_path):
    static_tmp = tmp_path / "static"
    static_tmp.mkdir()

    test_manifest = {
        "dummy-lib": {
            "npm_package": "dummy-lib",
            "version": "1.0.0",
            "files": [
                {
                    "target": "js/dummy.js",
                    "cdn_url_template": "https://cdn.example.com/dummy@{version}/dummy.js",
                    "min_size_bytes": 20,
                    "required_tokens": ["dummyFunction", "exports"],
                }
            ],
        }
    }
    manifest_file = static_tmp / "vendor_manifest.json"
    with open(manifest_file, "w") as fh:
        json.dump(test_manifest, fh)

    # Create initial file
    initial_file = static_tmp / "js" / "dummy.js"
    initial_file.parent.mkdir(parents=True)
    initial_file.write_text("initial content dummyFunction exports", encoding="utf-8")

    cmd = UpdateVendorCommand()

    new_content = b"/* v2.0.0 */ function dummyFunction() { return 'updated'; } exports.dummy = dummyFunction;"
    with (
        patch.object(cmd, "fetch_latest_version", return_value="2.0.0"),
        patch.object(cmd, "fetch_url", return_value=new_content),
    ):
        cmd.handle(
            check=False,
            update=True,
            package="dummy-lib",
            version_override=None,
            dry_run=False,
            manifest=str(manifest_file),
        )

    # 1. Target file has been updated
    assert initial_file.read_bytes() == new_content

    # 2. Backup file .bak was created with previous content
    bak_file = Path(f"{initial_file}.bak")
    assert bak_file.exists()
    assert bak_file.read_text(encoding="utf-8") == "initial content dummyFunction exports"

    # 3. Manifest was updated with new version
    with open(manifest_file) as fh:
        updated_manifest = json.load(fh)
    assert updated_manifest["dummy-lib"]["version"] == "2.0.0"
    assert "last_updated" in updated_manifest["dummy-lib"]


# ==============================================================================
# 5. Corruption Protection Tests (Invalid content, small size, missing tokens)
# ==============================================================================
def test_update_vendor_js_protects_against_corrupted_download(tmp_path):
    static_tmp = tmp_path / "static"
    static_tmp.mkdir()

    test_manifest = {
        "dummy-lib": {
            "npm_package": "dummy-lib",
            "version": "1.0.0",
            "files": [
                {
                    "target": "js/dummy.js",
                    "cdn_url_template": "https://cdn.example.com/dummy@{version}/dummy.js",
                    "min_size_bytes": 50,
                    "required_tokens": ["VALID_SIGNATURE"],
                }
            ],
        }
    }
    manifest_file = static_tmp / "vendor_manifest.json"
    with open(manifest_file, "w") as fh:
        json.dump(test_manifest, fh)

    initial_file = static_tmp / "js" / "dummy.js"
    initial_file.parent.mkdir(parents=True)
    original_text = "original working code VALID_SIGNATURE"
    initial_file.write_text(original_text, encoding="utf-8")

    cmd = UpdateVendorCommand()

    # Case A: Downloaded content is smaller than min_size_bytes
    tiny_content = b"too small"
    with (
        patch.object(cmd, "fetch_latest_version", return_value="2.0.0"),
        patch.object(cmd, "fetch_url", return_value=tiny_content),
    ):
        with pytest.raises(CommandError) as exc_info:
            cmd.handle(
                check=False,
                update=True,
                package="dummy-lib",
                version_override=None,
                dry_run=False,
                manifest=str(manifest_file),
            )
        assert "smaller than minimum expected" in str(exc_info.value)

    # Verify original file was completely preserved and untouched!
    assert initial_file.read_text(encoding="utf-8") == original_text

    # Case B: Downloaded content is missing required tokens / signatures
    tampered_content = b"/* plenty of bytes to pass size check 1234567890 1234567890 */ but missing token"
    with (
        patch.object(cmd, "fetch_latest_version", return_value="2.0.0"),
        patch.object(cmd, "fetch_url", return_value=tampered_content),
    ):
        with pytest.raises(CommandError) as exc_info:
            cmd.handle(
                check=False,
                update=True,
                package="dummy-lib",
                version_override=None,
                dry_run=False,
                manifest=str(manifest_file),
            )
        assert "missing required token signatures" in str(exc_info.value)

    # Verify original file remains intact
    assert initial_file.read_text(encoding="utf-8") == original_text


# ==============================================================================
# 6. Rollback Mechanism Tests
# ==============================================================================
def test_update_vendor_js_rollback_feature(tmp_path):
    static_tmp = tmp_path / "static"
    static_tmp.mkdir()

    test_manifest = {
        "dummy-lib": {
            "npm_package": "dummy-lib",
            "version": "2.0.0",
            "files": [{"target": "js/dummy.js"}],
        }
    }
    manifest_file = static_tmp / "vendor_manifest.json"
    with open(manifest_file, "w") as fh:
        json.dump(test_manifest, fh)

    target_file = static_tmp / "js" / "dummy.js"
    target_file.parent.mkdir(parents=True)
    target_file.write_text("broken new content", encoding="utf-8")

    bak_file = Path(f"{target_file}.bak")
    bak_file.write_text("working old backup content", encoding="utf-8")

    cmd = UpdateVendorCommand()
    cmd.handle(
        rollback=True,
        package="dummy-lib",
        manifest=str(manifest_file),
    )

    # File should now contain the backup content
    assert target_file.read_text(encoding="utf-8") == "working old backup content"


# ==============================================================================
# 7. Django Template Integration Tests
# ==============================================================================
def test_base_template_vendor_script_links_render_cleanly(client, admin):
    client.force_login(admin)

    # Render base.html with a basic request context
    html = render_to_string("base.html", {"request": MagicMock(user=admin)})

    # Confirm key vendor assets are included in the HTML output
    expected_asset_snippets = [
        "js/sweetalert2.all.min.js",
        "js/htmx/htmx.min.js",
        "js/jquery-3.7.1.min.js",
        "js/datatables/dataTables.js",
        "js/datatables/dataTables.buttons.min.js",
        "js/marked/marked.min.js",
        "css/datatables/buttons.dataTables.min.css",
        "css/datatables/jquery.dataTables.min.css",
    ]

    for snippet in expected_asset_snippets:
        assert snippet in html, f"Expected static asset snippet '{snippet}' not found in rendered base.html"

    # Verify that heavy Plotly (3.5MB) and unused jsoneditor are NOT loaded in base.html
    assert "js/plotly/plotly-2.34.0.min.js" not in html
    assert "jsoneditor.min.js" not in html


def test_json_view_template_renders_vanilla_jsoneditor(client, admin):
    client.force_login(admin)
    html = render_to_string("website/json_view.html", {"data": '{"test_key": "test_val"}'})
    assert "js/jsoneditor/vanilla-jsoneditor.js" in html
    assert "css/jsoneditor/jse-theme-dark.css" in html
    assert "JSONEditor" in html


def test_partial_analysis_scopes_plotly_to_bodyfile_chart():
    # When bodyfile_chart is None/empty, plotly must NOT be loaded
    html_no_chart = render_to_string(
        "website/partial_analysis.html",
        {
            "bodyfile_chart": None,
            "columns": ["PID", "Name"],
            "plugin": "windows.pslist.PsList",
        },
    )
    assert "js/plotly/plotly-2.34.0.min.js" not in html_no_chart

    # When bodyfile_chart is present, plotly is scoped to the chart
    html_with_chart = render_to_string(
        "website/partial_analysis.html",
        {
            "bodyfile_chart": "<div>chart</div>",
            "columns": ["PID", "Name"],
            "plugin": "timeliner.Timeliner",
        },
    )
    assert "js/plotly/plotly-2.34.0.min.js" in html_with_chart
