import json
import os
import shutil
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Manage, inspect, and safely update vendored JavaScript and CSS assets from CDN/npm with integrity checks."

    def add_arguments(self, parser):
        parser.add_argument(
            "--check",
            action="store_true",
            help="Check npm registry for newer versions without modifying any files.",
        )
        parser.add_argument(
            "--update",
            "--all",
            action="store_true",
            dest="update",
            help="Download and update packages (all or specified by --package).",
        )
        parser.add_argument(
            "--package",
            type=str,
            help="Target a specific package name defined in vendor_manifest.json.",
        )
        parser.add_argument(
            "--version-override",
            type=str,
            dest="version_override",
            help="Target a specific version instead of latest npm release (used with --package).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Simulate download and validation without writing files or modifying manifest.",
        )
        parser.add_argument(
            "--rollback",
            action="store_true",
            help="Restore previous .bak files if available.",
        )
        parser.add_argument(
            "--manifest",
            type=str,
            help="Custom path to vendor_manifest.json.",
        )

    def get_static_dir(self, manifest_path=None):
        if manifest_path:
            return Path(manifest_path).resolve().parent
        if hasattr(settings, "STATICFILES_DIRS") and settings.STATICFILES_DIRS:
            return Path(settings.STATICFILES_DIRS[0]).resolve()
        return Path(settings.APPS_DIR) / "static"

    def get_manifest_path(self, manifest_arg=None):
        if manifest_arg:
            return Path(manifest_arg).resolve()
        return self.get_static_dir() / "vendor_manifest.json"

    def load_manifest(self, manifest_path):
        if not manifest_path.exists():
            raise CommandError(f"Manifest not found at {manifest_path}")
        try:
            with open(manifest_path, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as e:
            raise CommandError(f"Failed to read manifest at {manifest_path}: {e}") from e

    def save_manifest(self, manifest_path, manifest_data):
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest_data, fh, indent=2)

    def get_opener(self):
        # Explicitly empty ProxyHandler avoids container proxy loopback/refusal issues
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def fetch_latest_version(self, npm_package, opener=None):
        if opener is None:
            opener = self.get_opener()
        url = f"https://registry.npmjs.org/{npm_package}/latest"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Orochi-Vendor-Updater/1.0",
                "Accept": "application/json",
            },
        )
        try:
            with opener.open(req, timeout=12) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("version")
        except (urllib.error.HTTPError, urllib.error.URLError, Exception) as e:
            raise CommandError(f"HTTP error {e.code} checking npm package {npm_package}: {e.reason}") from e

    def fetch_url(self, url, opener=None):
        if opener is None:
            opener = self.get_opener()
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Orochi-Vendor-Updater/1.0",
                "Accept": "*/*",
            },
        )
        try:
            with opener.open(req, timeout=20) as resp:
                if resp.status != 200:
                    raise CommandError(f"Failed downloading {url} (HTTP {resp.status})")
                return resp.read()
        except urllib.error.HTTPError as e:
            raise CommandError(f"HTTP error {e.code} downloading {url}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise CommandError(f"Network error downloading {url}: {e.reason}") from e

    def validate_content(self, content_bytes, min_size_bytes, required_tokens, target_name):
        size = len(content_bytes)
        if size < min_size_bytes:
            raise CommandError(
                f"Validation failed for {target_name}: downloaded size ({size} bytes) "
                f"is smaller than minimum expected ({min_size_bytes} bytes)."
            )

        try:
            text = content_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise CommandError(f"Failed decoding content for {target_name}: {e}") from e

        if missing_tokens := [tok for tok in required_tokens if tok not in text]:
            raise CommandError(
                f"Validation failed for {target_name}: missing required token signatures: {missing_tokens}."
            )

    def perform_rollback(self, manifest, static_dir, target_pkg=None):
        packages_to_rollback = [target_pkg] if target_pkg else list(manifest.keys())
        restored_count = 0

        for pkg in packages_to_rollback:
            if pkg not in manifest:
                raise CommandError(f"Package '{pkg}' not found in manifest.")
            pkg_info = manifest[pkg]
            for file_spec in pkg_info.get("files", []):
                target_path = static_dir / file_spec["target"]
                bak_path = Path(f"{target_path}.bak")
                if bak_path.exists():
                    shutil.copy2(bak_path, target_path)
                    self.stdout.write(self.style.SUCCESS(f"Restored {file_spec['target']} from .bak"))
                    restored_count += 1
                else:
                    self.stdout.write(self.style.WARNING(f"No .bak found for {file_spec['target']}"))

        if restored_count > 0:
            self.stdout.write(self.style.SUCCESS(f"Rollback complete ({restored_count} files restored)."))
        else:
            self.stdout.write(self.style.WARNING("No backup files (.bak) were found to restore."))

    def handle(self, *args, **options):
        manifest_path = self.get_manifest_path(options.get("manifest"))
        static_dir = self.get_static_dir(options.get("manifest"))
        manifest = self.load_manifest(manifest_path)

        # Handle rollback
        if options.get("rollback"):
            self.perform_rollback(manifest, static_dir, options.get("package"))
            return

        target_pkg = options.get("package")
        if target_pkg and target_pkg not in manifest:
            available = ", ".join(sorted(manifest.keys()))
            raise CommandError(f"Unknown package '{target_pkg}'. Available packages in manifest: {available}")

        packages_to_process = [target_pkg] if target_pkg else list(manifest.keys())

        if options.get("check") or not options.get("update"):
            self.stdout.write(self.style.MIGRATE_HEADING("--- Checking Vendor JS/CSS Updates ---"))
            header = f"{'Package':<22} {'Current':<12} {'Latest':<12} Status"
            self.stdout.write(header)
            self.stdout.write("-" * len(header))

            has_updates = False
            for pkg in sorted(packages_to_process):
                pkg_data = manifest[pkg]
                current_ver = pkg_data.get("version", "unknown")
                npm_pkg = pkg_data.get("npm_package", pkg)

                try:
                    latest_ver = self.fetch_latest_version(npm_pkg)
                    if latest_ver != current_ver:
                        has_updates = True
                        status_str = self.style.WARNING(f"Update available: {latest_ver}")
                    else:
                        status_str = self.style.SUCCESS("Up to date")
                    self.stdout.write(f"{pkg:<22} {current_ver:<12} {latest_ver:<12} {status_str}")
                except Exception as e:
                    err_str = self.style.ERROR(f"Check failed: {e}")
                    self.stdout.write(f"{pkg:<22} {current_ver:<12} {'error':<12} {err_str}")

            self.stdout.write("")
            if has_updates:
                self.stdout.write(
                    "Run 'python manage.py update_vendor_js --update' to apply updates, "
                    "or '--package <name>' to update individually."
                )
            else:
                self.stdout.write(self.style.SUCCESS("All checked vendor libraries are up to date."))
            return

        # Perform update
        dry_run = options.get("dry_run", False)
        version_override = options.get("version_override")
        if version_override and len(packages_to_process) > 1:
            raise CommandError("--version-override can only be used when targeting a single --package.")

        self.stdout.write(self.style.MIGRATE_HEADING("--- Updating Vendored Assets ---"))
        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN MODE: No files or manifest will be modified.\n"))

        updated_packages = 0
        manifest_modified = False

        for pkg in packages_to_process:
            pkg_data = manifest[pkg]
            current_ver = pkg_data.get("version")
            npm_pkg = pkg_data.get("npm_package", pkg)

            if version_override:
                target_version = version_override
            else:
                self.stdout.write(f"Querying npm for latest {npm_pkg}...")
                target_version = self.fetch_latest_version(npm_pkg)

            self.stdout.write(f"Package [{pkg}]: current version {current_ver} -> target version {target_version}")

            # 1. Download and validate all files to memory first
            prepared_downloads = []
            for file_spec in pkg_data.get("files", []):
                target_rel = file_spec["target"]
                url = file_spec["cdn_url_template"].format(version=target_version)
                min_size = file_spec.get("min_size_bytes", 1024)
                required_tokens = file_spec.get("required_tokens", [])

                self.stdout.write(f"  Fetching {url}...")
                content = self.fetch_url(url)
                self.validate_content(content, min_size, required_tokens, target_rel)
                self.stdout.write(self.style.SUCCESS(f"  Verified integrity of {target_rel} ({len(content)} bytes)"))
                prepared_downloads.append((target_rel, content))

            # 2. If all files in package passed validation, apply atomic writes
            if not dry_run:
                for target_rel, content in prepared_downloads:
                    dest_path = static_dir / target_rel
                    dest_path.parent.mkdir(parents=True, exist_ok=True)

                    tmp_path = Path(f"{dest_path}.tmp")
                    bak_path = Path(f"{dest_path}.bak")

                    with open(tmp_path, "wb") as fh:
                        fh.write(content)

                    # Backup existing file if present
                    if dest_path.exists():
                        shutil.copy2(dest_path, bak_path)

                    # Atomic replace
                    os.replace(tmp_path, dest_path)
                    self.stdout.write(self.style.SUCCESS(f"  Atomically wrote {dest_path}"))

                # Update manifest entry
                pkg_data["version"] = target_version
                pkg_data["last_updated"] = datetime.now(UTC).isoformat()
                manifest_modified = True

            updated_packages += 1
            self.stdout.write(self.style.SUCCESS(f"Successfully processed package '{pkg}'!\n"))

        if manifest_modified and not dry_run:
            self.save_manifest(manifest_path, manifest)
            self.stdout.write(self.style.SUCCESS(f"Updated manifest at {manifest_path}"))

        self.stdout.write(self.style.SUCCESS(f"Finished updating {updated_packages} package(s)."))
