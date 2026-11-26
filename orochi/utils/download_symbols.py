import binascii
import hashlib
import json
import logging
import lzma
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import requests
import rpmfile
from debian import debfile
from django.conf import settings
from extra_settings.models import Setting
from pefile import PE
from volatility3.framework.contexts import Context
from volatility3.framework.symbols.windows.pdbconv import PdbReader, PdbRetreiver

logger = logging.getLogger(__name__)


def package_name_from_url(url: str) -> str:
    """File name of a package URL; snapshot.debian.org URLs carry it in the fragment (``.../file/<hash>#name.deb``)."""
    if "#" in url:
        return url.rsplit("#", 1)[1].split("&", 1)[0]
    return os.path.basename(url.split("?", 1)[0]) or url


_SNAPSHOT_FILE_RE = re.compile(r"^https?://snapshot\.debian\.org/file/([0-9a-f]{40})(?:[#?]|$)")


def published_hash(url: str) -> tuple[str, str] | None:
    """Hash a package must have, when its source publishes one (#1674 FR-6).

    snapshot.debian.org serves files by content: the path is the SHA-1 of the file. A ``sha256=<hex>``
    parameter in the URL fragment (``...#name.deb&sha256=<hex>``) states the expected SHA-256 explicitly.
    """
    fragment = url.split("#", 1)[1] if "#" in url else ""
    for part in fragment.split("&"):
        if part.startswith("sha256=") and re.fullmatch(r"[0-9a-f]{64}", part[7:]):
            return "sha256", part[7:]
    if m := _SNAPSHOT_FILE_RE.match(url):
        return "sha1", m.group(1)
    return None


class Downloader:
    """Download Linux kernel debug packages and convert them to Volatility ISF with dwarf2json."""

    def __init__(
        self,
        file_list: list[tuple[str, str]] | None = None,
        url_list: list[str] | None = None,
        progress=None,
    ) -> None:
        """``progress`` is an optional callable receiving human readable status messages."""
        self.progress = progress or (lambda message: None)
        self.url_list = url_list if url_list is not None else []
        self.file_list = file_list if file_list is not None else []
        self.created_symbols: list[str] = []
        # {url: {"sha256": ..., "verified": "sha1" | "sha256" | None}} of every downloaded package
        self.downloads: dict[str, dict] = {}
        base = Setting.get("VOLATILITY_SYMBOL_PATH") or getattr(settings, "VOLATILITY_SYMBOL_PATH", "/symbols")
        self.down_path = f"{base}/added/"
        os.makedirs(self.down_path, exist_ok=True)
        try:
            from orochi.website.symbols_assistant import ensure_symbol_environment

            ensure_symbol_environment()
        except Exception:
            pass

    def _get_proxies(self) -> dict[str, str] | None:
        """Proxies from the ``http_proxy`` / ``https_proxy`` environment variables, or None."""
        proxies = None
        if os.environ.get("http_proxy") or os.environ.get("https_proxy"):
            proxies = {
                "http": os.environ.get("http_proxy"),
                "https": os.environ.get("https_proxy"),
            }
        return proxies

    def download_list(self):
        """Download and process files from web urls [Linux]"""
        processed_files = {}
        proxies = self._get_proxies()
        for url in self.url_list:
            name = package_name_from_url(url)
            logger.info(f"Downloading {url}")
            expected = published_hash(url)
            digests = {"sha1": hashlib.sha1(usedforsecurity=False), "sha256": hashlib.sha256()}
            with tempfile.NamedTemporaryFile() as archivedata:
                with requests.get(url, stream=True, proxies=proxies, timeout=120) as r:
                    r.raise_for_status()
                    size = int(r.headers.get("content-length") or 0)
                    self.progress(f"Downloading {name}" + (f" ({size / 1024**2:.0f} MB)" if size else "") + "...")
                    for chunk in r.iter_content(chunk_size=65536):
                        if chunk:
                            archivedata.write(chunk)
                            for digest in digests.values():
                                digest.update(chunk)
                sha256 = digests["sha256"].hexdigest()
                if expected and digests[expected[0]].hexdigest() != expected[1]:
                    # A package that is not the published one is refused before it is unpacked (#1674 FR-6)
                    raise ValueError(
                        f"{name}: {expected[0].upper()} {digests[expected[0]].hexdigest()} does not match the published "
                        f"{expected[1]}; download refused"
                    )
                self.downloads[url] = {"name": name, "sha256": sha256, "verified": expected[0] if expected else None}
                self.progress(
                    f"Downloaded {name} ("
                    + (f"{expected[0].upper()} verified against the source" if expected else "no published hash")
                    + f", SHA-256 {sha256[:16]}...), extracting vmlinux / System.map..."
                )
                archivedata.seek(0)
                kind = name.rsplit(".", 1)[-1].lower()
                if kind == "rpm":
                    processed_files[url] = self.process_rpm(archivedata)
                elif kind == "deb":
                    processed_files[url] = self.process_deb(archivedata)
                elif kind == "ddeb":
                    processed_files[url] = self.process_ddeb(archivedata)
        self.process(processed_files)

    def process_list(self):
        """Download and process uploaded files"""
        processed_files = {}
        for filepath, filename in self.file_list:
            logger.info(f"Processing {filename}")
            with open(filepath, "rb") as archivedata:
                if filename.endswith(".rpm"):
                    processed_files[filename] = self.process_rpm(archivedata)
                elif filename.endswith(".deb"):
                    processed_files[filename] = self.process_deb(archivedata)
                elif filename.endswith(".ddeb"):
                    processed_files[filename] = self.process_ddeb(archivedata)
                elif filename.lower().endswith(".exe"):
                    self.process_exe(filepath)
                elif filename.startswith("vmlinux") or filename.endswith(".elf"):
                    temp_elf = tempfile.NamedTemporaryFile(delete=False, prefix="vmlinux_")
                    temp_elf.write(archivedata.read())
                    temp_elf.close()
                    processed_files[filename] = temp_elf.name
                elif filename.startswith("System.map") or "System.map" in filename or filename.endswith(".map"):
                    temp_map = tempfile.NamedTemporaryFile(delete=False, prefix="System.map_")
                    temp_map.write(archivedata.read())
                    temp_map.close()
                    processed_files[filename] = temp_map.name
        self.process(processed_files)

    def process_raw_kernel(
        self,
        elf_path: str,
        system_map_path: str | None = None,
        output_name: str | None = None,
    ) -> str:
        """
        Executes dwarf2json linux directly over a raw vmlinux ELF and optional System.map.
        Generates and returns the path to the compressed ISF symbol file (.json.xz).
        """
        dwarf2json_bin = Setting.get("DWARF2JSON") or "/dwarf2json/dwarf2json"
        args = [dwarf2json_bin, "linux", "--elf", elf_path]
        if system_map_path and os.path.exists(system_map_path):
            args += ["--system-map", system_map_path]

        logger.info(f"Running dwarf2json: {' '.join(args)}")
        proc = subprocess.run(args, capture_output=True, check=False)

        if proc.returncode != 0:
            err_msg = proc.stderr.decode("utf-8", errors="ignore")
            logger.error(f"dwarf2json failed (code {proc.returncode}): {err_msg}")
            raise RuntimeError(f"dwarf2json failed: {err_msg}")

        if not proc.stdout:
            err_msg = proc.stderr.decode("utf-8", errors="ignore")
            logger.error(f"dwarf2json returned empty output: {err_msg}")
            raise RuntimeError(f"dwarf2json returned empty output: {err_msg}")

        if output_name:
            if not output_name.endswith(".json.xz"):
                output_name = f"{output_name}.json.xz"
            output_filename = os.path.join(self.down_path, output_name)
        else:
            base = Path(elf_path).stem
            output_filename = os.path.join(self.down_path, f"added_{base}.json.xz")

        logger.info(f"Writing compressed symbol table to {output_filename}")
        with lzma.open(output_filename, "w") as f:
            f.write(proc.stdout)
        self.created_symbols.append(output_filename)
        return output_filename

    def process_btf_kernel(
        self,
        btf_path: str,
        system_map_path: str | None = None,
        banner: str | None = None,
        output_name: str | None = None,
    ) -> str:
        """
        Executes btf2json directly over a BTF file (e.g. /sys/kernel/btf/vmlinux or stripped vmlinux),
        optional System.map, and optional Linux banner string.
        Generates and returns the path to the compressed ISF symbol file (.json.xz).
        """
        btf2json_bin = Setting.get("BTF2JSON") or getattr(settings, "BTF2JSON", "/btf2json/btf2json")
        args = [btf2json_bin, "--btf", btf_path]
        if system_map_path and os.path.exists(system_map_path):
            args += ["--map", system_map_path]
        if banner and banner.strip():
            args += ["--banner", banner.strip()]

        logger.info(f"Running btf2json: {' '.join(args)}")
        proc = subprocess.run(args, capture_output=True, check=False)

        if proc.returncode != 0:
            err_msg = proc.stderr.decode("utf-8", errors="ignore")
            logger.error(f"btf2json failed (code {proc.returncode}): {err_msg}")
            raise RuntimeError(f"btf2json failed: {err_msg}")

        if not proc.stdout:
            err_msg = proc.stderr.decode("utf-8", errors="ignore")
            logger.error(f"btf2json returned empty output: {err_msg}")
            raise RuntimeError(f"btf2json returned empty output: {err_msg}")

        if output_name:
            safe_name = os.path.basename(output_name.strip())
            if not safe_name.endswith(".json.xz"):
                safe_name = f"{safe_name}.json.xz"
            output_filename = os.path.join(self.down_path, safe_name)
        else:
            base = Path(btf_path).stem
            output_filename = os.path.join(self.down_path, f"added_btf_{base}.json.xz")

        logger.info(f"Writing compressed BTF symbol table to {output_filename}")
        with lzma.open(output_filename, "w") as f:
            f.write(proc.stdout)
        self.created_symbols.append(output_filename)
        return output_filename

    def process(self, processed_files):
        """Process the files and remove the temporary files"""
        try:
            self.process_files(processed_files)
        finally:
            for fname in processed_files.values():
                if fname and os.path.exists(fname):
                    try:
                        os.unlink(fname)
                    except OSError as e:
                        logger.warning(f"Failed removing temp file {fname}: {e}")
            logger.info("Done processing files.")

    def process_files(self, named_files: dict[str, str]):
        """Runs the dwarf2json binary across the files"""
        logger.info("Processing extracted files with dwarf2json...")
        if not named_files:
            return

        for i, value in named_files.items():
            if value is None:
                err = f"Failed to extract kernel binaries (vmlinux/System.map) from {i}"
                logger.error(err)
                raise ValueError(err)

        dwarf2json_bin = Setting.get("DWARF2JSON") or "/dwarf2json/dwarf2json"
        args = [dwarf2json_bin, "linux"]
        output_filename = os.path.join(self.down_path, "unknown-kernel.json.xz")

        for named_file, val in named_files.items():
            basename, _ = os.path.splitext(package_name_from_url(named_file))
            is_system_map = (
                "System.map" in named_file or "System" in os.path.basename(val) or named_file.lower().endswith(".map")
            )
            if is_system_map:
                prefix = "--system-map"
            else:
                prefix = "--elf"
                parsed_name = "-".join(basename.split("-")[2:]) if len(basename.split("-")) > 2 else basename
                output_filename = f"{self.down_path}added_{parsed_name}.json.xz"
            args += [prefix, val]

        self.progress("Building the symbol table (ISF) with dwarf2json, this can take a few minutes...")
        logger.info(f"Running dwarf2json: {' '.join(args)}")
        proc = subprocess.run(args, capture_output=True, check=False)

        if proc.returncode != 0:
            err_msg = proc.stderr.decode("utf-8", errors="ignore")
            logger.error(f"dwarf2json failed (code {proc.returncode}): {err_msg}")
            raise RuntimeError(f"dwarf2json failed: {err_msg}")

        if not proc.stdout:
            err_msg = proc.stderr.decode("utf-8", errors="ignore")
            logger.error(f"dwarf2json returned empty output: {err_msg}")
            raise RuntimeError(f"dwarf2json returned empty output: {err_msg}")

        logger.info(f"Writing compressed symbol table to {output_filename}")
        with lzma.open(output_filename, "w") as f:
            f.write(proc.stdout)
        self.created_symbols.append(output_filename)
        self.progress(f"Symbol table {os.path.basename(output_filename)} written.")

    def process_exe(self, archivedata) -> str | None:
        """Download json from pdb in exe [Windows]"""
        pe = PE(archivedata)
        if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG") or not pe.DIRECTORY_ENTRY_DEBUG:
            raise ValueError("PE executable does not contain a debug directory (DIRECTORY_ENTRY_DEBUG).")
        debug = pe.DIRECTORY_ENTRY_DEBUG[0].entry
        guid = "{:08X}{:04X}{:04X}{}{}".format(
            debug.Signature_Data1,
            debug.Signature_Data2,
            debug.Signature_Data3,
            f"{debug.Signature_Data4:02x}{debug.Signature_Data5:02x}{binascii.hexlify(debug.Signature_Data6).decode('utf-8')}",
            debug.Age,
        ).upper()
        raw_pdb_name = getattr(debug, "PdbFileName", b"ntkrnlmp.pdb")
        if isinstance(raw_pdb_name, bytes):
            pdb_name = raw_pdb_name.rstrip(b"\x00").decode("utf-8", errors="ignore").split("\\")[-1] or "ntkrnlmp.pdb"
        else:
            pdb_name = str(raw_pdb_name).split("\\")[-1] or "ntkrnlmp.pdb"
        filename = PdbRetreiver().retreive_pdb(guid, file_name=pdb_name, progress_callback=None)
        if not filename:
            raise RuntimeError(f"Could not retrieve PDB '{pdb_name}' for GUID {guid} from symbol server.")
        ctxt = Context()
        profile = PdbReader(ctxt, filename).get_json()

        output_filename = f"{self.down_path}{guid}.json"
        logger.info(f"Writing PDB profile to {output_filename}")
        with open(output_filename, "w") as f:
            json.dump(profile, f, indent=4)
        self.created_symbols.append(output_filename)
        return output_filename

    def process_rpm(self, archivedata) -> str | None:
        """Extract ``vmlinux`` or ``System.map`` from an RPM package."""
        rpm = rpmfile.RPMFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in rpm.getmembers():
            if "vmlinux" in member.name or "System.map" in member.name:
                logger.info(f"Extracting RPM member {member.name}")
                extracted = rpm.extractfile(member)
                break
        return self.process_gen(member, extracted)

    def process_deb(self, archivedata) -> str | None:
        """Extract ``vmlinux`` or ``System.map`` from a DEB package."""
        deb = debfile.DebFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in deb.data.tgz().getmembers():
            if member.name.endswith("vmlinux") or "System.map" in member.name:
                logger.info(f"Extracting DEB member {member.name}")
                extracted = deb.data.get_file(member.name)
                break
        return self.process_gen(member, extracted)

    def process_ddeb(self, archivedata) -> str | None:
        """Extract ``vmlinux`` or ``System.map`` from an Ubuntu DDEB debug package."""
        deb = debfile.DebFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in deb.data.tgz().getmembers():
            if member.name.endswith("vmlinux") or "System.map" in member.name:
                logger.info(f"Extracting DDEB member {member.name}")
                extracted = deb.data.get_file(member.name)
                break
        return self.process_gen(member, extracted)

    def process_gen(self, member, extracted):
        """Write an extracted member to a temporary file and return its path (None when nothing was found)."""
        if not member or not extracted:
            return None
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="vmlinux" if "vmlinux" in member.name else "System.map"
        ) as output:
            logger.info(f"Writing extracted kernel component to {output.name}")
            shutil.copyfileobj(extracted, output)
        return output.name


def download_symbols(
    url_list: list[str] | None = None,
    file_list: list[tuple[str, str]] | None = None,
) -> list[str]:
    """
    Direct function to download and compile symbols.
    """
    d = Downloader(file_list=file_list, url_list=url_list)
    if url_list:
        d.download_list()
    if file_list:
        d.process_list()
    return d.created_symbols
