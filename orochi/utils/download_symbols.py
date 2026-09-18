import binascii
import json
import logging
import lzma
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import requests
import rpmfile
from debian import debfile
from extra_settings.models import Setting
from pefile import PE
from volatility3.framework.contexts import Context
from volatility3.framework.symbols.windows.pdbconv import PdbReader, PdbRetreiver

logger = logging.getLogger(__name__)


class Downloader:
    def __init__(
        self,
        file_list: list[tuple[str, str]] | None = None,
        url_list: list[str] | None = None,
    ) -> None:
        self.url_list = url_list if url_list is not None else []
        self.file_list = file_list if file_list is not None else []
        self.created_symbols: list[str] = []
        base = Setting.get("VOLATILITY_SYMBOL_PATH") or "/app/.venv/lib/python3.13/site-packages/volatility3/symbols"
        self.down_path = f"{base}/added/"
        os.makedirs(self.down_path, exist_ok=True)
        try:
            from orochi.website.symbols_assistant import ensure_symbol_environment

            ensure_symbol_environment()
        except Exception:
            pass

    def _get_proxies(self) -> dict[str, str] | None:
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
            logger.info(f"Downloading {url}")
            with tempfile.NamedTemporaryFile() as archivedata:
                with requests.get(url, stream=True, proxies=proxies, timeout=120) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=65536):
                        if chunk:
                            archivedata.write(chunk)
                archivedata.seek(0)
                if url.endswith(".rpm"):
                    processed_files[url] = self.process_rpm(archivedata)
                elif url.endswith(".deb"):
                    processed_files[url] = self.process_deb(archivedata)
                elif url.endswith(".ddeb"):
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
                elif filename.endswith(".exe"):
                    self.process_exe(filepath)
                elif filename.startswith("vmlinux") or filename.endswith(".elf"):
                    temp_elf = tempfile.NamedTemporaryFile(delete=False)
                    temp_elf.write(archivedata.read())
                    temp_elf.close()
                    processed_files[filename] = temp_elf.name
                elif filename.startswith("System.map") or "System.map" in filename:
                    temp_map = tempfile.NamedTemporaryFile(delete=False)
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
        proc = subprocess.run(args, capture_output=True)

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
            basename, _ = os.path.splitext(named_file)
            prefix = "--system-map"
            if "System" not in val:
                prefix = "--elf"
                parsed_name = "-".join(basename.split("-")[2:]) if len(basename.split("-")) > 2 else basename
                output_filename = f"{self.down_path}added_{parsed_name}.json.xz"
            args += [prefix, val]

        logger.info(f"Running dwarf2json: {' '.join(args)}")
        proc = subprocess.run(args, capture_output=True)

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

    def process_exe(self, archivedata) -> str | None:
        """Download json from pdb in exe [Windows]"""
        pe = PE(archivedata)
        debug = pe.DIRECTORY_ENTRY_DEBUG[0].entry
        guid = "{:08X}{:04X}{:04X}{}{}".format(
            debug.Signature_Data1,
            debug.Signature_Data2,
            debug.Signature_Data3,
            f"{debug.Signature_Data4:x}{debug.Signature_Data5:x}{binascii.hexlify(debug.Signature_Data6).decode('utf-8')}",
            debug.Age,
        ).upper()
        filename = PdbRetreiver().retreive_pdb(guid, file_name="ntkrnlmp.pdb", progress_callback=None)
        ctxt = Context()
        profile = PdbReader(ctxt, filename).get_json()

        output_filename = f"{self.down_path}{guid}.json"
        logger.info(f"Writing PDB profile to {output_filename}")
        with open(output_filename, "w") as f:
            json.dump(profile, f, indent=4)
        self.created_symbols.append(output_filename)
        return output_filename

    def process_rpm(self, archivedata) -> str | None:
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
