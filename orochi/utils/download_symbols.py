import lzma
import os
import subprocess
import tempfile
from typing import List, Dict, Optional

import requests
import rpmfile
from debian import debfile

DWARF2JSON = "/dwarf2json/./dwarf2json"


class Downloader:
    def __init__(self, url_lists: List[List[str]], operating_system: str) -> None:
        self.url_lists = url_lists
        self.down_path = "/src/volatility/volatility/symbols/{}/".format(
            operating_system.lower()
        )

    def download_lists(self, keep=False):
        for url_list in self.url_lists:
            print("Downloading files...")
            files_for_processing = self.download_list(url_list)
            self.process_files(files_for_processing)
            if not keep:
                for fname in files_for_processing.values():
                    if fname:
                        os.unlink(fname)
            print("Done")

    def download_list(self, urls: List[str]) -> Dict[str, str]:
        processed_files = {}
        for url in urls:
            print(" - Downloading {}".format(url))
            data = requests.get(url)
            with tempfile.NamedTemporaryFile() as archivedata:
                archivedata.write(data.content)
                archivedata.seek(0)
                if url.endswith(".rpm"):
                    processed_files[url] = self.process_rpm(archivedata)
                elif url.endswith(".deb"):
                    processed_files[url] = self.process_deb(archivedata)
                elif url.endswith(".ddeb"):
                    processed_files[url] = self.process_ddeb(archivedata)
        print(" - Downloading done {}".format(processed_files))
        return processed_files

    def process_rpm(self, archivedata) -> Optional[str]:
        rpm = rpmfile.RPMFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in rpm.getmembers():
            if "vmlinux" in member.name or "System.map" in member.name:
                print(" - Extracting {}".format(member.name))
                extracted = rpm.extractfile(member)
                break
        if not member or not extracted:
            return None
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="vmlinux" if "vmlinux" in member.name else "System.map"
        ) as output:
            print(" - Writing to {}".format(output.name))
            output.write(extracted.read())
        return output.name

    def process_deb(self, archivedata) -> Optional[str]:
        deb = debfile.DebFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in deb.data.tgz().getmembers():
            if member.name.endswith("vmlinux") or "System.map" in member.name:
                print(" - Extracting {}".format(member.name))
                extracted = deb.data.get_file(member.name)
                break
        if not member or not extracted:
            return None
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="vmlinux" if "vmlinux" in member.name else "System.map"
        ) as output:
            print(" - Writing to {}".format(output.name))
            output.write(extracted.read())
        return output.name

    def process_ddeb(self, archivedata) -> Optional[str]:
        deb = debfile.DebFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in deb.data.tgz().getmembers():
            if "vmlinux" in member.name or "System.map" in member.name:
                print(" - Extracting {}".format(member.name))
                extracted = deb.data.get_file(member.name)
                break
        if not member or not extracted:
            return None
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="vmlinux" if "vmlinux" in member.name else "System.map"
        ) as output:
            print(" - Writing to {}".format(output.name))
            output.write(extracted.read())
        return output.name

    def process_files(self, named_files: Dict[str, str]):
        """Runs the dwarf2json binary across the files"""
        print("Processing Files...")
        for i in named_files:
            if named_files[i] is None:
                print("FAILURE: None encountered for {}".format(i))
                return
        args = [DWARF2JSON, "linux"]
        output_filename = "unknown-kernel.json"
        for named_file in named_files:
            basename, ext = os.path.splitext(named_file)

            prefix = "--system-map"
            if not "System" in named_files[named_file]:
                prefix = "--elf"
                output_filename = "{}{}{}{}".format(
                    self.down_path,
                    "added_",
                    "-".join(basename.split("-")[2:]),
                    ".json.xz",
                )
            args += [prefix, named_files[named_file]]
        print(" - Running {}".format(args))
        proc = subprocess.run(args, capture_output=True)

        print(" - Writing to {}".format(output_filename))
        with lzma.open(output_filename, "w") as f:
            f.write(proc.stdout)
