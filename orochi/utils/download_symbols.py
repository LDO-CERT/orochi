import lzma
import os
import subprocess
import tempfile
from typing import Dict, List, Optional

import requests
import rpmfile
from debian import debfile
from django.conf import settings


class Downloader:
    def __init__(self, file_list: List[str] = None, url_list: List[str] = None) -> None:
        self.url_list = url_list if url_list is not None else []
        self.file_list = file_list if file_list is not None else []
        self.down_path = f"{settings.VOLATILITY_SYMBOL_PATH}/added/"

    def download_list(self):
        processed_files = {}
        for url in self.url_list:
            print(f" - Downloading {url}")
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
        self.process(processed_files)

    def process_list(self):
        processed_files = {}
        for filepath, filename in self.file_list:
            print(f" - Processing {filename}")
            with open(filepath, "rb") as archivedata:
                if filename.endswith(".rpm"):
                    processed_files[filename] = self.process_rpm(archivedata)
                elif filename.endswith(".deb"):
                    processed_files[filename] = self.process_deb(archivedata)
                elif filename.endswith(".ddeb"):
                    processed_files[filename] = self.process_ddeb(archivedata)
        self.process(processed_files)

    def process(self, processed_files):
        self.process_files(processed_files)
        for fname in processed_files.values():
            if fname:
                os.unlink(fname)
        print("Done")

    def process_files(self, named_files: Dict[str, str]):
        """Runs the dwarf2json binary across the files"""
        print("Processing Files...")
        for i, value in named_files.items():
            if value is None:
                print(f"FAILURE: None encountered for {i}")
                return
        args = [settings.DWARF2JSON, "linux"]
        output_filename = "unknown-kernel.json"
        for named_file, value_ in named_files.items():
            basename, _ = os.path.splitext(named_file)

            prefix = "--system-map"
            if "System" not in value_:
                prefix = "--elf"
                output_filename = (
                    f'{self.down_path}added_{"-".join(basename.split("-")[2:])}.json.xz'
                )
            args += [prefix, named_files[named_file]]
        print(f" - Running {args}")
        proc = subprocess.run(args, capture_output=True)

        print(f" - Writing to {output_filename}")
        with lzma.open(output_filename, "w") as f:
            f.write(proc.stdout)

    def process_rpm(self, archivedata) -> Optional[str]:
        rpm = rpmfile.RPMFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in rpm.getmembers():
            if "vmlinux" in member.name or "System.map" in member.name:
                print(f" - Extracting {member.name}")
                extracted = rpm.extractfile(member)
                break
        return self.process_gen(member, extracted)

    def process_deb(self, archivedata) -> Optional[str]:
        deb = debfile.DebFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in deb.data.tgz().getmembers():
            if member.name.endswith("vmlinux") or "System.map" in member.name:
                print(f" - Extracting {member.name}")
                extracted = deb.data.get_file(member.name)
                break
        return self.process_gen(member, extracted)

    def process_ddeb(self, archivedata) -> Optional[str]:
        deb = debfile.DebFile(fileobj=archivedata)
        member = None
        extracted = None
        for member in deb.data.tgz().getmembers():
            if "vmlinux" in member.name or "System.map" in member.name:
                print(f" - Extracting {member.name}")
                extracted = deb.data.get_file(member.name)
                break
        return self.process_gen(member, extracted)

    def process_gen(self, member, extracted):
        if not member or not extracted:
            return None
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="vmlinux" if "vmlinux" in member.name else "System.map"
        ) as output:
            print(f" - Writing to {output.name}")
            output.write(extracted.read())
        return output.name
