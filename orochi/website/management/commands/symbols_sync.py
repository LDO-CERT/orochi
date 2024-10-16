import os
import shutil
from glob import glob
from pathlib import Path
from zipfile import ZipFile

import requests
import urllib3
from django.core.management.base import BaseCommand
from extra_settings.models import Setting
from volatility3 import framework

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Command(BaseCommand):
    help = "Sync Volatility Symbols"

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.local_path = Path(Setting.get("VOLATILITY_SYMBOL_PATH"))
        self.online_path = Setting.get("VOLATILITY_SYMBOL_DOWNLOAD_PATH")
        if os.environ.get("http_proxy", None) or os.environ.get("https_proxy", None):
            self.proxies = {
                "http": os.environ.get("http_proxy", None),
                "https": os.environ.get("https_proxy", None),
            }
        else:
            self.proxies = None

    def get_hash_local(self):
        if not Path(self.local_path, "MD5SUMS").exists():
            return None
        hashes = {}
        with Path(self.local_path, "MD5SUMS").open() as f:
            for line in f.readlines():
                try:
                    parts = line.split()
                    hashes[parts[1]] = parts[0]
                except Exception:
                    pass
        return hashes

    def get_hash_online(self, store=False):
        r = requests.get(
            f"{self.online_path}/MD5SUMS", proxies=self.proxies, verify=False
        )
        if r.status_code == 200:
            if store:
                with Path(self.local_path, "MD5SUMS").open(mode="w") as f:
                    f.write(r.text)

            hashes = {}
            for line in r.text.split("\n"):
                try:
                    parts = line.split()
                    hashes[parts[1]] = parts[0]
                except Exception:
                    pass
            return hashes
        return None

    def remove(self, item):
        path = os.path.join(self.local_path, item.split(".")[0])
        self.stdout.write(f"Removing path {path}.")
        files = glob(f"{path}/*")
        for f in files:
            if os.path.isdir(f):
                shutil.rmtree(f)
            elif f.find("added") != -1:
                os.remove(f)

    def download(self, item):
        r = requests.get(
            f"{self.online_path}/{item}", proxies=self.proxies, verify=False
        )
        local_path = Path("/tmp", item)
        if r.status_code == 200:
            with local_path.open(mode="wb") as f:
                f.write(r.content)
            with ZipFile(local_path, "r") as zipObj:
                for name in zipObj.namelist():
                    filetype = item.split(".")[0]
                    ok_path = (
                        Path(self.local_path, filetype)
                        if name.split("/")[0] != filetype
                        else Path(self.local_path)
                    )
                    self.stdout.write(f"NAME: {name} - PATH: {ok_path}")
                    zipObj.extract(name, ok_path)
            return True
        return False

    def handle(self, *args, **kwargs):
        hash_local = self.get_hash_local()
        self.stdout.write(f"Local hash: {hash_local}")
        hash_online = self.get_hash_online()
        self.stdout.write(f"Remote hash: {hash_online}")

        changed = False

        if not hash_online:
            self.stdout.write("Failed to download remote hashes - Exiting")
        else:
            for item in hash_online:
                if not hash_local or hash_local.get(item) != hash_online.get(item):
                    changed = True
                    self.stdout.write(f"Hashes for {item} are different - downloading")
                    self.remove(item)
                    self.stdout.write(f"Starting download of zip symbols {item}.")
                    if self.download(item):
                        self.stdout.write(
                            f"Download of zip symbols completed for {item}."
                        )
                    else:
                        self.stdout.write(f"Download of zip symbols failed for {item}.")
                else:
                    self.stdout.write(f"Hashes for {item} are equal - skipping")
            if changed:
                self.get_hash_online(store=True)
                self.stdout.write("Updating local hashes")
                framework.clear_cache()
                self.stdout.write("Clearing cache")
