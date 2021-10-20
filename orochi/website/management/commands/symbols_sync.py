import os
import requests
import shutil
from zipfile import ZipFile
from volatility3 import framework
from pathlib import Path
from glob import glob

from django.core.management.base import BaseCommand
from django.conf import settings

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Command(BaseCommand):
    help = "Sync Volatility Symbols"

    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)
        self.local_path = Path(settings.VOLATILITY_SYMBOL_PATH)
        self.online_path = settings.VOLATILITY_SYMBOL_DOWNLOAD_PATH
        if os.environ.get("http_proxy", None) or os.environ.get("https_proxy", None):
            self.proxies = {
                "http": os.environ.get("http_proxy", None),
                "https": os.environ.get("https_proxy", None),
            }
        else:
            self.proxies = None

    def get_hash_local(self):
        if Path(self.local_path, "MD5SUMS").exists():
            hashes = {}
            with Path(self.local_path, "MD5SUMS").open() as f:
                for line in f.readlines():
                    try:
                        parts = line.split()
                        hashes[parts[1]] = parts[0]
                    except:
                        pass
            return hashes
        return None

    def get_hash_online(self, store=False):
        r = requests.get(
            "{}/{}".format(self.online_path, "MD5SUMS"),
            proxies=self.proxies,
            verify=False,
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
                except:
                    pass
            return hashes
        return None

    def remove(self, item):
        path = os.path.join(self.local_path, item.split(".")[0])
        self.stdout.write("Removing path {}.".format(path))
        files = glob("{}/*".format(path))
        for f in files:
            if os.path.isdir(f):
                shutil.rmtree(f)
            else:
                if f.find("added") != -1:
                    os.remove(f)

    def download(self, item):
        r = requests.get(
            "{}/{}".format(self.online_path, item), proxies=self.proxies, verify=False
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
                    self.stdout.write("NAME: {} - PATH: {}".format(name, ok_path))
                    zipObj.extract(name, ok_path)
            return True
        return False

    def handle(self, *args, **kwargs):
        hash_local = self.get_hash_local()
        self.stdout.write("Local hash: {}".format(hash_local))
        hash_online = self.get_hash_online()
        self.stdout.write("Remote hash: {}".format(hash_online))

        changed = False

        if not hash_online:
            self.stdout.write("Failed to download remote hashes - Exiting")
        else:
            for item in hash_online:
                if not hash_local or hash_local.get(item, None) != hash_online.get(
                    item, None
                ):
                    changed = True
                    self.stdout.write(
                        "Hashes for {} are different - downloading".format(item)
                    )
                    self.remove(item)
                    self.stdout.write(
                        "Starting download of zip symbols {}.".format(item)
                    )
                    if self.download(item):
                        self.stdout.write(
                            "Download of zip symbols completed for {}.".format(item)
                        )
                    else:
                        self.stdout.write(
                            "Download of zip symbols failed for {}.".format(item)
                        )
                else:
                    self.stdout.write("Hashes for {} are equal - skipping".format(item))
            if changed:
                self.get_hash_online(store=True)
                self.stdout.write("Updating local hashes")
                framework.clear_cache()
                self.stdout.write("Clearing cache")
