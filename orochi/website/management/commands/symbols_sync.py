from django.core.management.base import BaseCommand

import os
import sys
import requests
import shutil
from zipfile import ZipFile, is_zipfile


class Command(BaseCommand):
    help = "Sync Volatility Symbols"

    def __init__(self):
        self.local_path = "/src/volatility/volatility/symbols"
        self.online_path = (
            "https://downloads.volatilityfoundation.org/volatility3/symbols"
        )
        self.proxies = {
            "http": os.environ.get("http_proxy", None),
            "https": os.environ.get("https_proxy", None),
        }

    def get_hash_local(self):
        if os.path.exists("{}/{}".format(self.local_path, "MD5SUMS")):
            hashes = {}
            with open("{}/{}".format(self.local_path, "MD5SUMS"), "r") as f:
                for line in f.readlines():
                    try:
                        parts = line.split()
                        hashes[parts[1]] = parts[0]
                    except:
                        pass
            return hashes
        else:
            return None

    def get_hash_online(self, store=False):
        r = requests.get(
            "{}/{}".format(self.online_path, "MD5SUMS"), proxies=self.proxies
        )
        if r.status_code == 200:
            if store:
                with open("{}/{}".format(self.local_path, "MD5SUMS"), "w") as f:
                    f.write(r.text)

            hashes = {}
            for line in r.text.split("\n"):
                try:
                    parts = line.split()
                    hashes[parts[1]] = parts[0]
                except:
                    pass
            return hashes
        else:
            return None

    def remove(self, item):
        path = "{}/{}/".format(self.local_path, item.split(".")[0])
        print("Removing path {}.".format(path))
        shutil.rmtree(path, ignore_errors=True)

    def download(self, item):
        r = requests.get("{}/{}".format(self.online_path, item), proxies=self.proxies)
        local_path = "/tmp/{}".format(item)
        if r.status_code == 200:
            with open(local_path, "wb") as f:
                f.write(r.content)
            with ZipFile(local_path, "r") as zipObj:
                for name in zipObj.namelist():
                    zipObj.extract(
                        name, "{}/{}".format(self.local_path, item.split(".")[0])
                    )
            return True
        return False

    def handle(self, *args, **kwargs):
        hash_local = self.get_hash_local()
        print("Local hash: {}".format(hash_local))
        hash_online = self.get_hash_online()
        print("Remote hash: {}".format(hash_online))
        if not hash_online:
            print("Failed to download remote hashes - Exiting")
            sys.exit()
        for item in hash_online.keys():
            if not hash_local or hash_local[item] != hash_online[item]:
                print("Hashes for {} are different - downloading".format(item))
                self.remove(item)
                if self.download(item):
                    print("Download of zip symbols completed for {}.".format(item))
                else:
                    print("Download of zip symbols failed for {}.".format(item))
            else:
                print("Hashes for {} are equal - skipping".format(item))
        self.get_hash_online(store=True)
