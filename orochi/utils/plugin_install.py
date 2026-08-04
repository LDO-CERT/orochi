import logging
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path

import volatility3.plugins
from distributed import get_client
from extra_settings.models import Setting
from volatility3 import framework
from volatility3.framework import contexts


def plugin_install(plugin_path):

    def install_process(bash_script, reqs_script, tmp_folder):
        if bash_script:
            subprocess.run(["apt", "update"], check=True)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write(bash_script)
                script_path = f.name
            try:
                subprocess.run(["bash", script_path], check=True)
            finally:
                os.remove(script_path)
        if reqs_script:
            subprocess.run(
                ["pip", "install", "setuptools<70", "wheel", "six", "cffi"],
                check=True
            )
            subprocess.run(
                ["pip", "install", "--no-build-isolation", "-r", f"{tmp_folder}/requirements.txt"],
                check=True
            )

    try:
        bash_script = None
        reqs_script = False
        py_names = []
        plugin_folder = Path(Setting.get("VOLATILITY_PLUGIN_PATH"))
        tmp_folder = plugin_folder / str(uuid.uuid4())
        os.mkdir(tmp_folder)
        with zipfile.ZipFile(plugin_path, "r") as f:
            for name in f.namelist():
                # Read apt script, no need to persist
                if name.endswith(".sh"):
                    bash_script = f.read(name).decode("utf-8")
                # Move requirements in temp folder
                elif name.lower() == "requirements.txt":
                    reqs_script = True
                    with open(tmp_folder / "requirements.txt", "wb") as reqs:
                        reqs.write(f.read(name))
                # keep script in custom folder
                elif name.endswith(".py"):
                    with open(plugin_folder / name, "wb") as reqs:
                        reqs.write(f.read(name))
                    py_names.append(Path(name).stem)

        # Install all on dask and workers
        install_process(bash_script, reqs_script, tmp_folder)
        dask_client = get_client(address="tcp://scheduler:8786")
        dask_client.run(install_process, bash_script, reqs_script, tmp_folder)
        shutil.rmtree(tmp_folder)

        # after install recover name from installed plugin
        _ = contexts.Context()
        _ = framework.import_files(volatility3.plugins, True)
        plugin_names = []
        for x, y in framework.list_plugins().items():
            for py_name in py_names:
                if x.startswith(f"custom.{py_name}"):
                    plugin_names.append({x: y})
        logging.debug("Plugins installed successfully.")
        return plugin_names
    except Exception as e:
        logging.error(f"Error installing plugin: {e}")
        return []
