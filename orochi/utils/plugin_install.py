import contextlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
import zipfile
from pathlib import Path

import volatility3.plugins
from extra_settings.models import Setting
from volatility3 import framework
from volatility3.framework import contexts

from orochi.backends.dask_client import get_dask_client

logger = logging.getLogger(__name__)


def _run_install_commands(
    bash_script: str | None,
    reqs_content: bytes | None,
    py_files: dict[str, bytes] | None = None,
    plugin_folder_str: str | None = None,
):
    """
    Executes optional apt/bash setup script, writes extracted .py files if missing
    (for remote Dask workers without shared volume), and installs Python requirements.
    """
    if py_files and plugin_folder_str:
        w_folder = Path(plugin_folder_str)
        w_folder.mkdir(parents=True, exist_ok=True)
        for rel_name, content in py_files.items():
            target = (w_folder / rel_name).resolve()
            if target.is_relative_to(w_folder.resolve()):
                target.parent.mkdir(parents=True, exist_ok=True)
                with open(target, "wb") as f:
                    f.write(content)

    apt_path = shutil.which("apt") or "/usr/bin/apt"
    bash_path = shutil.which("bash") or "/bin/bash"

    if bash_script:
        subprocess.run([apt_path, "update"], check=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(bash_script)
            script_path = f.name
        try:
            subprocess.run([bash_path, script_path], check=True)
        finally:
            with contextlib.suppress(OSError):
                os.remove(script_path)

    if reqs_content:
        with tempfile.NamedTemporaryFile(mode="wb", suffix="_requirements.txt", delete=False) as req_f:
            req_f.write(reqs_content)
            req_path = req_f.name
        try:
            uv_path = shutil.which("uv")
            pip_path = shutil.which("pip") or "/app/.venv/bin/pip"
            if uv_path:
                subprocess.run([uv_path, "pip", "install", "-r", req_path], check=True)
            elif os.path.exists(pip_path):
                subprocess.run([pip_path, "install", "-r", req_path], check=True)
            else:
                subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_path], check=True)
        finally:
            with contextlib.suppress(OSError):
                os.remove(req_path)


def plugin_install(plugin_path) -> list[dict]:
    """
    Extracts a custom Volatility 3 plugin .zip archive into VOLATILITY_PLUGIN_PATH,
    installs any bundled requirements.txt / setup .sh locally and across Dask workers,
    and returns a list of discovered `{plugin_name: plugin_class}` dicts.
    """
    tmp_folder = None
    try:
        bash_script: str | None = None
        reqs_content: bytes | None = None
        py_names: list[str] = []
        py_files: dict[str, bytes] = {}

        plugin_folder = Path(Setting.get("VOLATILITY_PLUGIN_PATH"))
        plugin_folder.mkdir(parents=True, exist_ok=True)
        tmp_folder = plugin_folder / f".tmp_{uuid.uuid4()}"
        tmp_folder.mkdir(parents=True, exist_ok=True)

        # Ensure plugin_folder is in volatility3.plugins.__path__
        if str(plugin_folder.resolve()) not in [str(Path(p).resolve()) for p in volatility3.plugins.__path__]:
            volatility3.plugins.__path__.append(str(plugin_folder.resolve()))

        with zipfile.ZipFile(plugin_path, "r") as f:
            for member in f.infolist():
                name = member.filename
                if member.is_dir() or name.startswith("__MACOSX") or Path(name).name.startswith("._"):
                    continue

                base_name = Path(name).name
                if base_name.endswith(".sh"):
                    bash_script = f.read(name).decode("utf-8", errors="replace")
                elif base_name.lower() == "requirements.txt":
                    reqs_content = f.read(name)
                elif base_name.endswith(".py"):
                    # Flatten top-level wrapper folder if the zip contains e.g. repo-main/my_plugin.py
                    # unless it's a standard OS namespace folder (windows, linux, mac, custom)
                    parts = Path(name).parts
                    if len(parts) > 1 and parts[0].lower() not in {"windows", "linux", "mac", "custom"}:
                        rel_path = Path(*parts[1:]) if len(parts) > 1 else Path(base_name)
                    else:
                        rel_path = Path(name)

                    if not rel_path.parts:
                        rel_path = Path(base_name)

                    target = (plugin_folder / rel_path).resolve()
                    if not target.is_relative_to(plugin_folder.resolve()):
                        raise ValueError(f"Invalid path in plugin archive: {name}")

                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = f.read(name)
                    with open(target, "wb") as out_f:
                        out_f.write(data)
                    py_files[str(rel_path)] = data
                    if base_name != "__init__.py":
                        py_names.append(Path(base_name).stem)

        if not py_names:
            logger.warning("No Python plugin files found in archive %s", plugin_path)
            return []

        # Run local installation of dependencies
        _run_install_commands(bash_script, reqs_content)

        # Broadcast to Dask workers if cluster is reachable
        try:
            dask_client = get_dask_client()
            dask_client.run(
                _run_install_commands,
                bash_script,
                reqs_content,
                py_files,
                str(plugin_folder),
            )
        except Exception as dask_err:
            logger.debug("Skipping Dask worker broadcast during plugin_install: %s", dask_err)

        # Discover installed plugin classes from Volatility 3 framework
        _ = contexts.Context()
        failures = framework.import_files(volatility3.plugins, True)
        if failures:
            logger.debug("Volatility import_files reported failures: %s", failures)

        all_plugins = framework.list_plugins()
        plugin_names = []
        seen = set()
        for plg_name, plg_cls in all_plugins.items():
            for py_name in py_names:
                if (
                    plg_name.startswith(f"custom.{py_name}.")
                    or plg_name.startswith(f"{py_name}.")
                    or f".{py_name}." in plg_name
                    or plg_name == py_name
                ) and plg_name not in seen:
                    seen.add(plg_name)
                    plugin_names.append({plg_name: plg_cls})

        logger.debug("Plugins installed successfully: %s", [list(p.keys())[0] for p in plugin_names])
        return plugin_names
    except Exception as e:
        logger.error("Error installing plugin: %s", e)
        return []
    finally:
        if tmp_folder and tmp_folder.exists():
            shutil.rmtree(tmp_folder, ignore_errors=True)
