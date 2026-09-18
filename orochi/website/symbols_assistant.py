import logging
import re
import shutil
from pathlib import Path
from typing import Any

from django.conf import settings
from extra_settings.models import Setting
from volatility3 import framework
from volatility3.framework import automagic, constants, contexts
from volatility3.framework.symbols import intermed

from orochi.utils.download_symbols import Downloader
from orochi.website.defaults import (
    DUMP_STATUS_COMPLETED,
    RESULT_STATUS_DISABLED,
    RESULT_STATUS_NOT_STARTED,
    SymbolStatus,
)

try:
    from orochi.website.defaults import BANNER_REGEX
except ImportError:
    BANNER_REGEX = r'^"?Linux version (?P<kernel>\S+) (?P<build>.+) \(((?P<gcc>gcc.+)) #(?P<number>\d+)(?P<info>.+)$"?'

logger = logging.getLogger(__name__)


def ensure_symbol_environment(symbol_base: str | None = None) -> dict[str, Any]:
    """
    Ensure symbol directory hierarchy, __init__.py with SYMBOL_BASEPATHS,
    and required Windows intermediate tables (pe.json, pdb.json, kdbg.json)
    exist to eliminate shadowing and 'No symbol files found: pe' issues (#1310).
    """
    actions_taken = []
    if not symbol_base:
        try:
            from extra_settings.models import Setting

            symbol_base = Setting.get("VOLATILITY_SYMBOL_PATH")
        except Exception:
            symbol_base = None

    if not symbol_base:
        symbol_base = "/app/.venv/lib/python3.13/site-packages/volatility3/symbols"

    base_path = Path(symbol_base)
    base_path.mkdir(parents=True, exist_ok=True)

    # 1. Ensure subdirectories
    for subdir in ["added", "windows", "linux", "mac"]:
        sub_dir_path = base_path / subdir
        if not sub_dir_path.exists():
            sub_dir_path.mkdir(parents=True, exist_ok=True)
            actions_taken.append(f"Created directory: {sub_dir_path}")

    # 2. Ensure __init__.py in symbol base path with constants.SYMBOL_BASEPATHS
    init_file = base_path / "__init__.py"
    init_content = (
        "# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0\n"
        "# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0\n"
        '"""Defines the symbols architecture.\n\n'
        "This is the namespace for all volatility symbols, and determines the\n"
        'path for loading symbol ISF files\n"""\n'
        "from volatility3.framework import constants\n\n"
        "__path__ = constants.SYMBOL_BASEPATHS\n"
    )
    if not init_file.exists() or "__path__" not in init_file.read_text(errors="ignore"):
        init_file.write_text(init_content)
        actions_taken.append(f"Created/repaired symbols __init__.py at {init_file}")

    # 3. Ensure windows sub-package __init__.py
    win_init = base_path / "windows" / "__init__.py"
    if not win_init.exists():
        win_init.write_text('"""Windows symbols namespace."""\n')
        actions_taken.append("Created windows/__init__.py")

    # 4. Dynamically patch volatility3.symbols.__path__ in runtime memory
    try:
        import volatility3.symbols

        current_paths = list(getattr(volatility3.symbols, "__path__", []))
        changed = False
        for bp in constants.SYMBOL_BASEPATHS:
            if bp not in current_paths:
                current_paths.append(bp)
                changed = True
        if changed:
            volatility3.symbols.__path__ = current_paths
            actions_taken.append("Patched volatility3.symbols.__path__ with SYMBOL_BASEPATHS")
    except Exception as exc:
        logger.warning(f"Could not patch volatility3.symbols.__path__: {exc}")

    # 5. Safeguard intermediate Windows tables: pe.json, pdb.json, kdbg.json
    try:
        import volatility3.framework.symbols.windows as fw_win_mod

        fw_win_dir = Path(fw_win_mod.__file__).parent
        dst_win_dir = base_path / "windows"
        for table_file in ["pe.json", "pdb.json", "kdbg.json"]:
            dst_file = dst_win_dir / table_file
            src_file = fw_win_dir / table_file
            if not dst_file.exists() and src_file.exists():
                shutil.copy2(src_file, dst_file)
                actions_taken.append(f"Copied fallback table {table_file} into {dst_win_dir}")
    except Exception as exc:
        logger.warning(f"Could not copy framework Windows tables: {exc}")

    return {
        "status": "ok",
        "symbol_path": str(base_path),
        "actions_taken": actions_taken,
    }


def distribute_symbols_to_workers() -> dict[str, Any]:
    """
    Distribute symbol environment and cache refresh to all connected Dask workers.
    """
    local_env = ensure_symbol_environment()
    symbol_base = local_env.get("symbol_path", "/app/.venv/lib/python3.13/site-packages/volatility3/symbols")

    # Refresh local cache
    try:
        from orochi.utils.volatility_dask_elk import refresh_symbols

        refresh_symbols()
    except Exception as exc:
        logger.warning(f"Local refresh_symbols error: {exc}")

    framework.clear_cache()

    worker_results: dict[str, Any] = {}
    try:
        from distributed import Client

        scheduler_url = getattr(settings, "DASK_SCHEDULER_URL", "tcp://scheduler:8786")
        client = Client(scheduler_url, timeout="3s")

        # Run environment and cache refresh on all workers
        w_env = client.run(ensure_symbol_environment, symbol_base=symbol_base)
        from orochi.utils.volatility_dask_elk import refresh_symbols

        w_ref = client.run(refresh_symbols)

        for w_id in w_env:
            worker_results[w_id] = {
                "environment": w_env.get(w_id),
                "cache_refreshed": True if w_id in w_ref else False,
            }
        logger.info(f"Symbols successfully distributed to {len(worker_results)} workers.")
    except Exception as exc:
        logger.warning(f"Could not contact Dask scheduler for symbol distribution: {exc}")

    return {
        "local": local_env,
        "worker_count": len(worker_results),
        "workers": worker_results,
    }


def check_symbols_health() -> dict[str, Any]:
    """
    Perform a complete health check of the symbol subsystem:
    - Verifies base symbol path and __init__.py integrity
    - Tests PE table resolution (#1310)
    - Counts loaded banners (Linux, Mac) and Windows PDB profiles
    - Audits Dask workers connection and sync status
    """
    ensure_symbol_environment()

    symbol_base = Setting.get("VOLATILITY_SYMBOL_PATH") or "/app/.venv/lib/python3.13/site-packages/volatility3/symbols"
    base_path = Path(symbol_base)

    # 1. Test PE symbol table loading
    pe_healthy = False
    pe_error = None
    try:
        ctx = contexts.Context()
        intermed.IntermediateSymbolTable.create(ctx, "health_check", "windows", "pe")
        pe_healthy = True
    except Exception as exc:
        pe_error = str(exc)

    # 2. Count registered banners
    linux_banners = 0
    mac_banners = 0
    try:
        ctx = contexts.Context()
        automagics = automagic.available(ctx)
        for auto in automagics:
            if auto._config_path == "automagic.LinuxSymbolFinder" and hasattr(auto, "banners"):
                linux_banners = len(auto.banners)
            elif auto._config_path == "automagic.MacSymbolFinder" and hasattr(auto, "banners"):
                mac_banners = len(auto.banners)
    except Exception as exc:
        logger.warning(f"Error reading automagics banners: {exc}")

    # 3. Count Windows PDB subdirectories & added ISFs
    windows_pdbs = 0
    win_dir = base_path / "windows"
    if win_dir.exists():
        windows_pdbs = len([d for d in win_dir.iterdir() if d.is_dir()])

    added_files = 0
    added_dir = base_path / "added"
    if added_dir.exists():
        added_files = len([f for f in added_dir.iterdir() if f.is_file()])

    # 4. Check worker connectivity
    worker_count = 0
    worker_keys = []
    try:
        from distributed import Client

        scheduler_url = getattr(settings, "DASK_SCHEDULER_URL", "tcp://scheduler:8786")
        client = Client(scheduler_url, timeout="2s")
        worker_info = client.scheduler_info().get("workers", {})
        worker_count = len(worker_info)
        worker_keys = list(worker_info.keys())
    except Exception:
        pass

    return {
        "status": "healthy" if pe_healthy else "degraded",
        "symbol_path": str(base_path),
        "pe_lookup_operational": pe_healthy,
        "pe_error": pe_error,
        "linux_banners_count": linux_banners,
        "mac_banners_count": mac_banners,
        "windows_pdb_profiles_count": windows_pdbs,
        "custom_added_isf_count": added_files,
        "dask_workers_count": worker_count,
        "dask_workers": worker_keys,
    }


def diagnose_symbols(dump) -> dict[str, Any]:
    """
    Diagnose symbol/kernel requirements for a memory dump and classify status:
    - detect OS, banner, kernel, distro, architecture
    - classify symbol status: ok, missing, wrong_kernel, unsupported, stale
    - propose concrete actions (1-click auto download / DWARF-ISF build / manual upload)
    - persist symbol_status per dump
    """
    ensure_symbol_environment()

    os_type = dump.operating_system
    banner_str = dump.banner or ""
    kernel_version = None
    distro = "Unknown"
    arch = "amd64"
    status = SymbolStatus.UNKNOWN
    message = ""
    remediation_type = "none"
    download_urls = []
    can_auto_resolve = False

    # 1. WINDOWS DIAGNOSIS
    if os_type == "Windows":
        # Check PE table resolution
        try:
            ctx = contexts.Context()
            intermed.IntermediateSymbolTable.create(ctx, "diag", "windows", "pe")
            pe_ok = True
        except Exception as exc:
            pe_ok = False
            message = f"Windows PE intermediate table lookup failed: {exc}"

        if not pe_ok:
            status = SymbolStatus.STALE
            message = (
                "PE intermediate symbol table not found (Issue #1310). Symbol path is shadowed or missing pe.json."
            )
            remediation_type = "repair_environment"
            can_auto_resolve = True
        else:
            # Check if Windows symbol tables exist
            symbol_base = (
                Setting.get("VOLATILITY_SYMBOL_PATH") or "/app/.venv/lib/python3.13/site-packages/volatility3/symbols"
            )
            win_dir = Path(symbol_base) / "windows"
            ntkrnl_exists = any(win_dir.glob("ntkrnl*")) or (Path(symbol_base) / "added").glob("*.json")
            if ntkrnl_exists:
                status = SymbolStatus.OK
                message = "Windows symbols and intermediate tables are installed and ready."
                remediation_type = "none"
                can_auto_resolve = False
            else:
                status = SymbolStatus.MISSING
                message = "No Windows kernel PDB symbol tables found locally. Official symbols can be synced or kernel PDB uploaded."
                remediation_type = "sync_symbols"
                can_auto_resolve = True

    # 2. LINUX DIAGNOSIS
    elif os_type == "Linux":
        # If banner is missing on dump, try to retrieve it from banners.Banners result
        if not banner_str:
            try:
                from orochi.utils.volatility_dask_elk import get_banner

                banner_res = dump.result_set.filter(plugin__name="banners.Banners").first()
                if banner_res and (banner_val := get_banner(banner_res)):
                    banner_str = banner_val.strip("\"'")
                    dump.banner = banner_str
                    dump.save(update_fields=["banner"])
            except Exception as exc:
                logger.debug(f"Could not retrieve banner from result: {exc}")

        if not banner_str:
            status = SymbolStatus.MISSING
            message = "Kernel banner is missing. Run 'banners.Banners' plugin to extract the Linux kernel banner."
            remediation_type = "run_banner_plugin"
            can_auto_resolve = False
        else:
            # Parse banner
            match = re.match(BANNER_REGEX, banner_str)
            if match:
                m_dict = match.groupdict()
                kernel_version = m_dict.get("kernel")
                gcc_info = (m_dict.get("gcc") or "").lower()
                extra_info = (m_dict.get("info") or "").lower()

                if "ubuntu" in gcc_info or "ubuntu" in extra_info:
                    distro = "Ubuntu"
                elif "debian" in gcc_info or "debian" in extra_info:
                    distro = "Debian"
                elif "fedora" in gcc_info or "fedora" in extra_info or "fc" in (kernel_version or ""):
                    distro = "Fedora"
                elif "red hat" in gcc_info or "el" in (kernel_version or "") or "rhel" in gcc_info:
                    distro = "RedHat/CentOS"
                else:
                    distro = "Generic Linux"

                if "arm64" in banner_str.lower() or "aarch64" in banner_str.lower():
                    arch = "arm64"
                elif "i386" in banner_str.lower() or "i686" in banner_str.lower():
                    arch = "i386"
                else:
                    arch = "amd64"
            else:
                kernel_version = banner_str.split()[2] if len(banner_str.split()) > 2 else "unknown"

            # Check if matching banner is loaded in automagic LinuxSymbolFinder
            matched_banner = False
            try:
                ctx = contexts.Context()
                automagics = automagic.available(ctx)
                if l_finders := [x for x in automagics if x._config_path == "automagic.LinuxSymbolFinder"]:
                    for active_b in l_finders[0].banners:
                        if not active_b:
                            continue
                        clean_b = active_b.rstrip(b"\n\00").decode("utf-8", errors="ignore")
                        if (m_act := re.match(BANNER_REGEX, clean_b)) and m_act.groupdict().get(
                            "kernel"
                        ) == kernel_version:
                            matched_banner = True
                            break
            except Exception as exc:
                logger.warning(f"Error checking active banners: {exc}")

            if matched_banner:
                status = SymbolStatus.OK
                message = f"Symbol table for Linux kernel {kernel_version} ({distro} {arch}) is installed and active."
                remediation_type = "none"
                can_auto_resolve = False
            else:
                # Missing or mismatch: check if download URL is available
                urls = []
                if dump.suggested_symbols_path:
                    urls = [u for u in dump.suggested_symbols_path if u and not u.startswith("[")]

                if not urls and banner_str:
                    try:
                        from orochi.utils.volatility_dask_elk import get_path_from_banner

                        found_urls = get_path_from_banner(banner_str)
                        urls = [u for u in found_urls if u and not u.startswith("[")]
                    except Exception as exc:
                        logger.debug(f"Error evaluating get_path_from_banner: {exc}")

                download_urls = urls
                if urls:
                    status = SymbolStatus.MISSING
                    message = (
                        f"Symbols for kernel {kernel_version} ({distro} {arch}) are missing locally. "
                        f"Upstream debug package is available for 1-click download and DWARF-ISF compilation."
                    )
                    remediation_type = "auto_download"
                    can_auto_resolve = True
                else:
                    status = SymbolStatus.UNSUPPORTED
                    message = (
                        f"No automated repository package found for kernel {kernel_version} ({distro} {arch}). "
                        "Please upload a debug package (.deb, .ddeb, .rpm) or a compiled ISF (.json.xz)."
                    )
                    remediation_type = "manual_upload"
                    can_auto_resolve = False

    # 3. MAC / OTHER DIAGNOSIS
    else:
        status = SymbolStatus.MISSING
        message = f"Symbol resolution for {os_type} requires Apple KDK / symbol package upload."
        remediation_type = "manual_upload"
        can_auto_resolve = False

    # Persist symbol_status to dump model
    if dump.symbol_status != status:
        dump.symbol_status = status
        dump.save(update_fields=["symbol_status"])

    actions = []
    if can_auto_resolve:
        actions.append(
            {
                "type": remediation_type,
                "label": "Auto-Resolve & Fix",
                "urls": download_urls,
                "remediation_type": remediation_type,
            }
        )
    actions.append(
        {
            "type": "upload",
            "label": "Upload Symbol / Package",
        }
    )

    return {
        "dump_index": dump.index,
        "dump_name": dump.name,
        "operating_system": os_type,
        "banner": banner_str,
        "kernel": kernel_version,
        "distro": distro,
        "arch": arch,
        "symbol_status": status,
        "symbol_status_label": SymbolStatus(status).label if status in SymbolStatus.values else str(status),
        "message": message,
        "remediation_type": remediation_type,
        "suggested_paths": download_urls,
        "can_auto_resolve": can_auto_resolve,
        "actions": actions,
    }


def auto_resolve_symbols(
    dump,
    custom_path: list[str] | None = None,
    async_task: bool = True,
    user=None,
) -> dict[str, Any]:
    """
    Execute 1-click automated remediation:
    1. Ensure symbol environment and intermediate Windows tables.
    2. For Linux: enqueue/execute Dask background task to download debug package and compile DWARF-ISF.
    3. For Windows: ensure PE table, download/sync Windows symbols if needed.
    4. Distribute symbols to Dask workers.
    5. Recheck check_runnable; on success mark dump as COMPLETED and re-enable plugins.
    """
    ensure_symbol_environment()

    from orochi.utils.volatility_dask_elk import check_runnable

    os_type = dump.operating_system

    if os_type == "Windows":
        # Repair environment and distribute
        distribute_symbols_to_workers()

        # Check if runnable
        if check_runnable(dump.pk, dump.operating_system, dump.banner):
            dump.symbol_status = SymbolStatus.OK
            dump.status = DUMP_STATUS_COMPLETED
            dump.result_set.filter(result=RESULT_STATUS_DISABLED).update(result=RESULT_STATUS_NOT_STARTED)
            dump.save(update_fields=["symbol_status", "status"])
            return {
                "success": True,
                "message": "Windows PE symbol environment repaired and verified successfully.",
                "symbol_status": SymbolStatus.OK,
            }
        else:
            return {
                "success": False,
                "errors": "Windows environment repaired, but kernel PDB profile is not available. Please upload the kernel PDB or sync symbols.",
                "symbol_status": dump.symbol_status,
            }

    elif os_type == "Linux":
        urls = custom_path or dump.suggested_symbols_path
        if not urls and dump.banner:
            from orochi.utils.volatility_dask_elk import get_path_from_banner

            urls = [u for u in get_path_from_banner(dump.banner) if u and not u.startswith("[")]

        if not urls:
            return {
                "success": False,
                "errors": "No automated download URL available for this kernel banner. Please specify a URL or upload the package.",
                "symbol_status": SymbolStatus.UNSUPPORTED,
            }

        if async_task:
            from orochi.website.tasks import download_symbols_task

            user_pk = getattr(user, "pk", None)
            task_result = download_symbols_task.enqueue(
                url_list=urls,
                dump_pk=dump.pk,
                user_pk=user_pk,
            )
            return {
                "success": True,
                "message": "Symbol download and compilation task submitted to Dask.",
                "task_id": getattr(task_result, "id", None),
                "symbol_status": dump.symbol_status,
            }

        try:
            downloader = Downloader(url_list=urls)
            downloader.download_list()
        except Exception as exc:
            logger.error(f"Downloader failed: {exc}")
            return {
                "success": False,
                "errors": f"Failed downloading or compiling debug package: {exc}",
                "symbol_status": dump.symbol_status,
            }

        # Distribute newly compiled symbols to all workers
        distribute_symbols_to_workers()

        if check_runnable(dump.pk, dump.operating_system, dump.banner):
            dump.symbol_status = SymbolStatus.OK
            dump.status = DUMP_STATUS_COMPLETED
            dump.result_set.filter(result=RESULT_STATUS_DISABLED).update(result=RESULT_STATUS_NOT_STARTED)
            dump.save(update_fields=["symbol_status", "status"])
            return {
                "success": True,
                "message": "Symbols downloaded, compiled with DWARF-ISF, and distributed to workers successfully.",
                "symbol_status": SymbolStatus.OK,
            }
        else:
            return {
                "success": False,
                "errors": "Symbols were compiled, but could not satisfy the kernel banner requirements.",
                "symbol_status": dump.symbol_status,
            }

    return {
        "success": False,
        "errors": f"Automated remediation not supported for operating system: {os_type}",
        "symbol_status": dump.symbol_status,
    }
