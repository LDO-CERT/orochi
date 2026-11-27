import concurrent.futures
import contextlib
import json
import logging
import lzma
import os
import shutil
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlparse

import magic
import requests
from django.conf import settings
from django.http import HttpRequest
from django.shortcuts import get_object_or_404
from django.utils.text import slugify
from extra_settings.models import Setting
from ninja import File, Form, Query, Router, Status
from ninja.files import UploadedFile
from ninja.pagination import paginate
from volatility3.framework import automagic, contexts

from orochi.api.models import (
    BtfGenerateIn,
    CustomSymbolsPagination,
    DwarfGenerateIn,
    ErrorsOut,
    ISFIn,
    SuccessResponse,
    SymbolsBannerIn,
    SymbolsOut,
    TableFilter,
    UploadFileIn,
)
from orochi.api.permissions import ninja_role_required
from orochi.api.security import dual_auth, validate_public_https_url
from orochi.utils.volatility_dask_elk import refresh_symbols
from orochi.website.models import Dump
from orochi.website.roles import ROLE_ADMIN, ROLE_ANALYST
from orochi.website.storage import allowed_upload_source_roots, resolve_path_within, sanitize_filename
from orochi.website.tasks import download_symbols_task, generate_btf_isf_task, generate_dwarf_isf_task

logger = logging.getLogger(__name__)
router = Router()


@router.get("/", auth=dual_auth, url_name="list_symbols", response=list[SymbolsOut])
@paginate(CustomSymbolsPagination)
def list_symbols(
    request: HttpRequest,
    draw: int | None = 1,
    filters: TableFilter = Query(default_factory=TableFilter),
):
    """List the Volatility symbol tables (ISF) available to the framework."""
    symbols = []

    ctx = contexts.Context()
    automagics = automagic.available(ctx)
    if banners := [x for x in automagics if x._config_path == "automagic.SymbolFinder"]:
        banner = banners[0].banners
    else:
        banner = []

    request.draw = draw if draw is not None else 1
    request.total = len(banner)
    request.search = filters.search or None

    search_term = filters.search.strip().lower() if filters.search else None

    for k, v in banner.items():
        try:
            k = k.decode("utf-8")
            v = str(v)
        except AttributeError:
            k = str(k)

        if search_term and (search_term not in k.lower() and search_term not in v.lower()):
            continue

        if "file://" in v:
            path = v.replace("file://", "").replace(Setting.get("VOLATILITY_SYMBOL_PATH"), "")
            action = ("list", "-") if "/added/" not in v else ("delete", path)
        else:
            path = v
            action = ("down", v)

        symbols.append(SymbolsOut(id=k, path=path, action=action))

    # Apply sorting by Key (col 0) or Path (col 1)
    reverse = filters.order_dir == "desc"
    order_col = filters.order_column if filters.order_column is not None else 1
    if order_col == 0:
        symbols.sort(key=lambda s: s.id.lower(), reverse=reverse)
    elif order_col == 1:
        symbols.sort(key=lambda s: s.path.lower(), reverse=reverse)

    return symbols


@router.post(
    "/banner",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def banner_symbols(request, payload: SymbolsBannerIn):
    """
    Handles the POST request to download banner symbols based on the provided payload.
    It checks the status of the download and updates the corresponding dump object accordingly.

    Args:
        request: The HTTP request object.
        payload (SymbolsBannerIn): The input data containing the index and path for the symbols.

    Returns:
        tuple: A tuple containing the HTTP status code and a message or error details.

    Raises:
        Exception: If an error occurs during the download process or while updating the dump status.
    """
    try:
        dump = get_object_or_404(Dump, index=payload.index)

        download_symbols_task.enqueue(
            url_list=payload.path,
            dump_pk=dump.pk,
            user_pk=request.user.pk,
        )
        return Status(200, {"message": "Symbol download and compilation task queued successfully."})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


def _validate_isf_file(filepath: str) -> None:
    """Validate that a non-archive uploaded symbol file is valid JSON (or XZ-compressed JSON) ISF."""
    p = Path(filepath)
    name_lower = p.name.lower()
    if name_lower.endswith(".json.xz") or name_lower.endswith(".xz"):
        with lzma.open(p, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
    elif name_lower.endswith(".json"):
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        raise ValueError(
            f"Unsupported symbol file '{p.name}'. Upload an ISF .json / .json.xz file or a compressed archive."
        )
    if not isinstance(data, dict):
        raise ValueError(f"Invalid ISF symbol file '{p.name}': root element must be a JSON object.")


@router.post(
    "/upload",
    url_name="upload_symbols",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def upload_symbols(
    request,
    payload: UploadFileIn | None = None,
    symbols: list[UploadedFile] | None = File(None),
):
    """
    Uploads a list of symbol files to a specified directory and extracts them if they are in a compressed format. This function handles file writing and type checking to ensure proper processing of the uploaded symbols.

    Args:
        request: The HTTP request object.
        symbols (List[UploadedFile]): A list of uploaded files representing the symbols to be processed.

    Returns:
        tuple: A tuple containing the HTTP status code and a message indicating the result of the upload.

    Raises:
        HttpResponse: Returns a 400 Bad Request response if an error occurs during the upload process.
    """
    try:
        seven_z_path = shutil.which("7z") or "/usr/bin/7z"
        path = Path(Setting.get("VOLATILITY_SYMBOL_PATH")) / "added"
        path.mkdir(parents=True, exist_ok=True)
        archive_mimes = {
            "application/zip",
            "application/x-7z-compressed",
            "application/x-rar",
            "application/gzip",
            "application/x-tar",
        }
        if payload is None:
            raw_payload = request.POST.get("payload")
            if raw_payload:
                with contextlib.suppress(Exception):
                    payload = UploadFileIn(**json.loads(raw_payload))
            elif "application/json" in (request.content_type or "").lower() and request.body:
                with contextlib.suppress(Exception):
                    payload = UploadFileIn(**json.loads(request.body))

        if payload and payload.info:
            allowed_roots = allowed_upload_source_roots()
            for item in payload.info:
                start = item.local_folder.replace(
                    "/upload/upload",
                    str(Path(settings.MEDIA_ROOT) / "uploads"),
                )
                if start.startswith("/media/tmp/"):
                    start = str(Path(settings.MEDIA_ROOT) / "tmp" / start.removeprefix("/media/tmp/"))
                source_path = resolve_path_within(start, allowed_roots, must_exist_file=True)
                safe_name = sanitize_filename(item.original_name or source_path.name)
                filepath = str(resolve_path_within(path / safe_name, [path]))
                shutil.move(str(source_path), filepath)
                filetype = magic.from_file(filepath, mime=True)
                if filetype in archive_mimes:
                    subprocess.call([seven_z_path, "e", filepath, f"-o{path}", "-y"])
                    Path(filepath).unlink(missing_ok=True)
                else:
                    try:
                        _validate_isf_file(filepath)
                    except Exception:
                        Path(filepath).unlink(missing_ok=True)
                        raise
        elif symbols:
            for symbol in symbols:
                safe_name = sanitize_filename(symbol.name)
                filepath = str(resolve_path_within(path / safe_name, [path]))
                with open(filepath, "wb") as f:
                    f.write(symbol.read())
                filetype = magic.from_file(filepath, mime=True)
                if filetype in archive_mimes:
                    subprocess.call([seven_z_path, "e", filepath, f"-o{path}", "-y"])
                    Path(filepath).unlink(missing_ok=True)
                else:
                    try:
                        _validate_isf_file(filepath)
                    except Exception:
                        Path(filepath).unlink(missing_ok=True)
                        raise
        else:
            return Status(400, {"errors": "No symbol files provided."})
        refresh_symbols()
        return Status(200, {"message": "Symbols uploaded."})

    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete(
    "/delete",
    url_name="delete_symbol",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut, 404: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def delete_symbol(request, path):
    """Delete a specific symbol file from the symbols directory.

    Attempts to delete a symbol file located in the added symbols path. If the file exists and is within the added directory,
    it will be removed and symbols will be refreshed.
    """
    try:
        base_root = Path(Setting.get("VOLATILITY_SYMBOL_PATH"))
        added_root = base_root / "added"
        candidate = base_root / str(path).lstrip("/")
        resolved = resolve_path_within(candidate, [added_root], must_exist_file=True)
        os.unlink(resolved)
        threading.Thread(target=refresh_symbols, daemon=True).start()
        return Status(200, {"message": "Symbols deleted."})
    except FileNotFoundError:
        return Status(404, {"errors": "Symbol file not found."})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/isf_download",
    url_name="isf_download",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def isf_download(request, payload: ISFIn | None = None):
    """Download and save symbol files from a given URL."""
    try:
        if payload is None:
            raw_path = request.POST.get("path")
            if not raw_path and request.POST.get("payload"):
                with contextlib.suppress(Exception):
                    raw_path = json.loads(request.POST["payload"]).get("path")
            if not raw_path and request.body:
                with contextlib.suppress(Exception):
                    raw_path = json.loads(request.body).get("path")
            if not raw_path:
                return Status(400, {"errors": "Missing ISF server URL ('path')."})
            payload = ISFIn(path=raw_path)

        path = validate_public_https_url(payload.path)
        domain = slugify(urlparse(path).netloc)
        media_path = Path(f"{Setting.get('VOLATILITY_SYMBOL_PATH')}/{domain}")
        media_path.mkdir(exist_ok=True, parents=True)
        try:
            data = json.loads(requests.get(path, timeout=60).content)
        except Exception:
            return Status(400, {"errors": "Error parsing symbols"})

        def download_file(url, dest_path):
            safe_url = validate_public_https_url(url)
            resolved_dest = resolve_path_within(dest_path, [media_path])
            try:
                response = requests.get(safe_url, timeout=300)
                with open(resolved_dest, "wb") as f:
                    f.write(response.content)
            except Exception as excp:
                logger.warning("ISF symbol download failed for %s: %s", safe_url, excp)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            for key in data:
                if key not in ["linux", "mac", "windows"]:
                    continue
                for urls in data[key].values():
                    for url in urls:
                        filename = sanitize_filename(url.split("/")[-1])
                        filepath = media_path / filename
                        executor.submit(download_file, url, filepath)

        refresh_symbols()
        return Status(200, {"message": "Symbols downloaded successfully"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/dwarf_generate",
    url_name="dwarf_generate",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ANALYST)
def dwarf_generate_symbols(
    request,
    elf: UploadedFile | None = File(None),
    system_map: UploadedFile | None = File(None),
    elf_path: str | None = Form(None),
    system_map_path: str | None = Form(None),
    output_name: str | None = Form(None),
    dump_index: str | None = Form(None),
):
    """
    Generate Volatility 3 Linux ISF symbol from a kernel ELF binary and optional System.map
    using dwarf2json on Dask workers (Issue #1554 / #272).
    """
    try:
        from orochi.website.models import Dump

        resolved_elf_path = None
        resolved_system_map_path = None
        dump_pk = None

        content_type = (request.content_type or "").lower()
        if "application/json" in content_type and request.body:
            try:
                data = json.loads(request.body)
                payload = DwarfGenerateIn(**data)
                elf_path = elf_path or payload.elf_path
                system_map_path = system_map_path or payload.system_map_path
                output_name = output_name or payload.output_name
                dump_index = dump_index or payload.dump_index
            except Exception:
                pass

        if elf_path or system_map_path:
            allowed_roots = allowed_upload_source_roots()
            if elf_path:
                resolved_elf_path = str(resolve_path_within(elf_path, allowed_roots, must_exist_file=True))
            if system_map_path:
                resolved_system_map_path = str(
                    resolve_path_within(system_map_path, allowed_roots, must_exist_file=True)
                )

        if dump_index:
            dump = Dump.objects.filter(index=dump_index).first()
            if dump:
                dump_pk = dump.pk

        if elf:
            upload_dir = Path(settings.MEDIA_ROOT) / "uploads" / "dwarf"
            upload_dir.mkdir(parents=True, exist_ok=True)
            resolved_elf_path = str(upload_dir / sanitize_filename(Path(elf.name).name))
            with open(resolved_elf_path, "wb") as f:
                f.write(elf.read())

        if system_map:
            upload_dir = Path(settings.MEDIA_ROOT) / "uploads" / "dwarf"
            upload_dir.mkdir(parents=True, exist_ok=True)
            resolved_system_map_path = str(upload_dir / sanitize_filename(Path(system_map.name).name))
            with open(resolved_system_map_path, "wb") as f:
                f.write(system_map.read())

        if not output_name:
            output_name = request.POST.get("output_name") or None
        if not dump_pk and request.POST.get("dump_index"):
            dump = Dump.objects.filter(index=request.POST["dump_index"]).first()
            if dump:
                dump_pk = dump.pk

        if not resolved_elf_path:
            return Status(400, {"errors": "Missing required kernel ELF (vmlinux)."})

        task_res = generate_dwarf_isf_task.enqueue(
            elf_path=resolved_elf_path,
            system_map_path=resolved_system_map_path,
            output_name=output_name,
            dump_pk=dump_pk,
            user_pk=request.user.pk,
        )
        return Status(200, {"message": f"dwarf2json ISF generation task queued successfully (Task ID: {task_res.id})."})

    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/btf_generate",
    url_name="btf_generate",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def btf_generate_symbols(
    request,
    payload: BtfGenerateIn | None = None,
    btf: UploadedFile | None = File(None),
    system_map: UploadedFile | None = File(None),
):
    """
    Generate Volatility 3 ISF symbols using btf2json on Dask workers from a BTF file
    (e.g. /sys/kernel/btf/vmlinux or stripped vmlinux), optional System.map, and optional Linux banner.
    Accepts either JSON payload with server paths or multipart file uploads.
    """
    try:
        btf_path = None
        system_map_path = None
        banner = None
        output_name = None
        dump_pk = None

        content_type = (request.content_type or "").lower()
        if payload is None and "application/json" in content_type and request.body:
            try:
                data = json.loads(request.body)
                payload = BtfGenerateIn(**data)
            except Exception:
                pass

        if payload:
            allowed_roots = allowed_upload_source_roots()
            if payload.btf_path:
                btf_path = str(resolve_path_within(payload.btf_path, allowed_roots, must_exist_file=True))
            if payload.system_map_path:
                system_map_path = str(resolve_path_within(payload.system_map_path, allowed_roots, must_exist_file=True))
            banner = payload.banner
            output_name = payload.output_name
            if payload.dump_index:
                dump = Dump.objects.filter(index=payload.dump_index).first()
                if dump:
                    dump_pk = dump.pk
                    if not banner and dump.banner:
                        banner = dump.banner

        if btf:
            upload_dir = Path(settings.MEDIA_ROOT) / "uploads" / "btf"
            upload_dir.mkdir(parents=True, exist_ok=True)
            btf_path = str(upload_dir / sanitize_filename(Path(btf.name).name))
            with open(btf_path, "wb") as f:
                f.write(btf.read())

        if system_map:
            upload_dir = Path(settings.MEDIA_ROOT) / "uploads" / "btf"
            upload_dir.mkdir(parents=True, exist_ok=True)
            system_map_path = str(upload_dir / sanitize_filename(Path(system_map.name).name))
            with open(system_map_path, "wb") as f:
                f.write(system_map.read())

        if not banner:
            banner = request.POST.get("banner") or None
        if not output_name:
            output_name = request.POST.get("output_name") or None
        if not dump_pk and request.POST.get("dump_index"):
            dump = Dump.objects.filter(index=request.POST["dump_index"]).first()
            if dump:
                dump_pk = dump.pk
                if not banner and dump.banner:
                    banner = dump.banner

        if not btf_path:
            return Status(400, {"errors": "Missing required BTF file or stripped vmlinux binary."})

        task_res = generate_btf_isf_task.enqueue(
            btf_path=btf_path,
            system_map_path=system_map_path,
            banner=banner,
            output_name=output_name,
            dump_pk=dump_pk,
            user_pk=request.user.pk,
        )
        return Status(200, {"message": f"btf2json ISF generation task queued successfully (Task ID: {task_res.id})."})

    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/upload_packages",
    url_name="upload_packages",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def upload_packages(
    request,
    payload: UploadFileIn | None = None,
    packages: list[UploadedFile] | None = File(None),
):
    """Upload and process symbol packages for analysis.

    This function handles symbol package uploads through either predefined file information or direct file uploads. It processes the uploaded files using a Downloader and refreshes symbol information.

    Args:
        request: The incoming HTTP request.
        payload: An UploadFileIn object containing file information.
        packages: Optional list of uploaded files to process.

    Returns:
        A tuple with status code and response message indicating upload success or failure.

    Raises:
        Exception: If there are issues processing uploaded files.

    Examples:
        POST /upload_packages with file information or direct file uploads.
    """
    try:
        path = Path(Setting.get("VOLATILITY_SYMBOL_PATH")) / "added"
        path.mkdir(parents=True, exist_ok=True)
        file_list = []
        if payload is None:
            raw_payload = request.POST.get("payload")
            if raw_payload:
                with contextlib.suppress(Exception):
                    payload = UploadFileIn(**json.loads(raw_payload))
            elif "application/json" in (request.content_type or "").lower() and request.body:
                with contextlib.suppress(Exception):
                    payload = UploadFileIn(**json.loads(request.body))

        if payload and payload.info:
            allowed_roots = allowed_upload_source_roots()
            for item in payload.info:
                start = item.local_folder.replace(
                    "/upload/upload",
                    str(Path(settings.MEDIA_ROOT) / "uploads"),
                )
                if start.startswith("/media/tmp/"):
                    start = str(Path(settings.MEDIA_ROOT) / "tmp" / start.removeprefix("/media/tmp/"))
                source_path = resolve_path_within(start, allowed_roots, must_exist_file=True)
                safe_name = sanitize_filename(item.original_name or source_path.name)
                file_list.append((str(source_path), safe_name))
        elif packages:
            media_root = Path(settings.MEDIA_ROOT)
            media_root.mkdir(parents=True, exist_ok=True)
            for package in packages:
                safe_name = sanitize_filename(package.name)
                filepath = resolve_path_within(media_root / safe_name, [media_root])
                with open(filepath, "wb") as f:
                    f.write(package.read())
                file_list.append((str(filepath), safe_name))
        else:
            return Status(400, {"errors": "No symbol packages provided."})

        download_symbols_task.enqueue(
            file_list=file_list,
            user_pk=request.user.pk,
        )
        return Status(200, {"message": "Symbols upload and compilation task queued successfully."})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.get(
    "/diagnostics",
    url_name="symbols_diagnostics",
    auth=dual_auth,
    response={200: dict, 400: ErrorsOut},
)
def get_symbols_diagnostics(request):
    """Return health check and metrics for symbol subsystem and workers."""
    try:
        from orochi.website.symbols_assistant import check_symbols_health

        health = check_symbols_health()
        return Status(200, health)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/sync_workers",
    url_name="symbols_sync_workers",
    auth=dual_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def sync_symbols_to_workers(request):
    """Distribute symbol environment and cache refresh across all Dask workers."""
    try:
        from orochi.website.symbols_assistant import distribute_symbols_to_workers

        result = distribute_symbols_to_workers()
        return Status(200, {"message": f"Symbols synchronized across {result.get('worker_count', 0)} workers."})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})
