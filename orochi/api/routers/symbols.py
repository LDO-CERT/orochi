import concurrent.futures
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import magic
import requests
from django.http import HttpRequest
from django.shortcuts import get_object_or_404
from django.utils.text import slugify
from extra_settings.models import Setting
from ninja import File, Query, Router, Status
from ninja.files import UploadedFile
from ninja.pagination import paginate
from ninja.security import django_auth
from volatility3.framework import automagic, contexts

from orochi.api.models import (
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
from orochi.utils.volatility_dask_elk import refresh_symbols
from orochi.website.models import Dump
from orochi.website.roles import ROLE_ADMIN
from orochi.website.tasks import download_symbols_task, generate_dwarf_isf_task

router = Router()


@router.get("/", auth=django_auth, url_name="list_symbols", response=list[SymbolsOut])
@paginate(CustomSymbolsPagination)
def list_symbols(request: HttpRequest, draw: int | None, filters: TableFilter = Query(...)):
    symbols = []

    ctx = contexts.Context()
    automagics = automagic.available(ctx)
    if banners := [x for x in automagics if x._config_path == "automagic.SymbolFinder"]:
        banner = banners[0].banners
    else:
        banner = []

    request.draw = draw
    request.total = len(banner)
    request.search = filters.search or None

    for k, v in banner.items():
        try:
            k = k.decode("utf-8")
            v = str(v)
        except AttributeError:
            k = str(k)

        if filters.search and (filters.search not in k and filters.search not in v):
            continue

        if "file://" in v:
            path = v.replace("file://", "").replace(Setting.get("VOLATILITY_SYMBOL_PATH"), "")
            action = ("list", "-") if "/added/" not in v else ("delete", path)
        else:
            path = v
            action = ("down", v)

        symbols.append(SymbolsOut(id=k, path=path, action=action))
    return symbols


@router.post(
    "/banner",
    auth=django_auth,
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


@router.post(
    "/upload",
    url_name="upload_symbols",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def upload_symbols(
    request,
    payload: UploadFileIn | None,
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
        if payload.info:
            for item in payload.info:
                start = item.local_folder
                start = start.replace("/upload/upload", "/media/uploads")
                filepath = f"{path}/{item.original_name}"
                shutil.move(start, filepath)
                filetype = magic.from_file(filepath, mime=True)
                if filetype in [
                    "application/zip",
                    "application/x-7z-compressed",
                    "application/x-rar",
                    "application/gzip",
                    "application/x-tar",
                ]:
                    subprocess.call([seven_z_path, "e", filepath, f"-o{path}", "-y"])
        elif symbols:
            for symbol in symbols:
                filepath = f"{path}/{Path(symbol.name).name}"
                with open(filepath, "wb") as f:
                    f.write(symbol.read())
                filetype = magic.from_file(filepath, mime=True)
                if filetype in [
                    "application/zip",
                    "application/x-7z-compressed",
                    "application/x-rar",
                    "application/gzip",
                    "application/x-tar",
                ]:
                    subprocess.call([seven_z_path, "e", filepath, f"-o{path}", "-y"])
        refresh_symbols()
        return Status(200, {"message": "Symbols uploaded."})

    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete(
    "/delete",
    url_name="delete_symbol",
    auth=django_auth,
    response={200: SuccessResponse, 405: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def delete_symbol(request, path):
    """Delete a specific symbol file from the symbols directory.

    Attempts to delete a symbol file located in the added symbols path. If the file exists and is within the added directory,
    it will be removed and symbols will be refreshed.

    Args:
        request: The incoming HTTP request.
        path: The relative path of the symbol file to delete.

    Returns:
        200: A success message if the symbol is deleted successfully.
        400: An error response with exception details if deletion fails.

    Raises:
        Exception: If there are any issues during the deletion process.
    """
    try:
        symbol_path = f"{Setting.get('VOLATILITY_SYMBOL_PATH')}{path}"
        if Path(symbol_path).exists() and symbol_path.find("/added/") != -1:
            os.unlink(symbol_path)
            refresh_symbols()
            return Status(200, {"message": "Symbols deleted."})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/isf_download",
    url_name="isf_download",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut},
)
def isf_download(request, payload: ISFIn):
    """Download and save symbol files from a given URL.

    This function downloads symbol files for different operating systems from a specified path and saves them locally. It supports concurrent downloading of multiple symbol files.

    Args:
        request: The incoming HTTP request.
        payload: An ISFIn object containing the download path.

    Returns:
        A tuple with status code and response message indicating success or failure.

    Raises:
        Exception: If there are issues parsing symbols or downloading files.

    Examples:
        POST /isf_download with a payload containing a valid symbol file URL.
        (e.g. https://raw.githubusercontent.com/Abyss-W4tcher/volatility3-symbols/master/banners/banners_plain.json)
    """
    try:
        path = payload.path
        domain = slugify(urlparse(path).netloc)
        media_path = Path(f"{Setting.get('VOLATILITY_SYMBOL_PATH')}/{domain}")
        media_path.mkdir(exist_ok=True, parents=True)
        try:
            data = json.loads(requests.get(path).content)
        except Exception:
            return Status(400, {"errors": "Error parsing symbols"})

        def download_file(url, path):
            if ".." in str(path):
                raise ValueError(f"Invalid path: {path}")
            try:
                response = requests.get(url)
                with open(path, "wb") as f:
                    f.write(response.content)
            except Exception as excp:
                print(excp)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            for key in data:
                if key not in ["linux", "mac", "windows"]:
                    continue
                for urls in data[key].values():
                    for url in urls:
                        filename = url.split("/")[-1]
                        filepath = f"{media_path}/{filename}"
                        executor.submit(download_file, url, filepath)

        refresh_symbols()
        return Status(200, {"message": "Symbols downloaded successfully"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/dwarf_generate",
    url_name="dwarf_generate",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
def dwarf_generate_symbols(
    request,
    payload: DwarfGenerateIn | None = None,
    elf: UploadedFile | None = File(None),
    system_map: UploadedFile | None = File(None),
):
    """
    Generate Volatility 3 Linux ISF symbol from a kernel ELF binary and optional System.map
    using dwarf2json on Dask workers (Issue #1554 / #272).
    """
    try:
        from orochi.website.models import Dump

        elf_path = None
        system_map_path = None
        output_name = None
        dump_pk = None

        if payload is None and request.body:
            try:
                data = json.loads(request.body)
                payload = DwarfGenerateIn(**data)
            except Exception:
                pass

        if payload:
            elf_path = payload.elf_path
            system_map_path = payload.system_map_path
            output_name = payload.output_name
            if payload.dump_index:
                dump = Dump.objects.filter(index=payload.dump_index).first()
                if dump:
                    dump_pk = dump.pk

        if elf:
            upload_dir = Path("/media/uploads/dwarf")
            upload_dir.mkdir(parents=True, exist_ok=True)
            elf_path = str(upload_dir / Path(elf.name).name)
            with open(elf_path, "wb") as f:
                f.write(elf.read())

        if system_map:
            upload_dir = Path("/media/uploads/dwarf")
            upload_dir.mkdir(parents=True, exist_ok=True)
            system_map_path = str(upload_dir / Path(system_map.name).name)
            with open(system_map_path, "wb") as f:
                f.write(system_map.read())

        if not elf_path:
            return Status(400, {"errors": "Missing required kernel ELF (vmlinux)."})

        task_res = generate_dwarf_isf_task.enqueue(
            elf_path=elf_path,
            system_map_path=system_map_path,
            output_name=output_name,
            dump_pk=dump_pk,
            user_pk=request.user.pk,
        )
        return Status(200, {"message": f"dwarf2json ISF generation task queued successfully (Task ID: {task_res.id})."})

    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/upload_packages",
    url_name="upload_packages",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut},
)
def upload_packages(
    request,
    payload: UploadFileIn | None,
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
        if payload and payload.info:
            for item in payload.info:
                start = item.local_folder
                start = start.replace("/upload/upload", "/media/uploads")
                file_list.append((start, item.original_name))
        elif packages:
            for package in packages:
                filepath = f"/media/{Path(package.name).name}"
                with open(filepath, "wb") as f:
                    f.write(package.read())
                file_list.append((filepath, Path(package.name).name))

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
    auth=django_auth,
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
    auth=django_auth,
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
