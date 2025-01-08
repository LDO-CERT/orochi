import concurrent.futures
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import magic
import requests
from django.http import HttpRequest
from django.shortcuts import get_object_or_404
from django.utils.text import slugify
from extra_settings.models import Setting
from ninja import File, Query, Router
from ninja.files import UploadedFile
from ninja.pagination import paginate
from ninja.security import django_auth
from volatility3.framework import automagic, contexts

from orochi.api.models import (
    CustomSymbolsPagination,
    ErrorsOut,
    ISFIn,
    SuccessResponse,
    SymbolsBannerIn,
    SymbolsOut,
    TableFilter,
    UploadFileIn,
)
from orochi.utils.download_symbols import Downloader
from orochi.utils.volatility_dask_elk import check_runnable, refresh_symbols
from orochi.website.defaults import DUMP_STATUS_COMPLETED
from orochi.website.models import Dump

router = Router()


@router.get("/", auth=django_auth, url_name="list_symbols", response=List[SymbolsOut])
@paginate(CustomSymbolsPagination)
def list_symbols(
    request: HttpRequest, draw: Optional[int], filters: TableFilter = Query(...)
):
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
            path = v.replace("file://", "").replace(
                Setting.get("VOLATILITY_SYMBOL_PATH"), ""
            )
            action = ("list", "-") if "/added/" not in v else ("delete", path)
        else:
            action = ("down", v)

        symbols.append(SymbolsOut(id=k, path=path, action=action))
    return symbols


@router.post(
    "/banner",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut},
)
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

        d = Downloader(url_list=payload.path)
        d.download_list()

        if check_runnable(dump.pk, dump.operating_system, dump.banner):
            dump.status = DUMP_STATUS_COMPLETED
            dump.save()
            return 200, {"message": "Symbol downloaded successfully"}
        return 400, {"errors": "Downloaded symbols not properly installed"}
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.post(
    "/upload",
    url_name="upload_symbols",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut},
)
def upload_symbols(
    request,
    payload: Optional[UploadFileIn],
    symbols: Optional[List[UploadedFile]] = File(None),
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
        path = Path(Setting.get("VOLATILITY_SYMBOL_PATH")) / "added"
        path.mkdir(parents=True, exist_ok=True)
        if payload.info:
            for item in payload.info:
                start = item.local_folder
                start = start.replace("/upload/upload", "/media/uploads")
                filepath = f"{path}/{ item.original_name}"
                shutil.move(start, filepath)
                filetype = magic.from_file(filepath, mime=True)
                if filetype in [
                    "application/zip",
                    "application/x-7z-compressed",
                    "application/x-rar",
                    "application/gzip",
                    "application/x-tar",
                ]:
                    subprocess.call(["7z", "e", filepath, f"-o{path}", "-y"])
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
                    subprocess.call(["7z", "e", filepath, f"-o{path}", "-y"])
        refresh_symbols()
        return 200, {"message": "Symbols uploaded."}

    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.delete(
    "/delete",
    url_name="delete_symbol",
    auth=django_auth,
    response={200: SuccessResponse, 405: ErrorsOut},
)
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
            return 200, {"message": "Symbols deleted."}
    except Exception as excp:
        return 400, {"errors": str(excp)}


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
            return 400, {"errors": "Error parsing symbols"}

        def download_file(url, path):
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
        return 200, {"message": "Symbols downloaded successfully"}
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.post(
    "/upload_packages",
    url_name="upload_packages",
    auth=django_auth,
    response={200: SuccessResponse, 400: ErrorsOut},
)
def upload_packages(
    request,
    payload: Optional[UploadFileIn],
    packages: Optional[List[UploadedFile]] = File(None),
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
        file_list = []
        if payload.info:
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
        d = Downloader(file_list=file_list)
        d.process_list()
        os.unlink(filepath)
        refresh_symbols()
        return 200, {"message": "Symbols uploaded."}
    except Exception as excp:
        return 400, {"errors": str(excp)}
