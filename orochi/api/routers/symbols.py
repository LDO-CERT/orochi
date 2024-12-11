import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

import magic
from django.shortcuts import get_object_or_404
from extra_settings.models import Setting
from ninja import File, Router
from ninja.files import UploadedFile
from ninja.security import django_auth

from orochi.api.models import ErrorsOut, SuccessResponse, SymbolsBannerIn, SymbolsIn
from orochi.utils.download_symbols import Downloader
from orochi.utils.volatility_dask_elk import check_runnable, refresh_symbols
from orochi.website.defaults import DUMP_STATUS_COMPLETED
from orochi.website.models import Dump

router = Router()


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
    request, payload: SymbolsIn, symbols: Optional[List[UploadedFile]] = File(None)
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
                original_name = item.original_name
                start = start.replace("/upload/upload", "/media/uploads")
                filename = original_name
                filepath = f"{path}/{filename}"
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
