import logging
import os
import re
from pathlib import Path
from typing import List

import yara_x

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Dump, DumpSecret, Value

logger = logging.getLogger(__name__)

SECRETS_YARA_PATH = Path(__file__).resolve().parent / "rules" / "secrets.yar"

CATEGORY_MAP = {
    "Secret_AWS_Access_Key": "aws",
    "Secret_Private_Key_PEM": "private_key",
    "Secret_JWT_Token": "jwt",
    "Secret_GitHub_Token": "api_key",
    "Secret_Slack_Token": "api_key",
    "Secret_OpenAI_Key": "api_key",
    "Secret_Database_Connection_URI": "db_uri",
    "Secret_Generic_Credentials": "password",
}


def mask_secret(secret: str, category: str = "generic") -> str:
    """Mask sensitive secret substrings for shoulder-surfing safe display."""
    if not secret:
        return ""
    secret = secret.strip()
    if category == "aws":
        if len(secret) >= 8:
            return f"{secret[:4]}{'*' * (len(secret) - 6)}{secret[-2:]}"
        return "****"
    elif category == "private_key":
        first_line = secret.splitlines()[0] if secret else "-----BEGIN PRIVATE KEY-----"
        return f"{first_line} [KEY BODY REDACTED]"
    elif category == "jwt":
        parts = secret.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.[PAYLOAD REDACTED].[SIGNATURE REDACTED]"
        return f"{secret[:10]}...[REDACTED]"
    elif category == "db_uri":
        # Mask password in URI scheme://user:pass@host
        return re.sub(
            r"(://[^:\s]+):([^@\s]+)(@)",
            r"\1:********\3",
            secret,
        )
    elif category == "api_key":
        if len(secret) > 10:
            return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"
        return f"{secret[:2]}******"
    elif category == "password":
        # e.g. password="SecretPassword" -> password="S****d"
        m = re.match(r'^(.*?=\s*["\']?)(.+?)(["\']?)$', secret)
        if m:
            prefix, val, suffix = m.groups()
            if len(val) > 4:
                masked_val = f"{val[0]}{'*' * (len(val) - 2)}{val[-1]}"
            else:
                masked_val = "****"
            return f"{prefix}{masked_val}{suffix}"
        return f"{secret[:2]}******"
    return f"{secret[:3]}******"


def get_compiled_secrets_scanner() -> yara_x.Scanner:
    """Compiles the curated secrets YARA ruleset with yara-x."""
    with open(SECRETS_YARA_PATH, "r", encoding="utf-8") as f:
        rule_content = f.read()
    compiled_rules = yara_x.compile(rule_content)
    return yara_x.Scanner(compiled_rules)


def scan_dump_for_secrets(dump: Dump) -> List[DumpSecret]:
    """
    Executes deep secrets scanning across dump Volatility plugin records
    and raw dump file memory buffers using yara-x.
    """
    scanner = get_compiled_secrets_scanner()
    found_secrets = []
    seen_keys = set()

    # 1. Scan structured Volatility outputs (cmdline, bash, envars, consoles)
    relevant_plugins = [
        "windows.cmdline.CmdLine",
        "windows.consoles.Consoles",
        "linux.bash.Bash",
        "mac.bash.Bash",
        "windows.envars.Envars",
        "windows.registry.userassist.UserAssist",
        "windows.vadyarascan.VadYaraScan",
        "yarascan.YaraScan",
    ]

    val_records = Value.objects.select_related("result__plugin").filter(
        result__dump=dump,
        result__plugin__name__in=relevant_plugins,
        result__result=RESULT_STATUS_SUCCESS,
    )

    for val_obj in val_records:
        val_data = val_obj.value or {}
        # Extract process and PID
        pid = val_data.get("PID") or val_data.get("Pid") or val_data.get("pid")
        process_name = (
            val_data.get("Process")
            or val_data.get("ImageFileName")
            or val_data.get("Name")
        )
        offset = val_data.get("Offset") or val_data.get("Offset(V)")

        # Convert whole JSON row or individual string fields to text for scanning
        text_fields = []
        for key in [
            "Args",
            "Command",
            "CommandHistory",
            "ScreenBuffer",
            "Variable",
            "Value",
            "Strings",
        ]:
            if key in val_data and isinstance(val_data[key], str):
                text_fields.append(val_data[key])
        if not text_fields:
            text_fields.append(str(val_data))

        for text in text_fields:
            if not text:
                continue
            text_bytes = text.encode("utf-8", errors="ignore")
            scan_results = scanner.scan(text_bytes)
            for rule in scan_results.matching_rules:
                rule_name = rule.identifier
                category = CATEGORY_MAP.get(rule_name, "password")
                for pattern in rule.patterns:
                    for match in pattern.matches:
                        raw_match = text_bytes[
                            match.offset : match.offset + match.length
                        ].decode("utf-8", errors="ignore")
                        dedup_key = (category, raw_match, pid)
                        if dedup_key in seen_keys:
                            continue
                        seen_keys.add(dedup_key)

                        found_secrets.append(
                            DumpSecret(
                                dump=dump,
                                category=category,
                                rule_name=rule_name,
                                matched_data=raw_match,
                                masked_data=mask_secret(raw_match, category),
                                offset=(
                                    hex(offset)
                                    if isinstance(offset, int)
                                    else (str(offset) if offset else None)
                                ),
                                pid=int(pid) if pid and str(pid).isdigit() else None,
                                process_name=(
                                    str(process_name) if process_name else None
                                ),
                            )
                        )

    # 2. Scan Raw Upload File (if available on disk)
    if dump.upload:
        try:
            file_path = dump.upload.path
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                # If file < 256MB, mmap scan directly; otherwise chunk scan
                chunk_size = 32 * 1024 * 1024  # 32MB
                overlap = 4096

                with open(file_path, "rb") as f:
                    offset_cursor = 0
                    while offset_cursor < file_size:
                        f.seek(offset_cursor)
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        scan_results = scanner.scan(chunk)
                        for rule in scan_results.matching_rules:
                            rule_name = rule.identifier
                            category = CATEGORY_MAP.get(rule_name, "password")
                            for pattern in rule.patterns:
                                for match in pattern.matches:
                                    abs_offset = offset_cursor + match.offset
                                    raw_match = chunk[
                                        match.offset : match.offset + match.length
                                    ].decode("utf-8", errors="ignore")
                                    dedup_key = (category, raw_match, None)
                                    if dedup_key in seen_keys:
                                        continue
                                    seen_keys.add(dedup_key)

                                    found_secrets.append(
                                        DumpSecret(
                                            dump=dump,
                                            category=category,
                                            rule_name=rule_name,
                                            matched_data=raw_match,
                                            masked_data=mask_secret(
                                                raw_match, category
                                            ),
                                            offset=hex(abs_offset),
                                            pid=None,
                                            process_name=None,
                                        )
                                    )
                        if len(chunk) < chunk_size:
                            break
                        offset_cursor += chunk_size - overlap
        except Exception as exc:
            logger.warning(f"Error scanning raw dump file {dump.upload}: {exc}")

    # 3. Atomically replace DumpSecret records in database
    DumpSecret.objects.filter(dump=dump).delete()
    if found_secrets:
        DumpSecret.objects.bulk_create(found_secrets)

    return list(DumpSecret.objects.filter(dump=dump))
