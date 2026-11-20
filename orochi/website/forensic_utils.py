from typing import Any

from django.db.models import Q

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Result, Value

HEX_COLUMN_NAMES: frozenset[str] = frozenset(
    {
        "offset(v)",
        "offset(p)",
        "offset",
        "base",
        "address",
        "start",
        "end",
        "start vpn",
        "end vpn",
        "table address",
        "hive offset",
        "virtual",
        "physical",
        "handler address",
    }
)


def extract_pid(value: Any) -> int | None:
    """Cleanly parse a PID value (int, decimal string, or hex string) into an integer."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str):
            value = value.strip()
            if value.startswith(("0x", "0X")):
                return int(value, 16)
        return int(value)
    except (ValueError, TypeError):
        return None


def format_offset(offset_val: Any) -> str:
    """Format memory offsets/addresses as clean 0x... hex strings."""
    if offset_val is None or offset_val == "":
        return ""
    try:
        if isinstance(offset_val, int) and not isinstance(offset_val, bool):
            return hex(offset_val)
        offset_str = str(offset_val).strip()
        if offset_str.startswith(("0x", "0X")):
            return offset_str
        return hex(int(offset_str))
    except (ValueError, TypeError):
        return str(offset_val)


def row_matches_pid(row: dict[str, Any], target_pid: int) -> bool:
    """Return True if a Volatility plugin row dict belongs to target_pid."""
    for key in ("PID", "Pid", "pid", "Process ID"):
        if key in row and extract_pid(row.get(key)) == target_pid:
            return True
    return False


def fetch_pid_rows(result_obj: Result | None, target_pid: int) -> list[dict[str, Any]]:
    """
    Fetch all Value dicts for target_pid from a Result using a PostgreSQL JSONB
    filter first, avoiding full-table Python scans on large plugins (e.g. handles/vadinfo).
    """
    if not result_obj or result_obj.result != RESULT_STATUS_SUCCESS:
        return []

    pid_str = str(target_pid)
    jsonb_q = (
        Q(value__PID=target_pid)
        | Q(value__PID=pid_str)
        | Q(value__Pid=target_pid)
        | Q(value__Pid=pid_str)
        | Q(value__pid=target_pid)
        | Q(value__pid=pid_str)
        | Q(value__contains={"Process ID": target_pid})
        | Q(value__contains={"Process ID": pid_str})
    )
    qs = Value.objects.filter(result=result_obj).filter(jsonb_q).values_list("value", flat=True)
    return [val for val in qs.iterator(chunk_size=1000) if isinstance(val, dict) and row_matches_pid(val, target_pid)]
