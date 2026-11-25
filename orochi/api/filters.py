from enum import StrEnum

from ninja import Schema


class OPERATING_SYSTEM(StrEnum):
    """Operating systems accepted by the API filters."""

    WINDOWS = "Windows"
    LINUX = "Linux"
    MAC = "Mac"
    OTHER = "Other"


class OperatingSytemFilters(Schema):
    """Query filter on the plugin / dump operating system."""

    operating_system: OPERATING_SYSTEM = None


class DumpFilters(Schema):
    """Query filter on the plugin result status of a dump."""

    result: int = None


###################################################
# DatatableFilter
###################################################
class Search(Schema):
    """DataTables search value (``regex`` flag as sent by the client)."""

    value: str = None
    regex: bool = False


class Column(Schema):
    """DataTables column descriptor sent with server-side requests."""

    data: int = 0
    name: str = None
    searchable: bool = True
    orderable: bool = True
    search: Search = None


class Order(Schema):
    """DataTables ordering: column index and direction (``asc`` / ``desc``)."""

    column: int = 0
    dir: str = "asc"


class DatatableFilter(Schema):
    """Server-side DataTables request: paging, columns, global search and ordering."""

    draw: int = 0
    start: int = 0
    length: int = 10
    columns: list[Column] = []
    search: Search = None
    order: list[Order] = []
