from typing import Any

from ninja import Router, Schema

from orochi.api.security import dual_auth
from orochi.website.search import execute_vector_search

router = Router()


class CaseSearchItem(Schema):
    """Case hit of the global search, with highlighted name and description."""

    id: int
    name: str
    name_highlighted: str
    description: str
    description_highlighted: str
    status: str
    is_ctf: bool
    created_at: Any
    author: str
    evidences_count: int
    findings_count: int
    url: str


class DumpSearchItem(Schema):
    """Dump hit of the global search, with highlighted fields."""

    id: int
    index: str
    name: str
    name_highlighted: str
    operating_system: str
    color: str
    comment: str
    comment_highlighted: str
    description: str
    description_highlighted: str
    banner: str
    md5: str
    sha256: str
    status: str
    created_at: Any
    author: str
    url: str


class ValueSummaryItem(Schema):
    """One field of a plugin row hit: value, highlighted value and whether it matched."""

    key: str
    value: str
    highlighted: str
    matched: bool


class PluginResultSearchItem(Schema):
    """Plugin row hit of the global search with its dump and the matching fields."""

    id: int
    dump_name: str
    dump_index: str
    dump_color: str
    dump_os: str
    plugin_name: str
    summary_fields: list[ValueSummaryItem]
    raw_value: dict | None = None
    updated_at: Any
    workbench_url: str


class GlobalSearchResultOut(Schema):
    """Global search response: query, scope, counts and hits per scope."""

    query: str
    scope: str
    cases_count: int
    dumps_count: int
    plugin_results_count: int
    total_count: int
    duration: float
    cases: list[CaseSearchItem]
    dumps: list[DumpSearchItem]
    plugin_results: list[PluginResultSearchItem]


@router.get("", auth=dual_auth, response={200: GlobalSearchResultOut})
def search(request, q: str = "", scope: str = "all", limit: int = 50):
    """
    Execute PostgreSQL vector global search across Cases, Dumps, and Plugin Results.
    """
    if scope not in ("all", "cases", "dumps", "results"):
        scope = "all"
    return execute_vector_search(request.user, q, scope=scope, limit=min(limit, 100))
