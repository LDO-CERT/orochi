from typing import Any, List, Optional

from ninja import Router, Schema
from ninja.security import django_auth

from orochi.website.search import execute_vector_search

router = Router()


class CaseSearchItem(Schema):
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
    key: str
    value: str
    highlighted: str
    matched: bool


class PluginResultSearchItem(Schema):
    id: int
    dump_name: str
    dump_index: str
    dump_color: str
    dump_os: str
    plugin_name: str
    summary_fields: List[ValueSummaryItem]
    raw_value: Optional[dict] = None
    updated_at: Any
    workbench_url: str


class GlobalSearchResultOut(Schema):
    query: str
    scope: str
    cases_count: int
    dumps_count: int
    plugin_results_count: int
    total_count: int
    duration: float
    cases: List[CaseSearchItem]
    dumps: List[DumpSearchItem]
    plugin_results: List[PluginResultSearchItem]


@router.get("", auth=django_auth, response={200: GlobalSearchResultOut})
def search(request, q: str = "", scope: str = "all", limit: int = 50):
    """
    Execute PostgreSQL vector global search across Cases, Dumps, and Plugin Results.
    """
    if scope not in ("all", "cases", "dumps", "results"):
        scope = "all"
    return execute_vector_search(request.user, q, scope=scope, limit=min(limit, 100))
