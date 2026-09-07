import html
import re
import time

from django.contrib.postgres.search import SearchHeadline, SearchQuery, SearchRank
from django.db.models import F, Q
from django.urls import reverse
from guardian.shortcuts import get_objects_for_user

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.models import Case, Value


def highlight_text(text, query):
    """Safely escape text and highlight matches of query."""
    if not text or not query:
        return html.escape(str(text or ""))
    escaped_text = html.escape(str(text))
    escaped_query = html.escape(query)
    pattern = re.compile(re.escape(escaped_query), re.IGNORECASE)
    return pattern.sub(
        lambda m: (
            f"<mark class='bg-amber-200 dark:bg-amber-900/60 text-zinc-900 dark:text-zinc-100 font-semibold px-0.5 rounded'>{m.group(0)}</mark>"
        ),
        escaped_text,
    )


def summarize_value_row(value_dict, query=None, max_fields=6):
    """Format matching fields and key attributes from a Volatility result row."""
    if not isinstance(value_dict, dict):
        return []

    key_priority = [
        "PID",
        "PPID",
        "ImageFileName",
        "Name",
        "Offset",
        "Process",
        "Path",
        "CommandLine",
        "Command",
        "CreateTime",
        "Time",
        "Address",
        "Type",
    ]

    items = []
    matched_items = []
    other_items = []

    for k, v in value_dict.items():
        if k == "__children":
            continue
        v_str = str(v)
        is_matched = bool(query and query.lower() in v_str.lower())
        formatted_entry = {
            "key": k,
            "value": v_str,
            "highlighted": (
                highlight_text(v_str, query) if is_matched else html.escape(v_str)
            ),
            "matched": is_matched,
        }
        if is_matched:
            matched_items.append(formatted_entry)
        elif k in key_priority:
            other_items.append(formatted_entry)
        else:
            items.append(formatted_entry)

    return (matched_items + other_items + items)[:max_fields]


def execute_vector_search(user, query_str, scope="all", limit=50):
    """
    Executes PostgreSQL full-text vector global search across Cases, Dumps, and Plugin Results.
    Returns a dictionary with result lists and counts.
    """
    start_time = time.time()
    results = {
        "query": query_str,
        "scope": scope,
        "cases": [],
        "dumps": [],
        "plugin_results": [],
        "cases_count": 0,
        "dumps_count": 0,
        "plugin_results_count": 0,
        "total_count": 0,
        "duration": 0,
    }

    if not query_str or not query_str.strip():
        return results

    q = query_str.strip()
    search_query = SearchQuery(q, search_type="websearch", config="english")

    # 1. SEARCH CASES
    if scope in ("all", "cases"):
        cases_qs = Case.objects.filter(Q(user=user) | Q(collaborators=user)).distinct()

        cases_qs = (
            cases_qs.filter(
                Q(search_vector=search_query)
                | Q(name__icontains=q)
                | Q(description__icontains=q)
            )
            .annotate(rank=SearchRank(F("search_vector"), search_query))
            .annotate(
                headline_desc=SearchHeadline(
                    "description",
                    search_query,
                    config="english",
                    start_sel="<mark class='bg-amber-200 dark:bg-amber-900/60 text-zinc-900 dark:text-zinc-100 font-semibold px-0.5 rounded'>",
                    stop_sel="</mark>",
                )
            )
            .order_by("-rank", "-created_at")
        )

        results["cases_count"] = cases_qs.count()
        for case in cases_qs[:limit]:
            results["cases"].append(
                {
                    "id": case.pk,
                    "name": case.name,
                    "name_highlighted": highlight_text(case.name, q),
                    "description": case.description or "",
                    "description_highlighted": case.headline_desc
                    or highlight_text(case.description or "", q),
                    "status": case.status,
                    "is_ctf": case.is_ctf,
                    "created_at": case.created_at,
                    "author": case.user.username,
                    "evidences_count": case.evidences.count(),
                    "findings_count": case.findings.count(),
                    "url": reverse("website:case_detail", kwargs={"pk": case.pk}),
                }
            )

    # 2. SEARCH DUMPS
    if scope in ("all", "dumps"):
        allowed_dumps = get_objects_for_user(user, "website.can_see")
        dumps_qs = (
            allowed_dumps.filter(
                Q(search_vector=search_query)
                | Q(name__icontains=q)
                | Q(comment__icontains=q)
                | Q(description__icontains=q)
                | Q(md5__iexact=q)
                | Q(sha256__iexact=q)
            )
            .annotate(rank=SearchRank(F("search_vector"), search_query))
            .order_by("-rank", "-created_at")
        )

        results["dumps_count"] = dumps_qs.count()
        for dump in dumps_qs[:limit]:
            results["dumps"].append(
                {
                    "id": dump.pk,
                    "index": dump.index,
                    "name": dump.name,
                    "name_highlighted": highlight_text(dump.name, q),
                    "operating_system": dump.operating_system,
                    "color": dump.color,
                    "comment": dump.comment or "",
                    "comment_highlighted": highlight_text(dump.comment or "", q),
                    "description": dump.description or "",
                    "description_highlighted": highlight_text(
                        dump.description or "", q
                    ),
                    "banner": dump.banner or "",
                    "md5": dump.md5 or "",
                    "sha256": dump.sha256 or "",
                    "status": dump.get_status_display(),
                    "created_at": dump.created_at,
                    "author": dump.author.username,
                    "url": f"/#dump_{dump.index}",
                }
            )

    # 3. SEARCH PLUGIN RESULTS (Value)
    if scope in ("all", "results"):
        allowed_dumps = get_objects_for_user(user, "website.can_see")
        values_qs = (
            Value.objects.filter(
                result__dump__in=allowed_dumps,
                result__result=RESULT_STATUS_SUCCESS,
            )
            .filter(Q(search_vector=search_query) | Q(value__icontains=q))
            .annotate(rank=SearchRank(F("search_vector"), search_query))
            .select_related("result__dump", "result__plugin")
            .order_by("-rank", "-result__updated_at")
        )

        results["plugin_results_count"] = values_qs.count()
        for item in values_qs[:limit]:
            dump = item.result.dump
            plugin = item.result.plugin
            results["plugin_results"].append(
                {
                    "id": item.pk,
                    "dump_name": dump.name,
                    "dump_index": dump.index,
                    "dump_color": dump.color,
                    "dump_os": dump.operating_system,
                    "plugin_name": plugin.name,
                    "summary_fields": summarize_value_row(item.value, q),
                    "raw_value": item.value,
                    "updated_at": item.result.updated_at,
                    "workbench_url": reverse(
                        "website:bookmarks",
                        kwargs={
                            "indexes": dump.index,
                            "plugin": plugin.name,
                            "query": q,
                        },
                    ),
                }
            )

    results["total_count"] = (
        results["cases_count"]
        + results["dumps_count"]
        + results["plugin_results_count"]
    )
    results["duration"] = round(time.time() - start_time, 3)
    return results
