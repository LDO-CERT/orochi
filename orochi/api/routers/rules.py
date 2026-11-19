import os
from pathlib import Path
from typing import Any

import yara_x
from django.contrib.postgres.search import SearchHeadline, SearchQuery
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404
from extra_settings.models import Setting
from ninja import File, Query, Router, Status, UploadedFile
from ninja.pagination import paginate

from orochi.api.models import (
    ErrorsOut,
    ListStr,
    RuleBuildSchema,
    RuleEditInSchena,
    RuleOut,
    RulePagination,
    RulesetFeedOut,
    RulesetFeedSyncIn,
    RulesetToggleAutoUpdateIn,
    RulesOutSchema,
    SuccessResponse,
    TableFilter,
)
from orochi.api.permissions import ninja_role_required, ninja_test_required
from orochi.api.security import dual_auth
from orochi.website.models import CustomRule
from orochi.website.roles import ROLE_ADMIN
from orochi.website.storage import sanitize_filename, unique_path_in_dir
from orochi.ya.models import Rule, Ruleset
from orochi.ya.rules_sync import (
    compile_default_yara_rule,
    compile_yara_rules_queryset,
    sync_rules_to_workers,
)
from orochi.ya.tasks import sync_yara_rules

router = Router()


def _get_or_create_user_ruleset(user):
    """Return user's primary personal Ruleset, creating one if signup/bootstrap skipped it."""
    ruleset = Ruleset.objects.filter(user=user).order_by("pk").first()
    if ruleset is None:
        ruleset, _ = Ruleset.objects.get_or_create(
            name=f"{user.username}-Ruleset",
            defaults={"user": user, "description": "Your crafted ruleset"},
        )
    return ruleset


@router.get("/", auth=dual_auth, url_name="list_rules", response=list[RuleOut])
@paginate(RulePagination)
def list_rules(request: HttpRequest, draw: int | None, filters: TableFilter = Query(...)):
    """Retrieve a list of rules based on the provided filters and pagination.

    This function fetches rules that are either associated with the authenticated user or are public.
    It supports searching and sorting based on various criteria, returning the results in a paginated format.

    Args:
        request (HttpRequest): The HTTP request object containing user and query information.
        draw (int, optional): A draw counter for the DataTables plugin to ensure proper response handling.
        filters (TableFilter, optional): An object containing search and order criteria. Defaults to Query(...).

    Returns:
        List[RuleOut]: A list of rules that match the specified filters and pagination settings.
    """
    rules = (
        Rule.objects.prefetch_related("ruleset")
        .filter(Q(ruleset__user__isnull=True) | Q(ruleset__user=request.user))
        .filter(ruleset__enabled=True)
        .filter(enabled=True)
    )
    request.draw = draw
    request.total = rules.count()
    request.search = filters.search or None

    if filters.search:
        query = SearchQuery(filters.search)
        rules = rules.filter(
            Q(search_vector=filters.search)
            | Q(ruleset__name__icontains=filters.search)
            | Q(ruleset__description__icontains=filters.search)
            | Q(path__icontains=filters.search)
        ).annotate(headline=SearchHeadline("rule", query))

    sort_fields = ["id", "ruleset__name", "path"]
    sort = sort_fields[filters.order_column] if filters.order_column else sort_fields[0]
    if filters.order_dir and filters.order_dir == "desc":
        sort = f"-{sort}"
    return rules.order_by(sort)


@router.patch(
    "/{int:id}",
    auth=dual_auth,
    url_name="edit_rule",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def edit_rule(request, id: int, data: RuleEditInSchena):
    """
    Edit or create a rule based on the provided primary key.

    Args:
        pk (int): The primary key of the rule to edit or create.

    Returns:
        tuple: A tuple containing the HTTP status code and a message indicating the success or error.
    Raises:
        Exception: If an error occurs during the process.
    """
    try:
        rule = get_object_or_404(
            Rule.objects.filter(Q(ruleset__user__isnull=True) | Q(ruleset__user=request.user)),
            pk=id,
        )
        name = os.path.basename(rule.path)
        try:
            yara_x.compile(data.text)
        except yara_x.CompileError as exc:
            return Status(400, {"errors": f"Invalid YARA syntax in {name}: {exc}"})
        if rule.ruleset.user == request.user:
            with open(rule.path, "w") as f:
                rule.rule = data.text
                rule.save()
                f.write(data.text)
            return Status(200, {"message": f"Rule {name} updated."})
        ruleset = _get_or_create_user_ruleset(request.user)
        user_path = Path(Setting.get("LOCAL_YARA_PATH")) / f"{sanitize_filename(request.user.username)}-Ruleset"
        rule.pk = None
        rule.ruleset = ruleset
        rule.rule = data.text
        new_path = unique_path_in_dir(user_path, Path(rule.path).name)
        with open(new_path, "w") as f:
            f.write(data.text)
        rule.path = str(new_path)
        rule.save()
        return Status(200, {"message": f"Rule {name} created in local ruleset."})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.get("/{int:id}/download", url_name="download_rule", auth=dual_auth, response={200: Any, 400: ErrorsOut})
def download_rule(request, id: int):
    """
    Download a rule file by its primary key.

    Args:
        pk (int): The primary key of the rule to download.

    Returns:
        HttpResponse: The HTTP response object containing the downloaded rule file.

    Raises:
        Exception: If an error occurs during the process.
    """
    try:
        rule = (
            Rule.objects.filter(pk=id, ruleset__enabled=True)
            .filter(Q(ruleset__user__isnull=True) | Q(ruleset__user=request.user))
            .first()
        )
        if not rule:
            return Status(400, {"errors": "Generic error"})
        if os.path.exists(rule.path):
            with open(rule.path, "rb") as f:
                rule_data = f.read()

            response = HttpResponse(
                rule_data,
                content_type="application/text",
            )
            response["Content-Disposition"] = f"attachment; filename={os.path.basename(rule.path)}"
            return response
        else:
            return Status(400, {"errors": "Rule not found"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete(
    "/",
    auth=dual_auth,
    url_name="delete_rules",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def delete_rules(request, info: ListStr):
    """
    Summary:
    Delete rules based on the provided rule IDs.

    Explanation:
    This function deletes rules based on the specified rule IDs belonging to the authenticated user. It removes the rules from the database and returns a success message upon deletion.

    Args:
    - request: The request object.
    - rule_ids: A list of integers representing the IDs of rules to be deleted.

    Returns:
    - Tuple containing status code and a message dictionary.

    Raises:
    - Any exception encountered during the process will result in a 400 status code with an error message.
    """
    try:
        rules = Rule.objects.filter(pk__in=info.rule_ids, ruleset__user=request.user)
        rules_count = rules.count()
        rules.delete()
        delete_message = f"{rules_count} rules deleted."
        if rules_count != len(info.rule_ids):
            delete_message += " Only rules in your ruleset have been deleted."
        return Status(200, {"message": delete_message})

    except Exception as excp:
        return Status(
            400,
            {"errors": (str(excp) if excp else "Generic error during rules deletion")},
        )


@router.post(
    "/build",
    response={200: SuccessResponse, 400: ErrorsOut},
    url_name="rule_build",
    auth=dual_auth,
)
def build_rules(request, info: RuleBuildSchema):
    """
    Summary:
    Build rules based on the provided information.

    Explanation:
    This function builds rules using the provided information and saves them in a custom folder. It creates a new YARA rule file and stores it in the specified location.

    Args:
    - request: The request object.
    - info: An instance of RuleBuildSchema containing rule information.

    Returns:
    - Tuple containing status code and a message dictionary.

    Raises:
    - Any exception encountered during the process will result in a 400 status code with an error message.
    """
    try:
        safe_rulename = sanitize_filename(info.rulename)
        rules_qs = Rule.objects.filter(pk__in=info.rule_ids).filter(
            Q(ruleset__user__isnull=True) | Q(ruleset__user=request.user)
        )
        if not rules_qs.exists():
            return Status(400, {"errors": "No accessible rules selected"})

        compiled_rules, _, _ = compile_yara_rules_queryset(rules_qs, ignore_errors=False)

        # Manage duplicated file path
        base_yara = Path(Setting.get("LOCAL_YARA_PATH") or "/yara")
        folder = base_yara / "customs" / sanitize_filename(request.user.username)
        new_path = unique_path_in_dir(folder, f"{safe_rulename}.yara")
        with open(new_path, "wb") as fo:
            compiled_rules.serialize_into(fo)
        CustomRule.objects.create(
            user=request.user,
            path=str(new_path),
            name=safe_rulename,
        )

        return Status(200, {"message": f"Rule {safe_rulename} created"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/",
    url_name="upload_rule",
    auth=dual_auth,
    response={200: list[RulesOutSchema], 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_test_required("is_not_readonly")
def upload_rule(request, files: list[UploadedFile] = File(...)):
    """Uploads rules from provided files and associates them with the user's ruleset.

    This function handles the uploading of rule files, ensuring they are saved in a user-specific directory.
    It validates YARA syntax before saving.

    Args:
        request: The HTTP request object containing user information.
        files (List[UploadedFile]): A list of files to be uploaded.

    Returns:
        Tuple[int, List[RuleOut] | ErrorsOut]: A tuple containing the HTTP status code and either a list of created rules or error details.
    """
    try:
        validated_files = []
        for f in files:
            raw_bytes = f.read()
            rule_text = raw_bytes.decode("utf8", "replace")
            try:
                yara_x.compile(rule_text)
            except yara_x.CompileError as exc:
                return Status(400, {"errors": f"Invalid YARA syntax in {f.name}: {exc}"})
            validated_files.append((f.name, raw_bytes, rule_text))

        rules = []
        ruleset = _get_or_create_user_ruleset(request.user)
        user_path = Path(Setting.get("LOCAL_YARA_PATH")) / f"{sanitize_filename(request.user.username)}-Ruleset"
        with transaction.atomic():
            for fname, raw_bytes, rule_text in validated_files:
                new_path = unique_path_in_dir(user_path, fname)
                with open(new_path, "wb") as uf:
                    uf.write(raw_bytes)
                rule = Rule.objects.create(
                    path=str(new_path),
                    ruleset=ruleset,
                    rule=rule_text,
                )
                rules.append(rule)
        return Status(200, rules)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.get(
    "/feeds/",
    auth=dual_auth,
    url_name="list_yara_feeds",
    response=list[RulesetFeedOut],
)
def list_yara_feeds(request: HttpRequest):
    """
    List all public YARA ruleset feeds with sync status and rule counts (Issue #1552).
    """
    rulesets = Ruleset.objects.filter(user__isnull=True).annotate(rules_count=Count("rules")).order_by("name")
    return [
        RulesetFeedOut(
            id=rs.pk,
            name=rs.name,
            url=rs.url,
            description=rs.description,
            enabled=rs.enabled,
            cloned=rs.cloned,
            auto_update=rs.auto_update,
            rules_count=rs.rules_count,
            last_sync=rs.last_sync,
            last_sync_status=rs.last_sync_status,
            last_sync_error=rs.last_sync_error,
        )
        for rs in rulesets
    ]


@router.post(
    "/feeds/sync",
    auth=dual_auth,
    url_name="sync_yara_feeds",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def sync_yara_feeds(request: HttpRequest, payload: RulesetFeedSyncIn | None = None):
    """
    Trigger synchronization of YARA rule feeds and recompile default rule (Issue #1552 / #272).
    """
    try:
        ruleset_id = payload.ruleset_id if payload else None
        compile_default = payload.compile_default if payload else True
        force = payload.force if payload else False

        task_res = sync_yara_rules.enqueue(
            ruleset_id=ruleset_id,
            compile_default=compile_default,
            force=force,
        )
        return Status(
            200,
            {"message": f"YARA rules sync task queued successfully (Task ID: {task_res.id})."},
        )
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/feeds/{int:ruleset_id}/toggle_auto_update",
    auth=dual_auth,
    url_name="toggle_feed_auto_update",
    response={200: SuccessResponse, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def toggle_feed_auto_update(request: HttpRequest, ruleset_id: int, payload: RulesetToggleAutoUpdateIn):
    """
    Toggle automatic update polling for a specific YARA feed (Issue #1552).
    """
    try:
        ruleset = get_object_or_404(Ruleset, pk=ruleset_id, user__isnull=True)
        ruleset.auto_update = payload.auto_update
        ruleset.save(update_fields=["auto_update"])
        status_str = "enabled" if payload.auto_update else "disabled"
        return Status(
            200,
            {"message": f"Auto-update {status_str} for feed '{ruleset.name}'."},
        )
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/compile_default",
    auth=dual_auth,
    url_name="compile_default_yara",
    response={200: dict, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def compile_default_yara_endpoint(request: HttpRequest):
    """
    Compile all active YARA rules into the default rule and sync to workers (Issue #272).
    """
    try:
        res = compile_default_yara_rule()
        worker_res = sync_rules_to_workers()
        res["workers"] = worker_res
        return Status(200, res)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/sync_workers",
    auth=dual_auth,
    url_name="sync_yara_workers",
    response={200: dict, 400: ErrorsOut, 403: ErrorsOut},
)
@ninja_role_required(ROLE_ADMIN)
def sync_yara_workers_endpoint(request: HttpRequest):
    """
    Verify and synchronize compiled YARA rules across all Dask workers (Issue #272).
    """
    try:
        res = sync_rules_to_workers()
        return Status(200, res)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})
