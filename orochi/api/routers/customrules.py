import os
import shutil
from typing import List, Optional

from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from extra_settings.models import Setting
from ninja import Query, Router
from ninja.pagination import paginate
from ninja.security import django_auth

from orochi.api.models import (
    RULE_ACTION,
    CustomRulePagination,
    ErrorsOut,
    ListStr,
    ListStrAction,
    RuleData,
    RuleFilter,
    SuccessResponse,
)
from orochi.website.models import CustomRule

router = Router()


@router.get(
    "/",
    auth=django_auth,
    url_name="list_customrules",
    response=List[RuleData],
)
@paginate(CustomRulePagination)
def list_custom_rules(
    request: HttpRequest, draw: Optional[int], filters: RuleFilter = Query(...)
):
    rules = CustomRule.objects.filter(Q(public=True) | Q(user=request.user))
    request.draw = draw
    request.total = rules.count()
    request.search = filters.search or None
    if filters.search:
        filtered_rules = rules.filter(
            Q(name__icontains=filters.search) | Q(path__icontains=filters.search)
        )
    else:
        filtered_rules = rules
    sort_fields = ["pk", "name", "path", "public", "user"]
    sort = sort_fields[filters.order_column] if filters.order_column else sort_fields[0]
    if filters.order_dir and filters.order_dir == "desc":
        sort = f"-{sort}"
    return filtered_rules.order_by(sort)


@router.post(
    "/{int:id}/default",
    auth=django_auth,
    url_name="default_customrule",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def default_custom_rule(request, id: int):
    """
    Set a custom rule as the default.

    Args:
        request: The request object.
        id (int): The ID of the custom rule to set as default.

    Returns:
        tuple: A tuple containing the status code and a dictionary with a message.

    Raises:
        Exception: If an error occurs during the process of setting the rule as default.
    """
    try:
        old_default = CustomRule.objects.filter(user=request.user, default=True)
        if old_default.count() == 1:
            old = old_default.first()
            old.default = False
            old.save()

        rule = CustomRule.objects.get(pk=id)
        name = os.path.basename(rule.path)
        if rule.user == request.user:
            rule.default = True
            rule.save()
            return 200, {"message": f"Rule {name} set as default."}
        # Make a copy
        user_path = f"{Setting.get('LOCAL_YARA_PATH')}/{request.user.username}-Ruleset"
        os.makedirs(user_path, exist_ok=True)
        new_path = f"{user_path}/{rule.name}"
        filename, extension = os.path.splitext(new_path)
        counter = 1
        while os.path.exists(new_path):
            new_path = f"{filename}{counter}{extension}"
            counter += 1

        shutil.copy(rule.path, new_path)
        CustomRule.objects.create(
            user=request.user, name=rule.name, path=new_path, default=True
        )
        name = os.path.basename(new_path)

        return 200, {
            "message": f"Rule {name} copied in your ruleset and set as default."
        }
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.post(
    "/publish",
    auth=django_auth,
    url_name="publish_customrule",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def publish_custom_rules(request, info: ListStrAction):
    try:
        rules = CustomRule.objects.filter(pk__in=info.rule_ids, user=request.user)
        rules_count = rules.count()
        for rule in rules:
            rule.public = info.action == RULE_ACTION.PUBLISH
            rule.save()
        return 200, {"message": f"{rules_count} custom rules {info.action.value}ed."}

    except Exception as excp:
        return 400, {
            "errors": (str(excp) if excp else "Generic error during publishing")
        }


@router.get("/{int:id}/download", auth=django_auth)
def download_custom_rule(request, id: int):
    """
    Download a custom rule file by its primary key.

    Args:
        pk (int): The primary key of the custom rule to download.

    Returns:
        HttpResponse: The HTTP response object containing the downloaded custom rule file.

    Raises:
        Exception: If an error occurs during the process.
    """
    try:
        rule = CustomRule.objects.filter(pk=id).filter(
            Q(user=request.user) | Q(public=True)
        )
        if rule.count() == 1:
            rule = rule.first()
        else:
            return 400, {"errors": "Generic error"}
        if os.path.exists(rule.path):
            with open(rule.path, "rb") as f:
                rule_data = f.read()

            response = HttpResponse(
                rule_data,
                content_type="application/text",
            )
            response["Content-Disposition"] = (
                f"attachment; filename={os.path.basename(rule.path)}"
            )
            return response
        else:
            return 400, {"errors": "Custom Rule not found"}
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.delete(
    "/",
    auth=django_auth,
    url_name="delete_customrules",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def delete_custom_rules(request, info: ListStr):
    """
    Summary:
    Delete custom rules based on the provided rule IDs.

    Explanation:
    This function deletes custom rules based on the specified rule IDs belonging to the authenticated user. It removes the rules from the database and returns a success message upon deletion.

    Args:
    - request: The request object.
    - rule_ids: A list of integers representing the IDs of custom rules to be deleted.

    Returns:
    - Tuple containing status code and a message dictionary.

    Raises:
    - Any exception encountered during the process will result in a 400 status code with an error message.
    """
    try:
        rules = CustomRule.objects.filter(pk__in=info.rule_ids, user=request.user)
        rules_count = rules.count()
        for rule in rules:
            os.remove(rule.path)
        rules.delete()
        delete_message = f"{rules_count} custom rules deleted."
        if rules_count != len(info.rule_ids):
            delete_message += " Only custom rules in your ruleset have been deleted."
        return 200, {"message": delete_message}

    except Exception as excp:
        return 400, {
            "errors": (
                str(excp) if excp else "Generic error during custom rules deletion"
            )
        }
