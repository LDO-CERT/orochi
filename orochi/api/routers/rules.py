import os
from typing import List

import yara
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from ninja import Query, Router
from ninja.security import django_auth

from orochi.api.filters import RulesFilter
from orochi.api.models import (
    ErrorsOut,
    ListStr,
    RuleBuildSchema,
    RulesOutSchema,
    SuccessResponse,
)
from orochi.website.models import CustomRule
from orochi.ya.models import Rule

router = Router()


@router.get("/", response={200: List[RulesOutSchema]}, auth=django_auth)
def list_rules(request, filters: Query[RulesFilter]):
    return Rule.objects.all()


@router.get("/{pk}/download", auth=django_auth)
def download(request, pk: int):
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
        rule = Rule.objects.filter(pk=pk).filter(ruleset__enabled=True)
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
            return 400, {"errors": "Rule not found"}
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.delete(
    "/",
    auth=django_auth,
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
        rules.delete()
        rules_count = rules.count()
        if rules_count == 0:
            return 200, {"message": f"{rules_count} rules deleted."}
        else:
            return 200, {"message": "Only rules in your ruleset can be deleted."}
    except Exception as excp:
        return 400, {
            "errors": str(excp) if excp else "Generic error during rules deletion"
        }


@router.post(
    "/build",
    response={200: SuccessResponse, 400: ErrorsOut},
    url_name="rule_build",
    auth=django_auth,
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
        rules = Rule.objects.filter(pk__in=info.rule_ids)
        rules_file = {f"{rule.ruleset.name}_{rule.pk}": rule.path for rule in rules}
        rules = yara.compile(filepaths=rules_file)

        # Manage duplicated file path
        folder = f"/yara/customs/{request.user.username}"
        os.makedirs(folder, exist_ok=True)
        new_path = f"{folder}/{info.rulename}.yara"
        filename, extension = os.path.splitext(new_path)
        counter = 1
        while os.path.exists(new_path):
            new_path = f"{filename}{counter}{extension}"
            counter += 1

        rules.save(new_path)
        CustomRule.objects.create(
            user=request.user,
            path=new_path,
            name=info.rulename,
        )

        return 200, {"message": f"Rule {info.rulename} created"}
    except Exception as excp:
        return 400, {"errors": str(excp)}
