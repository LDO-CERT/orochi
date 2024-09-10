import os
from pathlib import Path

import yara_x
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from extra_settings.models import Setting
from ninja import Router
from ninja.security import django_auth

from orochi.api.models import (
    ErrorsOut,
    ListStr,
    RuleBuildSchema,
    RuleEditInSchena,
    SuccessResponse,
)
from orochi.website.models import CustomRule
from orochi.ya.models import Rule, Ruleset

router = Router()


@router.patch(
    "/{int:id}",
    auth=django_auth,
    url_name="edit_rule",
    response={200: SuccessResponse, 400: ErrorsOut},
)
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
        rule = get_object_or_404(Rule, pk=id)
        name = os.path.basename(rule.path)
        if rule.ruleset.user == request.user:
            with open(rule.path, "w") as f:
                rule.rule = data.text
                f.write(data.text)
            return 200, {"message": f"Rule {name} updated."}
        ruleset = get_object_or_404(Ruleset, user=request.user)
        user_path = f"{Setting.get('LOCAL_YARA_PATH')}/{request.user.username}-Ruleset"
        os.makedirs(user_path, exist_ok=True)
        rule.pk = None
        rule.ruleset = ruleset
        rule.rule = data.text
        new_path = f"{user_path}/{Path(rule.path).name}"
        filename, extension = os.path.splitext(new_path)
        counter = 1
        while os.path.exists(new_path):
            new_path = f"{filename}{counter}{extension}"
            counter += 1
        with open(new_path, "w") as f:
            f.write(data.text)
        rule.path = new_path
        rule.save()
        return 200, {"message": f"Rule {name} created in local ruleset."}
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.get("/{int:id}/download", url_name="download_rule", auth=django_auth)
def download(request, id: int):
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
        rule = Rule.objects.filter(pk=id).filter(ruleset__enabled=True)
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
        rules_count = rules.count()
        rules.delete()
        delete_message = f"{rules_count} rules deleted."
        if rules_count != len(info.rule_ids):
            delete_message += " Only rules in your ruleset have been deleted."
        return 200, {"message": delete_message}

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

        compiler = yara_x.Compiler()
        for rule in rules:
            with open(rule.path, "r") as fp:
                compiler.add_source(fp.read())
        rules = compiler.build()

        # Manage duplicated file path
        folder = f"/yara/customs/{request.user.username}"
        os.makedirs(folder, exist_ok=True)
        new_path = f"{folder}/{info.rulename}.yara"
        filename, extension = os.path.splitext(new_path)
        counter = 1
        while os.path.exists(new_path):
            new_path = f"{filename}{counter}{extension}"
            counter += 1
        with open(new_path, "wb") as fo:
            rules.serialize_into(fo)
        CustomRule.objects.create(
            user=request.user,
            path=new_path,
            name=info.rulename,
        )

        return 200, {"message": f"Rule {info.rulename} created"}
    except Exception as excp:
        return 400, {"errors": str(excp)}
