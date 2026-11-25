"""Declarative Sigma-style YAML hunting rules engine over Volatility plugin rows (Issue #1545)."""

from __future__ import annotations

import logging
import re
from typing import Any

import yaml

from orochi.website.defaults import RESULT_STATUS_SUCCESS
from orochi.website.detection.rules import DetectionResult
from orochi.website.models import Dump, HuntingRule, Result, Value

logger = logging.getLogger(__name__)

LEVEL_TO_SEVERITY = {
    "low": ("Low", 15),
    "medium": ("Medium", 25),
    "high": ("High", 35),
    "critical": ("Critical", 50),
}


class SigmaRuleValidationError(ValueError):
    """Raised when a declarative YAML hunting rule is malformed or missing required sections."""


def parse_and_validate_sigma_rule(yaml_content: str) -> dict[str, Any]:
    """Parse and validate a Sigma-style YAML rule string."""
    if not yaml_content or not yaml_content.strip():
        raise SigmaRuleValidationError("Rule YAML content cannot be empty.")
    try:
        parsed = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise SigmaRuleValidationError(f"Invalid YAML syntax: {exc}") from exc

    if not isinstance(parsed, dict):
        raise SigmaRuleValidationError("Rule YAML must deserialize to a mapping/dictionary.")
    if not parsed.get("title"):
        raise SigmaRuleValidationError("Rule must define a 'title' field.")
    detection = parsed.get("detection")
    if not isinstance(detection, dict) or not detection:
        raise SigmaRuleValidationError("Rule must define a non-empty 'detection' mapping.")

    named_blocks = {k: v for k, v in detection.items() if k != "condition"}
    if not named_blocks:
        raise SigmaRuleValidationError("Rule 'detection' must define at least one selection block.")
    for name, block in named_blocks.items():
        if not isinstance(block, (dict, list)):
            raise SigmaRuleValidationError(f"Detection block '{name}' must be a mapping or list of mappings.")

    return parsed


def _match_single_value(actual: Any, expected: Any, modifiers: set[str]) -> bool:
    if actual is None:
        return False
    actual_str = str(actual)
    expected_str = str(expected)

    if "re" in modifiers:
        try:
            return bool(re.search(expected_str, actual_str, re.IGNORECASE))
        except re.error:
            return False

    a_low = actual_str.lower()
    e_low = expected_str.lower()
    if "contains" in modifiers:
        return e_low in a_low
    if "startswith" in modifiers:
        return a_low.startswith(e_low)
    if "endswith" in modifiers:
        return a_low.endswith(e_low)
    return a_low == e_low


def _match_field_condition(row: dict[str, Any], field_spec: str, expected: Any) -> bool:
    parts = field_spec.split("|")
    field_name = parts[0]
    modifiers = {p.lower() for p in parts[1:]}

    # Case-insensitive lookup of field_name in row
    actual = None
    if field_name in row:
        actual = row[field_name]
    else:
        low_target = field_name.lower()
        for k, v in row.items():
            if str(k).lower() == low_target:
                actual = v
                break

    if isinstance(expected, list):
        if "all" in modifiers:
            return all(_match_single_value(actual, item, modifiers) for item in expected)
        return any(_match_single_value(actual, item, modifiers) for item in expected)
    return _match_single_value(actual, expected, modifiers)


def _match_selection_block(row: dict[str, Any], block: dict[str, Any] | list[Any]) -> bool:
    if isinstance(block, list):
        return any(
            isinstance(sub, dict) and all(_match_field_condition(row, k, v) for k, v in sub.items()) for sub in block
        )
    return all(_match_field_condition(row, k, v) for k, v in block.items())


def _evaluate_condition(condition: str, block_results: dict[str, bool]) -> bool:
    """Safely evaluate boolean condition over named selection results (and/or/not/parentheses)."""
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_]+", condition or "")
    if not tokens:
        return any(block_results.values())

    pos = 0

    def parse_or() -> bool:
        nonlocal pos
        val = parse_and()
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            right = parse_and()
            val = val or right
        return val

    def parse_and() -> bool:
        nonlocal pos
        val = parse_not()
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            right = parse_not()
            val = val and right
        return val

    def parse_not() -> bool:
        nonlocal pos
        if pos < len(tokens) and tokens[pos].lower() == "not":
            pos += 1
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        nonlocal pos
        if pos >= len(tokens):
            return False
        tok = tokens[pos]
        if tok == "(":
            pos += 1
            val = parse_or()
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return val
        pos += 1
        return bool(block_results.get(tok, False))

    return parse_or()


def match_sigma_rule_on_row(parsed_rule: dict[str, Any], row: dict[str, Any]) -> bool:
    """Return True if a single plugin row satisfies the parsed Sigma-style rule."""
    detection = parsed_rule["detection"]
    block_results = {
        name: _match_selection_block(row, block) for name, block in detection.items() if name != "condition"
    }
    condition = detection.get("condition")
    if not condition:
        return all(block_results.values()) if block_results else False
    return _evaluate_condition(str(condition), block_results)


def evaluate_hunting_rules(dump: Dump) -> list[DetectionResult]:
    """Evaluate all enabled HuntingRule definitions against a dump's successful plugin rows (#1545)."""
    rules = list(HuntingRule.objects.filter(enabled=True))
    if not rules:
        return []

    results_qs = list(Result.objects.filter(dump=dump, result=RESULT_STATUS_SUCCESS).select_related("plugin"))
    if not results_qs:
        return []

    findings: list[DetectionResult] = []
    rows_cache: dict[int, list[dict[str, Any]]] = {}

    for rule in rules:
        try:
            parsed = parse_and_validate_sigma_rule(rule.yaml_content)
        except SigmaRuleValidationError as exc:
            logger.warning("Skipping invalid HuntingRule '%s': %s", rule.slug, exc)
            continue

        logsource = parsed.get("logsource") if isinstance(parsed.get("logsource"), dict) else {}
        # The rule's own filter wins only when set; "*" (the default) defers to the YAML logsource
        plugin_filter = (rule.plugin_filter or "*").strip()
        if plugin_filter in {"*", ""}:
            plugin_filter = str(logsource.get("plugin") or "*").strip()

        matching_results = [
            r for r in results_qs if plugin_filter in {"*", ""} or r.plugin.name.lower().endswith(plugin_filter.lower())
        ]
        if not matching_results:
            continue

        # A ``level`` in the YAML sets severity and score; otherwise the rule's own fields apply
        level = str(parsed.get("level") or "").lower()
        severity, score = LEVEL_TO_SEVERITY.get(level, (rule.severity, rule.score))

        for res in matching_results:
            if res.pk not in rows_cache:
                rows_cache[res.pk] = list(Value.objects.filter(result=res).values_list("value", flat=True))
            for row in rows_cache[res.pk]:
                if not isinstance(row, dict):
                    continue
                if match_sigma_rule_on_row(parsed, row):
                    pid = row.get("PID") or row.get("Pid")
                    proc = row.get("ImageFileName") or row.get("Process") or row.get("COMM") or res.plugin.name
                    entity = f"{proc} (PID {pid})" if pid else str(proc)
                    findings.append(
                        DetectionResult(
                            rule_id=f"HUNT_{rule.slug.upper()}",
                            rule_name=parsed.get("title") or rule.name,
                            category="Hunting Rule (Sigma)",
                            severity=severity,
                            score=score,
                            mitre_technique=rule.mitre_technique or "",
                            description=parsed.get("description")
                            or rule.description
                            or f"Matched hunting rule '{rule.name}'.",
                            evidence_snippet=f"Plugin: {res.plugin.name} | Row: {str(row)[:200]}",
                            entity=entity,
                            raw_data=row,
                        )
                    )

    return findings
