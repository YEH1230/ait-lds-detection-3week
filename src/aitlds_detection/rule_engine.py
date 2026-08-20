"""Small, explicit Sigma subset evaluator used by the AIT-LDS PoC.

It is intentionally not advertised as a complete Sigma implementation.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from . import __version__


SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "exists",
    "cased",
    "neq",
}
TOKEN_PATTERN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_.*-]+)")
SENSITIVE_PATTERN = re.compile(
    r"(?i)(password|passwd|pwd|token|session|key)=([^&\s]+)"
)


class RuleValidationError(ValueError):
    pass


def get_field(event: dict[str, Any], field: str) -> tuple[bool, Any]:
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _mask(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return SENSITIVE_PATTERN.sub(r"\1=[REDACTED]", value)[:512]


def _string_equal(actual: str, expected: str, cased: bool) -> bool:
    left = actual if cased else actual.casefold()
    right = expected if cased else expected.casefold()
    if "*" in right or "?" in right:
        return fnmatch.fnmatchcase(left, right)
    return left == right


def compare_scalar(actual: Any, expected: Any, modifiers: set[str]) -> bool:
    if "exists" in modifiers:
        return bool(expected)
    if isinstance(actual, list):
        result = any(compare_scalar(item, expected, modifiers) for item in actual)
        return not result if "neq" in modifiers else result
    if not isinstance(actual, str) or not isinstance(expected, str):
        result = actual == expected
        return not result if "neq" in modifiers else result

    cased = "cased" in modifiers
    left = actual if cased else actual.casefold()
    right = expected if cased else expected.casefold()
    if "contains" in modifiers:
        result = right in left
    elif "startswith" in modifiers:
        result = left.startswith(right)
    elif "endswith" in modifiers:
        result = left.endswith(right)
    else:
        result = _string_equal(actual, expected, cased)
    return not result if "neq" in modifiers else result


def match_field(event: dict[str, Any], expression: str, expected: Any) -> bool:
    parts = expression.split("|")
    field, modifiers = parts[0], set(parts[1:])
    unsupported = modifiers - SUPPORTED_MODIFIERS
    if unsupported:
        raise RuleValidationError(
            f"unsupported modifier(s) {sorted(unsupported)} in {expression}"
        )
    present, actual = get_field(event, field)
    if "exists" in modifiers:
        return present is bool(expected)
    if not present:
        return False
    values = expected if isinstance(expected, list) else [expected]
    results = [compare_scalar(actual, value, modifiers) for value in values]
    return all(results) if "all" in modifiers else any(results)


def match_selection(event: dict[str, Any], selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(match_field(event, key, value) for key, value in selection.items())
    if isinstance(selection, list):
        return any(match_selection(event, item) for item in selection)
    raise RuleValidationError("Sigma subset selections must be a map or list of maps")


class ConditionParser:
    def __init__(self, condition: str, selections: dict[str, bool]) -> None:
        self.selections = selections
        self.tokens = self._tokenize(condition)
        self.index = 0

    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(condition):
            match = TOKEN_PATTERN.match(condition, position)
            if not match:
                raise RuleValidationError(
                    f"unsupported condition syntax near {condition[position:]!r}"
                )
            tokens.append(match.group(1))
            position = match.end()
        return tokens

    def parse(self) -> bool:
        result = self._parse_or()
        if self.index != len(self.tokens):
            raise RuleValidationError(
                f"unexpected condition token: {self.tokens[self.index]}"
            )
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self, expected: str | None = None) -> str:
        token = self._peek()
        if token is None:
            raise RuleValidationError("unexpected end of condition")
        if expected is not None and token.casefold() != expected:
            raise RuleValidationError(f"expected {expected!r}, got {token!r}")
        self.index += 1
        return token

    def _parse_or(self) -> bool:
        result = self._parse_and()
        while (self._peek() or "").casefold() == "or":
            self._take("or")
            right = self._parse_and()
            result = result or right
        return result

    def _parse_and(self) -> bool:
        result = self._parse_not()
        while (self._peek() or "").casefold() == "and":
            self._take("and")
            right = self._parse_not()
            result = result and right
        return result

    def _parse_not(self) -> bool:
        if (self._peek() or "").casefold() == "not":
            self._take("not")
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        token = self._take()
        if token == "(":
            result = self._parse_or()
            self._take(")")
            return result
        if token.casefold() in {"1", "all"}:
            quantifier = token.casefold()
            self._take("of")
            pattern = self._take()
            names = list(self.selections)
            if pattern.casefold() != "them":
                names = [name for name in names if fnmatch.fnmatchcase(name, pattern)]
            if not names:
                raise RuleValidationError(
                    f"condition pattern matches no selections: {pattern}"
                )
            values = [self.selections[name] for name in names]
            return any(values) if quantifier == "1" else all(values)
        if token not in self.selections:
            raise RuleValidationError(f"unknown selection in condition: {token}")
        return self.selections[token]


@dataclass(frozen=True)
class SigmaSubsetRule:
    path: Path
    data: dict[str, Any]
    version: str

    @property
    def rule_id(self) -> str:
        return str(self.data["id"])

    @property
    def target_labels(self) -> set[str]:
        return set(self.data.get("x_aitlds_labels", []))

    def matches_logsource(self, event: dict[str, Any]) -> bool:
        actual = event.get("logsource", {})
        return all(
            key == "definition" or actual.get(key) == value
            for key, value in self.data["logsource"].items()
        )

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if not self.matches_logsource(event):
            return None
        detection = self.data["detection"]
        selections = {
            name: match_selection(event, selection)
            for name, selection in detection.items()
            if name != "condition"
        }
        if not ConditionParser(detection["condition"], selections).parse():
            return None

        matched_names = [name for name, result in selections.items() if result]
        matched_fields: dict[str, Any] = {}
        for name in matched_names:
            selection = detection[name]
            maps = selection if isinstance(selection, list) else [selection]
            for mapping in maps:
                if not isinstance(mapping, dict):
                    continue
                for expression in mapping:
                    field = expression.split("|", 1)[0]
                    present, value = get_field(event, field)
                    if present:
                        matched_fields[field] = _mask(value)

        seed_material = f"{event['event_id']}:{self.rule_id}:{self.version}"
        return {
            "seed_id": hashlib.sha256(seed_material.encode()).hexdigest(),
            "event_id": event["event_id"],
            "rule_id": self.rule_id,
            "rule_title": self.data["title"],
            "rule_version": self.version,
            "severity": self.data.get("level", "medium"),
            "classification": "suspicious",
            "matched_selections": matched_names,
            "evidence_refs": [
                {
                    "file": event["log"]["file"],
                    "line_no": event["log"]["line_no"],
                }
            ],
            "matched_fields_masked": matched_fields,
            "engine_version": __version__,
            "created_at": event.get("@timestamp"),
        }


def validate_rule(data: dict[str, Any], path: Path) -> None:
    required = {"title", "id", "status", "description", "logsource", "detection"}
    missing = sorted(required - data.keys())
    if missing:
        raise RuleValidationError(f"{path}: missing fields {missing}")
    if not isinstance(data["logsource"], dict) or not data["logsource"]:
        raise RuleValidationError(f"{path}: logsource must be a non-empty map")
    if not isinstance(data["detection"], dict):
        raise RuleValidationError(f"{path}: detection must be a map")
    condition = data["detection"].get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise RuleValidationError(f"{path}: detection.condition must be a string")
    selection_names = [name for name in data["detection"] if name != "condition"]
    if not selection_names:
        raise RuleValidationError(f"{path}: no selections")
    for name in selection_names:
        selection = data["detection"][name]
        maps = selection if isinstance(selection, list) else [selection]
        for mapping in maps:
            if not isinstance(mapping, dict):
                raise RuleValidationError(f"{path}: {name} must contain maps")
            for expression in mapping:
                modifiers = set(expression.split("|")[1:])
                unsupported = modifiers - SUPPORTED_MODIFIERS
                if unsupported:
                    raise RuleValidationError(
                        f"{path}: unsupported modifiers {sorted(unsupported)}"
                    )
    ConditionParser(condition, {name: False for name in selection_names}).parse()


def load_rules(directory: Path) -> list[SigmaSubsetRule]:
    rules: list[SigmaSubsetRule] = []
    seen_ids: set[str] = set()
    for path in sorted(directory.glob("*.yml")):
        raw = path.read_bytes()
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            raise RuleValidationError(f"{path}: rule must be a YAML map")
        validate_rule(data, path)
        rule_id = str(data["id"])
        if rule_id in seen_ids:
            raise RuleValidationError(f"duplicate rule id: {rule_id}")
        seen_ids.add(rule_id)
        rules.append(
            SigmaSubsetRule(path=path, data=data, version=hashlib.sha256(raw).hexdigest()[:12])
        )
    if not rules:
        raise RuleValidationError(f"no .yml rules found in {directory}")
    return rules


def evaluate_rules(event: dict[str, Any], rules: list[SigmaSubsetRule]) -> list[dict]:
    return [seed for rule in rules if (seed := rule.evaluate(event)) is not None]


def rule_manifest(rules: list[SigmaSubsetRule]) -> str:
    return json.dumps(
        [
            {
                "id": rule.rule_id,
                "title": rule.data["title"],
                "version": rule.version,
                "path": rule.path.as_posix(),
                "target_labels": sorted(rule.target_labels),
            }
            for rule in rules
        ],
        ensure_ascii=False,
        indent=2,
    )

