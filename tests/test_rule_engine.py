from __future__ import annotations

from pathlib import Path

import pytest

from aitlds_detection.normalizers import normalize_apache
from aitlds_detection.rule_engine import (
    ConditionParser,
    RuleValidationError,
    evaluate_rules,
    load_rules,
)


RULES = Path(__file__).resolve().parents[1] / "rules"


def test_condition_parser_boolean_and_pattern() -> None:
    selections = {"selection_a": True, "selection_b": False, "filter_x": False}
    assert ConditionParser(
        "1 of selection_* and not filter_x", selections
    ).parse() is True
    assert ConditionParser("all of selection_*", selections).parse() is False


def test_condition_parser_rejects_unknown_selection() -> None:
    with pytest.raises(RuleValidationError):
        ConditionParser("selection_missing", {"selection": True}).parse()


def test_rules_load_and_webshell_seed_keeps_source_reference() -> None:
    rules = load_rules(RULES)
    raw = (
        '192.168.10.238 - - [04/Mar/2020:19:32:50 +0000] '
        '"GET /static/evil.php?cmd=cat%20/etc/passwd HTTP/1.1" '
        '200 131 "-" "curl/7.58.0"'
    )
    event = normalize_apache(raw, "access.log", 122941)
    seeds = evaluate_rules(event, rules)
    titles = {seed["rule_title"] for seed in seeds}
    assert "Webshell Command in HTTP Query" in titles
    seed = next(seed for seed in seeds if seed["rule_title"] == "Webshell Command in HTTP Query")
    assert seed["evidence_refs"] == [{"file": "access.log", "line_no": 122941}]
    assert seed["rule_version"]


def test_normal_request_does_not_match() -> None:
    rules = load_rules(RULES)
    raw = (
        '192.168.10.190 - - [29/Feb/2020:00:00:02 +0000] '
        '"GET /login.php HTTP/1.1" 200 2532 "-" '
        '"Mozilla/5.0 Firefox/73.0"'
    )
    event = normalize_apache(raw, "access.log", 1)
    assert evaluate_rules(event, rules) == []


def test_nikto_user_agent_matches_across_response_codes() -> None:
    rules = load_rules(RULES)
    raw = (
        '192.168.10.18 - - [04/Mar/2020:13:54:29 +0000] '
        '"GET /./index.php HTTP/1.1" 302 553 "-" '
        '"Mozilla/5.00 (Nikto/2.1.5) (Test:getinfo)"'
    )
    event = normalize_apache(raw, "access.log", 2)
    titles = {seed["rule_title"] for seed in evaluate_rules(event, rules)}
    assert "Apache Nikto Scanner Activity" in titles
