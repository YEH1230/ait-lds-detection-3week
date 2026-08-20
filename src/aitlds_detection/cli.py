"""Command line interface for normalization, detection and evaluation."""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

from .labels import iter_labeled_events
from .metrics import ConfusionMatrix
from .normalizers import NORMALIZERS
from .rule_engine import evaluate_rules, load_rules, rule_manifest


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize(args: argparse.Namespace) -> None:
    normalizer = NORMALIZERS[args.log_type]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    processed = 0
    failures = 0
    start = time.perf_counter()
    with args.log.open(encoding="utf-8", errors="replace") as source, args.output.open(
        "w", encoding="utf-8"
    ) as destination:
        for line_no, raw_line in enumerate(source, start=1):
            if args.limit is not None and processed >= args.limit:
                break
            event = normalizer(
                raw_line.rstrip("\r\n"),
                args.log.as_posix(),
                line_no,
                year=args.year,
            )
            processed += 1
            if not event["normalizer"]["success"]:
                failures += 1
            destination.write(json.dumps(event, ensure_ascii=False) + "\n")
    elapsed = time.perf_counter() - start
    stats = {
        "input": args.log.as_posix(),
        "output": args.output.as_posix(),
        "log_type": args.log_type,
        "processed_events": processed,
        "parse_failures": failures,
        "runtime_seconds": elapsed,
        "events_per_second": processed / elapsed if elapsed else 0.0,
    }
    _write_json(args.output.with_suffix(args.output.suffix + ".stats.json"), stats)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


def evaluate(args: argparse.Namespace) -> None:
    normalizer = NORMALIZERS[args.log_type]
    rules = load_rules(args.rules)
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    (output / "rule_manifest.json").write_text(rule_manifest(rules), encoding="utf-8")

    overall = ConfusionMatrix()
    per_rule = {rule.rule_id: ConfusionMatrix() for rule in rules}
    active_rule_ids: set[str] = set()
    label_counts: Counter[str] = Counter()
    parse_failures = 0
    example_errors: list[dict] = []
    seeds_path = output / "detection_seeds.jsonl"
    start = time.perf_counter()
    processed = 0

    with seeds_path.open("w", encoding="utf-8") as seed_output:
        for event in iter_labeled_events(
            args.log,
            args.labels,
            normalizer,
            label_policy=args.label_policy,
            year=args.year,
        ):
            processed += 1
            if not event["normalizer"]["success"]:
                parse_failures += 1
            truth = event["ground_truth"]
            label_counts[truth["selected"]] += 1
            seeds = evaluate_rules(event, rules)
            predicted_ids = {seed["rule_id"] for seed in seeds}
            overall.add(truth["is_attack"], bool(seeds))

            for rule in rules:
                if not rule.matches_logsource(event):
                    continue
                active_rule_ids.add(rule.rule_id)
                expected = truth["selected"] in rule.target_labels
                per_rule[rule.rule_id].add(expected, rule.rule_id in predicted_ids)

            for seed in seeds:
                seed["ground_truth"] = truth
                seed_output.write(json.dumps(seed, ensure_ascii=False) + "\n")

            if len(example_errors) < args.max_error_examples and (
                truth["is_attack"] != bool(seeds)
            ):
                example_errors.append(
                    {
                        "file": event["log"]["file"],
                        "line_no": event["log"]["line_no"],
                        "label": truth,
                        "predicted_rule_ids": sorted(predicted_ids),
                        "raw_line": event["raw_line"],
                    }
                )

    elapsed = time.perf_counter() - start
    report = {
        "input": {
            "log": args.log.as_posix(),
            "labels": args.labels.as_posix(),
            "log_type": args.log_type,
            "label_policy": args.label_policy,
        },
        "processed_events": processed,
        "parse_failures": parse_failures,
        "selected_label_counts": dict(label_counts.most_common()),
        "overall": overall.to_dict(),
        "per_rule": {
            rule.rule_id: {
                "title": rule.data["title"],
                "target_labels": sorted(rule.target_labels),
                **per_rule[rule.rule_id].to_dict(),
            }
            for rule in rules
            if rule.rule_id in active_rule_ids
        },
        "runtime_seconds": elapsed,
        "events_per_second": processed / elapsed if elapsed else 0.0,
        "error_examples": example_errors,
        "notes": [
            "Metrics are event/line-level, not attack-chain-level.",
            "AIT-LDS labels are automatically generated and were not manually corrected.",
            "Default event policy uses the second similarity/order label column.",
        ],
    }
    _write_json(output / "metrics.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    normalize_parser = subparsers.add_parser("normalize")
    normalize_parser.add_argument("--log", type=Path, required=True)
    normalize_parser.add_argument("--log-type", choices=sorted(NORMALIZERS), required=True)
    normalize_parser.add_argument("--output", type=Path, required=True)
    normalize_parser.add_argument("--year", type=int, default=2020)
    normalize_parser.add_argument("--limit", type=int)
    normalize_parser.set_defaults(handler=normalize)
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--log", type=Path, required=True)
    evaluate_parser.add_argument("--labels", type=Path, required=True)
    evaluate_parser.add_argument("--log-type", choices=sorted(NORMALIZERS), required=True)
    evaluate_parser.add_argument("--rules", type=Path, required=True)
    evaluate_parser.add_argument("--output-dir", type=Path, required=True)
    evaluate_parser.add_argument("--label-policy", choices=["event", "time"], default="event")
    evaluate_parser.add_argument("--year", type=int, default=2020)
    evaluate_parser.add_argument("--max-error-examples", type=int, default=20)
    evaluate_parser.set_defaults(handler=evaluate)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
