"""Create a compact feature profile for one labeled AIT-LDS log file."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aitlds_detection.labels import iter_labeled_events  # noqa: E402
from aitlds_detection.normalizers import NORMALIZERS  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--log-type", choices=sorted(NORMALIZERS), required=True)
    parser.add_argument("--label-policy", choices=["event", "time"], default="event")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    label_counts: Counter[str] = Counter()
    profiles: dict[str, dict[str, Counter[str]]] = defaultdict(
        lambda: defaultdict(Counter)
    )
    parse_failures = 0
    parse_failure_examples: list[dict[str, object]] = []
    total = 0
    for event in iter_labeled_events(
        args.log,
        args.labels,
        NORMALIZERS[args.log_type],
        label_policy=args.label_policy,
    ):
        total += 1
        label = event["ground_truth"]["selected"]
        label_counts[label] += 1
        if not event["normalizer"]["success"]:
            parse_failures += 1
            if len(parse_failure_examples) < 20:
                parse_failure_examples.append(
                    {
                        "line_no": event["log"]["line_no"],
                        "label": label,
                        "errors": event["normalizer"]["errors"],
                        "raw_line": event["raw_line"],
                    }
                )
        features = {
            "method": event["http"]["request"].get("method"),
            "status": event["http"]["response"].get("status_code"),
            "user_agent": event["user_agent"].get("original"),
            "path": event["url"].get("path"),
            "action": event["event"].get("action"),
            "auth_service": event["auth"].get("service"),
        }
        for name, value in features.items():
            if value is not None:
                profiles[label][name][str(value)] += 1

    payload = {
        "input": {
            "log": args.log.as_posix(),
            "labels": args.labels.as_posix(),
            "log_type": args.log_type,
            "label_policy": args.label_policy,
        },
        "total": total,
        "parse_failures": parse_failures,
        "parse_failure_examples": parse_failure_examples,
        "label_counts": dict(label_counts.most_common()),
        "top_features_by_label": {
            label: {
                feature: counts.most_common(12)
                for feature, counts in feature_counters.items()
            }
            for label, feature_counters in profiles.items()
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
