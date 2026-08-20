"""Summarize AIT-LDS line-aligned labels and show matching log samples."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def inspect(log_path: Path, label_path: Path, limit: int) -> dict[str, object]:
    counts: Counter[str] = Counter()
    samples: dict[str, list[dict[str, object]]] = defaultdict(list)
    total = 0
    with log_path.open(encoding="utf-8", errors="replace") as logs, label_path.open(
        encoding="utf-8", errors="replace"
    ) as labels:
        for line_number, pair in enumerate(zip(logs, labels, strict=True), start=1):
            raw_line, raw_label = pair
            time_label, similarity_label = (
                part.strip() for part in raw_label.rstrip("\r\n").split(",", 1)
            )
            label_key = f"{time_label},{similarity_label}"
            counts[label_key] += 1
            if label_key != "0,0" and len(samples[label_key]) < limit:
                samples[label_key].append(
                    {"line_no": line_number, "raw_line": raw_line.rstrip("\r\n")}
                )
            total += 1
    return {
        "total": total,
        "counts": dict(counts.most_common()),
        "samples": dict(samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("labels", type=Path)
    parser.add_argument("--limit", type=int, default=3)
    args = parser.parse_args()
    print(
        json.dumps(
            inspect(args.log, args.labels, args.limit),
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
