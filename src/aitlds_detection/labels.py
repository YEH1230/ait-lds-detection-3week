"""Read AIT-LDS v1.0 line-aligned labels without hiding label uncertainty."""

from __future__ import annotations

from itertools import zip_longest
from pathlib import Path
from typing import Callable, Iterator


class LabelAlignmentError(ValueError):
    pass


def parse_label(raw_label: str, policy: str) -> dict:
    parts = raw_label.rstrip("\r\n").split(",", 1)
    if len(parts) != 2:
        raise LabelAlignmentError(f"invalid label row: {raw_label!r}")
    time_label, event_label = (part.strip() for part in parts)
    if policy not in {"time", "event"}:
        raise ValueError(f"unsupported label policy: {policy}")
    selected = time_label if policy == "time" else event_label
    return {
        "time_window": time_label,
        "similarity_order": event_label,
        "policy": policy,
        "selected": selected,
        "is_attack": selected != "0",
    }


def iter_labeled_events(
    log_path: Path,
    label_path: Path,
    normalizer: Callable,
    *,
    label_policy: str = "event",
    year: int = 2020,
) -> Iterator[dict]:
    source_name = log_path.as_posix()
    with log_path.open(encoding="utf-8", errors="replace") as logs, label_path.open(
        encoding="utf-8", errors="replace"
    ) as labels:
        for line_no, pair in enumerate(
            zip_longest(logs, labels, fillvalue=None), start=1
        ):
            raw_line, raw_label = pair
            if raw_line is None or raw_label is None:
                raise LabelAlignmentError(
                    f"log/label line count mismatch at line {line_no}"
                )
            raw_line = raw_line.rstrip("\r\n")
            event = normalizer(raw_line, source_name, line_no, year=year)
            event["ground_truth"] = parse_label(raw_label, label_policy)
            yield event

