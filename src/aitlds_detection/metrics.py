"""Binary and per-rule metrics for line-level AIT-LDS evaluation."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, expected: bool, predicted: bool) -> None:
        if expected and predicted:
            self.tp += 1
        elif not expected and predicted:
            self.fp += 1
        elif expected and not predicted:
            self.fn += 1
        else:
            self.tn += 1

    def to_dict(self) -> dict:
        precision = self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0
        recall = self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        fpr = self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0
        return {
            **asdict(self),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": fpr,
        }

