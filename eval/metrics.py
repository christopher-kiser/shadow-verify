"""Pure scores. A zero denominator is null. No AWS and no labels are invented."""

from __future__ import annotations

import math
import statistics
from typing import Any

CLASSES = ("PASS", "FAIL", "NOT_ASSESSED")
Z = 1.959964


def wilson(successes: int, n: int, z: float = Z) -> dict[str, float] | None:
    if n <= 0:
        return None
    p = successes / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    low = max(0.0, center - half)
    high = min(1.0, center + half)
    if low < 1e-12:
        low = 0.0
    if high > 1 - 1e-12:
        high = 1.0
    return {"k": successes, "n": n, "point": p, "low": low, "high": high}


def percentile_95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = math.ceil(0.95 * len(ordered)) - 1
    return ordered[max(0, index)]


def kappa(left: list[str], right: list[str]) -> float | None:
    n = len(left)
    if n == 0 or n != len(right):
        return None
    classes = sorted(set(left) | set(right))
    po = sum(a == b for a, b in zip(left, right)) / n
    pe = 0.0
    for name in classes:
        pe += (left.count(name) / n) * (right.count(name) / n)
    if pe == 1:
        return None
    return (po - pe) / (1 - pe)


def confusion(rows: list[dict], predicted: str) -> dict[str, dict[str, int]]:
    matrix = {gold: {pred: 0 for pred in CLASSES} for gold in CLASSES}
    for row in rows:
        gold = row.get("expected_verdict")
        pred = row.get(predicted)
        if gold in matrix and pred in matrix[gold]:
            matrix[gold][pred] += 1
    return matrix


def score(rows: list[dict], predicted: str) -> dict[str, Any]:
    """Scores against ``expected_verdict`` and against ``claim_true``."""

    usable = [row for row in rows if row.get(predicted) in CLASSES and row.get("expected_verdict") in CLASSES]
    tallies = _tallies(usable, predicted)
    rates = _rates(tallies)
    rates.update(
        {
            "n": len(usable),
            "confusion": confusion(usable, predicted),
            "kappa": kappa(
                [row["expected_verdict"] for row in usable],
                [row[predicted] for row in usable],
            ),
            "truth": _truth(usable, predicted),
        }
    )
    return rates


def _tallies(usable: list[dict], predicted: str) -> dict[str, Any]:
    groups = {name: [row for row in usable if row["expected_verdict"] == name] for name in CLASSES}
    decided = groups["PASS"] + groups["FAIL"]
    hit = sum(1 for row in groups["FAIL"] if row[predicted] == "FAIL")
    wrong = [row["scenario_id"] for row in usable if row[predicted] == "PASS" and row["expected_verdict"] != "PASS"]
    by_type: dict[str, dict[str, int]] = {}
    for row in groups["FAIL"]:
        bucket = by_type.setdefault(row.get("failure_type") or "", {"expected_fail": 0, "caught": 0})
        bucket["expected_fail"] += 1
        if row[predicted] == "FAIL":
            bucket["caught"] += 1
    return {
        "hit": hit,
        "n_fail": len(groups["FAIL"]),
        "n_pass": len(groups["PASS"]),
        "n_na": len(groups["NOT_ASSESSED"]),
        "n_decided": len(decided),
        "n_pred_fail": sum(1 for row in usable if row[predicted] == "FAIL"),
        "false_fail": sum(1 for row in groups["PASS"] if row[predicted] == "FAIL"),
        "na": sum(1 for row in usable if row[predicted] == "NOT_ASSESSED"),
        "na_when_gold_na": sum(1 for row in groups["NOT_ASSESSED"] if row[predicted] == "NOT_ASSESSED"),
        "over": sum(1 for row in decided if row[predicted] == "NOT_ASSESSED"),
        "covered": sum(1 for row in decided if row[predicted] != "NOT_ASSESSED"),
        "correct": sum(1 for row in usable if row[predicted] == row["expected_verdict"]),
        "wrong_pass": wrong,
        "n": len(usable),
        "not_pass": sum(1 for row in usable if row["expected_verdict"] != "PASS"),
        "by_failure_type": by_type,
    }


def _rates(counts: dict[str, Any]) -> dict[str, Any]:
    hit, n_fail, n_pass = counts["hit"], counts["n_fail"], counts["n_pass"]
    return {
        "detection": _rate(hit, n_fail),
        "detection_wilson": wilson(hit, n_fail),
        "false_fail": _rate(counts["false_fail"], n_pass),
        "false_fail_wilson": wilson(counts["false_fail"], n_pass),
        "fail_precision": _rate(hit, counts["n_pred_fail"]),
        "na_rate": _rate(counts["na"], counts["n"]),
        "na_rate_wilson": wilson(counts["na"], counts["n"]),
        "na_honesty": _rate(counts["na_when_gold_na"], counts["n_na"]),
        "over_abstention": _rate(counts["over"], counts["n_decided"]),
        "coverage": _rate(counts["covered"], counts["n_decided"]),
        "wrong_pass": len(counts["wrong_pass"]),
        "wrong_pass_ids": counts["wrong_pass"],
        "wrong_pass_wilson": wilson(len(counts["wrong_pass"]), counts["not_pass"]),
        "accuracy": _rate(counts["correct"], counts["n"]),
        "agreement": _rate(counts["correct"], counts["n"]),
        "by_failure_type": counts["by_failure_type"],
    }


def latency_stats(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"median": None, "p95": None}
    return {"median": statistics.median(values), "p95": percentile_95(values)}


def call_stats(rows: list[dict]) -> dict[str, Any]:
    counts = [len(row.get("api_ops") or []) for row in rows]
    by_op: dict[str, int] = {}
    for row in rows:
        for op in row.get("api_ops") or []:
            by_op[op] = by_op.get(op, 0) + 1
    if not counts:
        return {"median": None, "max": None, "total": 0, "by_operation": by_op}
    return {
        "median": statistics.median(counts),
        "max": max(counts),
        "total": sum(counts),
        "by_operation": by_op,
    }


def _truth(rows: list[dict], predicted: str) -> dict[str, Any]:
    labeled = [row for row in rows if isinstance(row.get("claim_true"), bool)]
    false_rows = [row for row in labeled if row["claim_true"] is False]
    true_rows = [row for row in labeled if row["claim_true"] is True]
    caught = sum(1 for row in false_rows if row[predicted] == "FAIL")
    false_fail = sum(1 for row in true_rows if row[predicted] == "FAIL")
    na = sum(1 for row in labeled if row[predicted] == "NOT_ASSESSED")
    wrong = [row["scenario_id"] for row in false_rows if row[predicted] == "PASS"]
    na_true = sum(1 for row in true_rows if row[predicted] == "NOT_ASSESSED")
    na_false = sum(1 for row in false_rows if row[predicted] == "NOT_ASSESSED")
    return {
        "n": len(labeled),
        "detection": _rate(caught, len(false_rows)),
        "detection_wilson": wilson(caught, len(false_rows)),
        "false_fail": _rate(false_fail, len(true_rows)),
        "false_fail_wilson": wilson(false_fail, len(true_rows)),
        "na_rate": _rate(na, len(labeled)),
        "na_rate_wilson": wilson(na, len(labeled)),
        "wrong_pass": len(wrong),
        "wrong_pass_ids": wrong,
        "abstention": {
            "all": _rate(na, len(labeled)),
            "true": _rate(na_true, len(true_rows)),
            "false": _rate(na_false, len(false_rows)),
        },
    }


def _rate(k: int, n: int) -> float | None:
    if n == 0:
        return None
    return k / n
