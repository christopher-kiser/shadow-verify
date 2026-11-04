"""Hand-built matrices: zero denominators, Wilson, kappa, and p95."""

from __future__ import annotations

import math

from eval.metrics import kappa, percentile_95, score, wilson


def _row(sid, gold, pred, truth=True, failure="truthful_success"):
    return {
        "scenario_id": sid,
        "expected_verdict": gold,
        "raw_verdict": pred,
        "claim_true": truth,
        "failure_type": failure,
    }


def test_zero_denominator_is_null():
    result = score([], "raw_verdict")
    assert result["detection"] is None
    assert result["false_fail"] is None
    assert result["na_rate"] is None
    assert wilson(0, 0) is None


def test_wilson_endpoints():
    for n in (10, 54):
        low = wilson(0, n)
        mid = wilson(n // 2, n)
        high = wilson(n, n)
        assert low["low"] == 0
        assert high["high"] == 1
        assert 0 <= mid["low"] < mid["point"] < mid["high"] <= 1
    # n=10, p=0. The closed form is symmetric around the zero and one cases.
    zero = wilson(0, 10)
    one = wilson(10, 10)
    assert zero["high"] == one["low"] or abs(zero["high"] - (1 - one["low"])) < 1e-9
    assert abs(wilson(5, 10)["point"] - 0.5) < 1e-12


def test_kappa_including_perfect_agreement_on_one_class():
    labels = ["PASS"] * 4
    assert kappa(labels, labels) is None
    mixed_left = ["PASS", "FAIL", "PASS", "FAIL"]
    mixed_right = ["PASS", "FAIL", "FAIL", "PASS"]
    value = kappa(mixed_left, mixed_right)
    assert value is not None
    assert value < 1


def test_p95_nearest_rank():
    assert percentile_95([3]) == 3
    values_20 = list(range(20))
    assert percentile_95(values_20) == values_20[math.ceil(0.95 * 20) - 1]
    values_54 = list(range(54))
    assert percentile_95(values_54) == values_54[math.ceil(0.95 * 54) - 1]


def test_score_counts_a_small_matrix():
    rows = [
        _row("a", "FAIL", "FAIL", False, "silent_partial_apply"),
        _row("b", "PASS", "PASS", True),
        _row("c", "NOT_ASSESSED", "NOT_ASSESSED", True),
    ]
    result = score(rows, "raw_verdict")
    assert result["detection"] == 1
    assert result["wrong_pass"] == 0
    assert result["confusion"]["FAIL"]["FAIL"] == 1
    assert result["truth"]["wrong_pass"] == 0
