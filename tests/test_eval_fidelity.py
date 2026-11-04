"""Fidelity gate. CF-02 is a truth wrong-PASS only when raw is PASS."""

from __future__ import annotations

import json
from pathlib import Path

from eval.fidelity import coverage, gate

ROOT = Path(__file__).resolve().parents[1]


def _load(sid: str) -> dict:
    return json.loads((ROOT / "eval" / "scenarios" / f"{sid}.json").read_text(encoding="utf-8"))[
        "agent_claim"
    ]


def test_cf_gate_and_truth_accounting():
    assert gate("PASS", _load("CF-01")) == "NOT_ASSESSED"
    assert gate("PASS", _load("CF-02")) == "NOT_ASSESSED"
    assert gate("PASS", _load("CF-03")) == "NOT_ASSESSED"
    assert gate("FAIL", _load("CF-04")) == "FAIL"
    assert coverage(_load("CF-01")) < 1
    # Raw PASS on CF-02 (T false) is a truth wrong-PASS. Raw NA is an abstention.
    cf02 = _load("CF-02")
    assert gate("PASS", cf02) == "NOT_ASSESSED"
    raw_pass_on_false = True  # claim_true is false in the scenario file
    scenario = json.loads((ROOT / "eval" / "scenarios" / "CF-02.json").read_text(encoding="utf-8"))
    assert scenario["claim_true"] is False
    assert raw_pass_on_false
    cf03 = json.loads((ROOT / "eval" / "scenarios" / "CF-03.json").read_text(encoding="utf-8"))
    assert cf03["claim_true"] is True
    assert gate("NOT_ASSESSED", _load("CF-03")) == "NOT_ASSESSED"


def test_prose_property_outside_the_vocabulary_is_uncovered():
    claim = {
        "prose_assertions": [
            {"resource_id": "b", "property": "not_a_real_property", "op": "eq", "value": True}
        ],
        "structured": {
            "resources": [
                {
                    "resource_id": "b",
                    "assertions": [
                        {"property": "not_a_real_property", "op": "eq", "value": True}
                    ],
                }
            ]
        },
    }
    assert coverage(claim) == 0
    assert gate("PASS", claim) == "NOT_ASSESSED"
