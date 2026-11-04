"""One JSONL row. The eight row fields travel together."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RowParts:
    scenario: dict
    baseline: str
    raw: str
    gated: str
    reasons: list[str]
    ops: list[str]
    latency: float | None
    coverage: float | None


def row_dict(parts: RowParts) -> dict:
    scenario = parts.scenario
    return {
        "scenario_id": scenario["id"],
        "set": "stretch" if scenario.get("stretch") else "core",
        "mode": "MOCKED",
        "baseline": parts.baseline,
        "condition": scenario.get("condition"),
        "failure_type": scenario.get("failure_type"),
        "expected_verdict": scenario.get("expected_verdict"),
        "expected_raw_verdict": scenario.get("expected_raw_verdict"),
        "claim_true": scenario.get("claim_true"),
        "raw_verdict": parts.raw,
        "gated_verdict": parts.gated,
        "coverage": parts.coverage,
        "reasons": parts.reasons,
        "checked_account": None,
        "evidence_sha256": None,
        "api_calls": len(parts.ops),
        "api_ops": parts.ops,
        "latency_ms": parts.latency,
        "resource_type": scenario.get("resource_type"),
        "unchecked": [],
        "error": None,
    }


def error_rows(scenario: dict, message: str, baselines: tuple[str, ...]) -> list[dict]:
    rows = []
    for baseline in baselines:
        row = row_dict(
            RowParts(scenario, baseline, "ERROR", "ERROR", [], [], None, None)
        )
        row["error"] = message
        rows.append(row)
    return rows
