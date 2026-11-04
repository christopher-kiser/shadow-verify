"""The report reads result files and still exits 0 without matplotlib."""

from __future__ import annotations

import builtins
import json
from pathlib import Path

from eval.report import main


def test_report_lists_coverage_gaps_and_skips_the_plot(tmp_path, monkeypatch, capsys):
    row = {
        "scenario_id": "S3-02",
        "set": "core",
        "mode": "MOCKED",
        "baseline": "shadow_verify",
        "condition": "none",
        "failure_type": "truthful_success",
        "expected_verdict": "PASS",
        "expected_raw_verdict": "PASS",
        "claim_true": True,
        "raw_verdict": "NOT_ASSESSED",
        "gated_verdict": "NOT_ASSESSED",
        "coverage": 1,
        "reasons": ["unsupported_property"],
        "checked_account": [{"resource_id": "b", "checked_account": "NOT_ASSESSED"}],
        "evidence_sha256": None,
        "api_calls": 0,
        "api_ops": [],
        "latency_ms": 0,
        "resource_type": "s3_bucket",
        "unchecked": ["encryption.sse_algorithm"],
        "error": None,
    }
    correct = dict(row)
    correct.update(
        {
            "scenario_id": "S3-11",
            "expected_verdict": "NOT_ASSESSED",
            "expected_raw_verdict": "NOT_ASSESSED",
            "reasons": ["GetPublicAccessBlock failed: AccessDenied: denied"],
            "unchecked": [],
            "failure_type": "unverifiable",
        }
    )
    (tmp_path / "results.jsonl").write_text(
        json.dumps(row) + "\n" + json.dumps(correct) + "\n",
        encoding="utf-8",
    )
    summary = {
        "mode": "MOCKED",
        "versions": {"moto": "5.2.5"},
        "tool_commit": "abc",
        "freeze_tag": "eval-freeze-v1",
        "freeze_commit": "df422f3",
        "set_sha256": "abc",
        "heldout_pin_sha256": "def",
        "metrics_raw": {
            "confusion": {
                "PASS": {"PASS": 0, "FAIL": 0, "NOT_ASSESSED": 1},
                "FAIL": {"PASS": 0, "FAIL": 0, "NOT_ASSESSED": 0},
                "NOT_ASSESSED": {"PASS": 0, "FAIL": 0, "NOT_ASSESSED": 1},
            },
            "detection": None,
            "detection_wilson": None,
            "false_fail": None,
            "false_fail_wilson": None,
            "na_rate": 1,
            "na_rate_wilson": None,
            "wrong_pass": 0,
            "wrong_pass_ids": [],
            "agreement": 0.5,
            "kappa": None,
            "truth": {"wrong_pass": 0, "wrong_pass_ids": []},
        },
        "metrics_gated": None,
        "baselines": {},
    }
    (tmp_path / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "matplotlib" or name.startswith("matplotlib."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    assert main(["--out", str(tmp_path)]) == 0
    text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "MOCKED" in text
    assert "author-designed scenarios, not real agent traces" in text
    assert "S3-02" in text
    assert "miss" in text
    assert "S3-11" in text
    assert "SV + eval fidelity gate (not the product)" in text
    assert "plot skipped" in capsys.readouterr().out
