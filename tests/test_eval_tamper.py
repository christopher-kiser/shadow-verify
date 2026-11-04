"""A flipped payload byte fails v0 verify. The S3-01 hash is stable."""

from __future__ import annotations

import json
import os
from pathlib import Path

from eval.adapter import load_allowlist, verify_evidence
from eval.run import FIXED, _pass, clock, main
from eval.seed import install_fake_env

ROOT = Path(__file__).resolve().parents[1]
S3_GOLDEN = "e9d1c3ad64baa521ff1323f0cf0e70316d52c138f0a142d53f80991f8df53bed"


def test_tamper_is_detected_for_each_verdict(tmp_path):
    code = main(
        [
            "--scenario",
            "S3-01",
            "--scenario",
            "SG-09",
            "--scenario",
            "S3-11",
            "--out",
            str(tmp_path),
            "--root",
            str(ROOT),
        ]
    )
    assert code == 0
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["tamper_detected"] == {"PASS": True, "FAIL": True, "NOT_ASSESSED": True}
    bundle = tmp_path / "evidence" / "S3-01" / "S3-01.json"
    assert verify_evidence(bundle) == []
    text = bundle.read_text(encoding="utf-8")
    marker = '"bundle_sha256": "'
    pos = text.find(marker) + len(marker)
    flipped = bundle.with_name("flipped.json")
    flipped.write_text(text[:pos] + ("0" if text[pos] != "0" else "1") + text[pos + 1 :], encoding="utf-8")
    assert verify_evidence(flipped)


def test_determinism_and_golden_hash(tmp_path):
    os.environ["SV_TOOL_COMMIT"] = "eval-golden"
    install_fake_env(str(tmp_path))
    scenario = json.loads((ROOT / "eval" / "scenarios" / "S3-01.json").read_text(encoding="utf-8"))
    allow, denied = load_allowlist(ROOT / "docs" / "iam-policy.json")
    first = _pass(scenario, tmp_path / "a", allow, denied)
    second = _pass(scenario, tmp_path / "b", allow, denied)
    left = next(row for row in first if row["baseline"] == "shadow_verify")
    right = next(row for row in second if row["baseline"] == "shadow_verify")
    assert left["evidence_sha256"] == right["evidence_sha256"] == S3_GOLDEN
    assert left["raw_verdict"] == "PASS"
    assert clock() == FIXED
