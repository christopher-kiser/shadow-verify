"""A flipped payload byte fails v0 verify."""

from __future__ import annotations

import json
from pathlib import Path

from eval.adapter import verify_evidence
from eval.run import main

ROOT = Path(__file__).resolve().parents[1]


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
