"""Exit gate, manifest refusal, and the unexercised held-out path."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from eval.run import main
from eval.scoring import gate_exit

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_mismatch_exits_2_before_seed(tmp_path, monkeypatch):
    shutil.copytree(ROOT / "eval", tmp_path / "eval")
    target = tmp_path / "eval" / "scenarios" / "S3-01.json"
    target.write_bytes(target.read_bytes() + b" ")
    seeded = []
    monkeypatch.setattr("eval.run.apply", lambda *a, **k: seeded.append(True))
    code = main(["--all", "--root", str(tmp_path), "--out", str(tmp_path / "out")])
    assert code == 2
    assert seeded == []
    target.write_bytes(target.read_bytes()[:-1])
    extra = tmp_path / "eval" / "scenarios" / "EXTRA.json"
    extra.write_text("{}\n", encoding="utf-8")
    assert main(["--all", "--root", str(tmp_path), "--out", str(tmp_path / "out2")]) == 2
    extra.unlink()
    (tmp_path / "eval" / "scenarios" / "S3-02.json").unlink()
    assert main(["--all", "--root", str(tmp_path), "--out", str(tmp_path / "out3")]) == 2
    assert seeded == []


def test_heldout_verifies_the_pin_and_does_not_run(tmp_path, monkeypatch):
    seeded = []
    monkeypatch.setattr("eval.run.apply", lambda *a, **k: seeded.append(True))
    assert main(["--heldout", "--root", str(ROOT), "--out", str(tmp_path)]) == 0
    assert seeded == []
    shutil.copytree(ROOT / "eval", tmp_path / "eval")
    pin = tmp_path / "eval" / "heldout.manifest.json"
    data = json.loads(pin.read_text(encoding="utf-8"))
    data["set_sha256"] = "231a58c6" + ("0" * 51) + "70aa0"
    data["files"] = {"eval/heldout/H-01.json": "ab"}
    pin.write_text(json.dumps(data) + "\n", encoding="utf-8")
    assert main(["--heldout", "--root", str(tmp_path), "--out", str(tmp_path / "o")]) == 2
    assert seeded == []


def test_exit_gate_rejects_fake_passes_and_missing_labels():
    def row(sid, raw, expected="FAIL", raw_expected="FAIL", truth=False, stretch=False):
        return {
            "scenario_id": sid,
            "baseline": "shadow_verify",
            "set": "stretch" if stretch else "core",
            "raw_verdict": raw,
            "gated_verdict": raw,
            "expected_verdict": expected,
            "expected_raw_verdict": raw_expected,
            "claim_true": truth,
            "error": None,
        }

    gaps = {"CF-02"}
    common = {"read_only_ok": True, "determinism_ok": True, "determinism_checked": False}
    code, _ = gate_exit([row("CF-04", "PASS")], gaps, **common)
    assert code == 1
    code, _ = gate_exit([row("S3-06", "PASS")], gaps, **common)
    assert code == 1
    code, _ = gate_exit([row("L-02", "PASS", stretch=True)], gaps, **common)
    assert code == 1
    missing = row("HB-01", "PASS")
    del missing["expected_raw_verdict"]
    code, _ = gate_exit([missing], gaps, read_only_ok=True, determinism_ok=None, determinism_checked=False)
    assert code == 2
    known = json.loads((ROOT / "eval" / "labels" / "known_gaps.json").read_text(encoding="utf-8"))
    for sid in known:
        scenario = json.loads((ROOT / "eval" / "scenarios" / f"{sid}.json").read_text(encoding="utf-8"))
        assert scenario["expected_raw_verdict"] == "PASS"
        assert scenario["claim_true"] is False
