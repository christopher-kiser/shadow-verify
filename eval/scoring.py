"""Exit gate, coverage gaps, and the summary document. Expectations are not edited."""

from __future__ import annotations

import hashlib
import platform
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

from eval.manifest import HELD_OUT_PIN
from eval.metrics import call_stats, latency_stats, score

VERDICTS = {"PASS", "FAIL", "NOT_ASSESSED"}
_BASELINES = ("self_report", "naive_exists", "always_not_assessed", "shadow_verify")


def is_coverage_na(row: dict) -> bool:
    if row.get("baseline") != "shadow_verify":
        return False
    if row.get("raw_verdict") != "NOT_ASSESSED":
        return False
    return any(_is_gap_reason(reason) for reason in row.get("reasons") or [])


def is_coverage_wrong(row: dict) -> bool:
    """Abstaining because v0 cannot read the claim, when the label is PASS or FAIL."""

    return is_coverage_na(row) and row.get("expected_verdict") in {"PASS", "FAIL"}


def is_correct_na(row: dict) -> bool:
    return (
        row.get("baseline") == "shadow_verify"
        and row.get("raw_verdict") == "NOT_ASSESSED"
        and row.get("expected_verdict") == "NOT_ASSESSED"
        and not is_coverage_na(row)
        and not row.get("error")
    )


def gate_exit(
    rows: list[dict],
    known_gaps: set[str],
    *,
    read_only_ok: bool,
    determinism_ok: bool | None,
    determinism_checked: bool,
) -> tuple[int, list[str]]:
    sv = [row for row in rows if row.get("baseline") == "shadow_verify"]
    for row in sv:
        if row.get("expected_verdict") not in VERDICTS:
            return 2, [f"{row.get('scenario_id')}: missing expected_verdict"]
        if row.get("expected_raw_verdict") not in VERDICTS:
            return 2, [f"{row.get('scenario_id')}: missing expected_raw_verdict"]
        if "claim_true" not in row:
            return 2, [f"{row.get('scenario_id')}: missing claim_true"]
    problems: list[str] = []
    if any(row.get("error") for row in sv):
        problems.append("case error")
    if not read_only_ok:
        problems.append("read_only")
    if determinism_checked and not determinism_ok:
        problems.append("determinism")
    for row in sv:
        sid = row["scenario_id"]
        if row.get("gated_verdict") == "PASS" and row.get("expected_verdict") != "PASS":
            problems.append(f"gated wrong-PASS {sid}")
        if row.get("raw_verdict") == "PASS" and row.get("expected_raw_verdict") != "PASS":
            problems.append(f"raw PASS where expected_raw is not PASS {sid}")
        if (
            row.get("raw_verdict") == "PASS"
            and row.get("claim_true") is False
            and sid not in known_gaps
        ):
            problems.append(f"truth wrong-PASS {sid}")
    if problems:
        return 1, problems
    return 0, []


def headlines(rows: list[dict]) -> dict:
    sv = [row for row in rows if row.get("baseline") == "shadow_verify" and not row.get("error")]
    truth_wrong = [
        row["scenario_id"]
        for row in sv
        if row.get("raw_verdict") == "PASS" and row.get("claim_true") is False
    ]
    underspecified = [
        row["scenario_id"]
        for row in sv
        if row.get("condition") == "underspecified_claim" and row.get("raw_verdict") == "PASS"
    ]
    raw_mismatch = [
        row["scenario_id"]
        for row in sv
        if row.get("raw_verdict") != row.get("expected_raw_verdict")
    ]
    owner_unchecked = [
        row["scenario_id"]
        for row in sv
        if row.get("raw_verdict") == "PASS"
        and row.get("resource_type") == "s3_bucket"
        and _s3_owner_unchecked(row)
    ]
    gaps = [row["scenario_id"] for row in sv if is_coverage_na(row)]
    gap_wrong = [row["scenario_id"] for row in sv if is_coverage_wrong(row)]
    correct = [row["scenario_id"] for row in sv if is_correct_na(row)]
    return {
        "raw_wrong_pass_vs_truth": truth_wrong,
        "raw_pass_on_underspecified": underspecified,
        "raw_vs_expected_raw_mismatches": raw_mismatch,
        "s3_pass_owner_unchecked": owner_unchecked,
        "coverage_na": gaps,
        "coverage_na_wrong": gap_wrong,
        "correct_na": correct,
    }


def build_summary(root: Path, rows: list[dict], meta: dict, commit: str, stretch: bool, freeze_commit: str, set_digest: str) -> dict:
    core = _sv(rows, "core")
    extra = _sv(rows, "stretch")
    versions = {}
    for name in ("boto3", "botocore", "moto", "rfc8785"):
        try:
            versions[name] = version(name)
        except Exception:
            versions[name] = "unknown"
    lock = root / "requirements-ci.txt"
    lock_hash = hashlib.sha256(lock.read_bytes()).hexdigest() if lock.is_file() else None
    return {
        "mode": "MOCKED",
        "label": "MOCKED",
        "set": "core+stretch" if stretch else "core",
        "run_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": commit,
        "tool_commit": commit,
        "freeze_tag": "eval-freeze-v1",
        "freeze_commit": freeze_commit,
        "set_sha256": set_digest,
        "heldout_pin_sha256": HELD_OUT_PIN,
        "heldout_ran": False,
        "aws_default_emulation": True,
        "scenario_author": "Christopher",
        "scenario_date": "2026-11-03",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "versions": versions,
        "lock_sha256": lock_hash,
        "n": _counts(core),
        "stretch_n": _counts(extra),
        "headlines": headlines(core),
        "stretch_headlines": headlines(extra),
        "metrics_raw": score(core, "raw_verdict"),
        "metrics_gated": score(core, "gated_verdict"),
        "stretch_metrics_raw": score(extra, "raw_verdict"),
        "baselines": {
            name: score(_baseline(rows, name), "raw_verdict") for name in _BASELINES
        },
        "latency_ms": latency_stats(
            [row["latency_ms"] for row in core if isinstance(row.get("latency_ms"), (int, float))]
        ),
        "calls": call_stats(core),
        "determinism_ok": meta["determinism_ok"],
        "tamper_detected": meta["tamper_detected"],
        "read_only_ok": meta["read_only_ok"],
        "note": "author-designed scenarios, not real agent traces",
    }


def _sv(rows: list[dict], set_name: str) -> list[dict]:
    return [
        row
        for row in rows
        if row["baseline"] == "shadow_verify" and row["set"] == set_name and row["raw_verdict"] != "ERROR"
    ]


def _baseline(rows: list[dict], name: str) -> list[dict]:
    return [
        row
        for row in rows
        if row["baseline"] == name and row["set"] == "core" and row["raw_verdict"] != "ERROR"
    ]


def _counts(rows: list[dict]) -> dict:
    out = {name: 0 for name in ("PASS", "FAIL", "NOT_ASSESSED")}
    truth = {"true": 0, "false": 0, "null": 0}
    for row in rows:
        if row.get("raw_verdict") in out:
            out[row["raw_verdict"]] += 1
        value = row.get("claim_true")
        truth["true" if value is True else "false" if value is False else "null"] += 1
    out["truth"] = truth
    return out


def _s3_owner_unchecked(row: dict) -> bool:
    accounts = row.get("checked_account") or []
    if not accounts:
        return True
    return all(item.get("checked_account") == "NOT_ASSESSED" for item in accounts)


def _is_gap_reason(reason: str) -> bool:
    text = str(reason)
    return text == "unsupported_property" or text == "unsupported_resource" or text.startswith(
        "unsupported_property "
    ) or text.startswith("unsupported_resource ")
