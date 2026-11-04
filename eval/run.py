"""Offline runner. MOCKED. A manifest mismatch exits 2 before any seed."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import boto3
from moto import mock_aws

from eval.adapter import load_allowlist, run_verify
from eval.baselines import always_not_assessed, naive_exists, self_report
from eval.faults import FaultPlan
from eval.fidelity import coverage, gate
from eval.guard import GuardViolation, audit_only, protect
from eval.manifest import HELD_OUT_PIN, check, heldout_problems, repo_root, set_sha256
from eval.metrics import call_stats, latency_stats, score
from eval.placeholders import substitute
from eval.schema import validate_scenario
from eval.scoring import gate_exit, headlines
from eval.seed import apply, install_fake_env, seed_random

FIXED = datetime(2026, 1, 1, tzinfo=timezone.utc)
HMAC_KEY = b"shadow-verify-eval-v1"
BASELINES = ("self_report", "naive_exists", "always_not_assessed", "shadow_verify")


def clock() -> datetime:
    return FIXED


def _sleep(_seconds: float) -> None:
    return None


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else repo_root()
    if args.live:
        print("LIVE is not run by this harness. See eval/live/SETUP.md", file=sys.stderr)
        return 2
    if not args.all and not args.scenario and not args.heldout:
        print("pass --all, --scenario, or --heldout", file=sys.stderr)
        return 2
    problems = check(root)
    if problems:
        for item in problems:
            print(item, file=sys.stderr)
        return 2
    if args.heldout:
        held = heldout_problems(root)
        if held:
            for item in held:
                print(item, file=sys.stderr)
            return 2
        if not args.all and not args.scenario:
            print("held-out pin ok; cases were not run")
            return 0
    scenarios, unknown = _select(root, args.scenario, args.include_stretch)
    if unknown:
        print(unknown, file=sys.stderr)
        return 2
    schema_problems = []
    for scenario, path in scenarios:
        schema_problems.extend(validate_scenario(scenario, filename=path.name))
    if schema_problems:
        for item in schema_problems:
            print(item, file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else root / "eval" / "results" / "mocked"
    install_fake_env(str(out / "no-aws"))
    commit = _git(root, "rev-parse", "HEAD") or "unknown"
    os_commit(commit)
    rows, meta = _execute(root, scenarios, out / "evidence", args.check_determinism)
    summary = _summary(root, rows, meta, commit, bool(args.include_stretch))
    _write(out, rows, summary)
    code, why = gate_exit(
        rows,
        _known_gaps(root),
        read_only_ok=meta["read_only_ok"],
        determinism_ok=meta["determinism_ok"],
        determinism_checked=bool(args.check_determinism),
    )
    for item in why:
        print(item, file=sys.stderr)
    print(f"MOCKED wrote {out}")
    return code


def _execute(root, scenarios, evidence_root: Path, determinism: bool):
    allow, denied = load_allowlist(root / "docs" / "iam-policy.json")
    rows: list[dict] = []
    determinism_ok = True
    read_only_ok = True
    tamper = {"PASS": None, "FAIL": None, "NOT_ASSESSED": None}
    for scenario, _path in scenarios:
        try:
            produced, ok = _one(scenario, evidence_root / scenario["id"], allow, denied, determinism)
            rows.extend(produced)
            if determinism and not ok:
                determinism_ok = False
            _note_tamper(produced, evidence_root / scenario["id"], tamper)
        except GuardViolation as exc:
            read_only_ok = False
            rows.extend(_errors(scenario, f"guard: {exc}"))
        except Exception as exc:
            rows.extend(_errors(scenario, f"{type(exc).__name__}: {exc}"))
    return rows, {
        "read_only_ok": read_only_ok,
        "determinism_ok": determinism_ok if determinism else None,
        "tamper_detected": tamper,
    }


def _one(scenario, evidence_dir: Path, allow, denied, determinism: bool):
    rows = _pass(scenario, evidence_dir, allow, denied)
    if not determinism:
        return rows, True
    again = _pass(scenario, evidence_dir / "again", allow, denied)
    left = _sv(rows)
    right = _sv(again)
    ok = (
        left.get("raw_verdict") == right.get("raw_verdict")
        and left.get("evidence_sha256") == right.get("evidence_sha256")
    )
    return rows, ok


def _pass(scenario, evidence_dir: Path, allow, denied) -> list[dict]:
    with mock_aws():
        seed_random()
        session = boto3.Session(region_name="us-east-1")
        saved = apply(session, scenario)
        apply(session, scenario, post=True, saved=saved)
        resources = substitute(scenario["agent_claim"]["structured"]["resources"], saved)
        prose = scenario["agent_claim"]["prose_assertions"]
        if prose != "same":
            prose = substitute(prose, saved)
        fidelity_claim = {"prose_assertions": prose, "structured": {"resources": resources}}
        ratio = coverage(fidelity_claim)
        claim = {"id": scenario["id"], "text": scenario["agent_claim"]["text"], "resources": resources}
        rows = [
            _row(scenario, "self_report", self_report(resources), ratio, None),
            _row(scenario, "always_not_assessed", always_not_assessed(resources), ratio, None),
        ]
        with audit_only():
            started = time.perf_counter()
            naive = naive_exists(session, resources)
            naive_ms = (time.perf_counter() - started) * 1000
        rows.insert(1, _row(scenario, "naive_exists", naive, ratio, naive_ms))
        faults = FaultPlan(scenario["seed"]["fault"], scenario["seed"]["page_size"])
        with protect(session, faults, allow, denied) as state:
            started = time.perf_counter()
            outcome = run_verify(claim, session, clock, _sleep, HMAC_KEY, evidence_dir)
            sv_ms = (time.perf_counter() - started) * 1000
            ops = list(state.ops)
        outcome["api_ops"] = ops or outcome["api_ops"]
        outcome["gated_verdict"] = gate(outcome["verdict"], fidelity_claim)
        outcome["verdict_latency_ms"] = sv_ms
        rows.append(_sv_row(scenario, outcome, ratio))
        return rows


def _row(scenario, baseline, outcome, ratio, latency) -> dict:
    ops = list(outcome.get("api_ops") or [])
    verdict = outcome["verdict"]
    return _base(scenario, baseline, verdict, verdict, outcome.get("reasons") or [], ops, latency, ratio)


def _sv_row(scenario, outcome, ratio) -> dict:
    ops = list(outcome.get("api_ops") or [])
    row = _base(
        scenario,
        "shadow_verify",
        outcome["verdict"],
        outcome["gated_verdict"],
        outcome.get("reasons") or [],
        ops,
        outcome.get("verdict_latency_ms"),
        ratio,
    )
    row["checked_account"] = outcome.get("checked_account")
    row["evidence_sha256"] = outcome.get("evidence_sha256")
    row["unchecked"] = outcome.get("unchecked") or []
    return row


def _base(scenario, baseline, raw, gated, reasons, ops, latency, ratio) -> dict:
    return {
        "scenario_id": scenario["id"],
        "set": "stretch" if scenario.get("stretch") else "core",
        "mode": "MOCKED",
        "baseline": baseline,
        "condition": scenario.get("condition"),
        "failure_type": scenario.get("failure_type"),
        "expected_verdict": scenario.get("expected_verdict"),
        "expected_raw_verdict": scenario.get("expected_raw_verdict"),
        "claim_true": scenario.get("claim_true"),
        "raw_verdict": raw,
        "gated_verdict": gated,
        "coverage": ratio,
        "reasons": reasons,
        "checked_account": None,
        "evidence_sha256": None,
        "api_calls": len(ops),
        "api_ops": ops,
        "latency_ms": latency,
        "resource_type": scenario.get("resource_type"),
        "unchecked": [],
        "error": None,
    }


def _errors(scenario, message: str) -> list[dict]:
    rows = []
    for baseline in BASELINES:
        row = _base(scenario, baseline, "ERROR", "ERROR", [], [], None, None)
        row["error"] = message
        rows.append(row)
    return rows


def _sv(rows: list[dict]) -> dict:
    for row in rows:
        if row["baseline"] == "shadow_verify":
            return row
    return {}


def _note_tamper(rows, evidence_dir: Path, tamper: dict) -> None:
    from eval.adapter import verify_evidence

    row = _sv(rows)
    verdict = row.get("raw_verdict")
    path = evidence_dir / f"{row.get('scenario_id')}.json"
    if verdict not in tamper or tamper[verdict] is not None or not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    marker = '"bundle_sha256": "'
    idx = text.find(marker)
    if idx == -1:
        return
    pos = idx + len(marker)
    flipped_char = "0" if text[pos] != "0" else "1"
    flipped = text[:pos] + flipped_char + text[pos + 1 :]
    dest = path.with_name(path.stem + ".tamper.json")
    dest.write_text(flipped, encoding="utf-8", newline="\n")
    tamper[verdict] = bool(verify_evidence(dest))
    dest.unlink()


def _select(root: Path, ids: list[str] | None, include_stretch: bool):
    chosen = []
    named = set(ids or [])
    for path in sorted((root / "eval" / "scenarios").glob("*.json")):
        scenario = json.loads(path.read_text(encoding="utf-8"))
        if named and scenario["id"] not in named:
            continue
        if scenario.get("stretch") and not include_stretch and not named:
            continue
        chosen.append((scenario, path))
    if named and len(chosen) != len(named):
        found = {item[0]["id"] for item in chosen}
        missing = ", ".join(sorted(named - found))
        return [], f"unknown scenario: {missing}"
    return chosen, ""


def _summary(root, rows, meta, commit: str, stretch: bool) -> dict:
    def sv(set_name):
        return [
            row
            for row in rows
            if row["baseline"] == "shadow_verify" and row["set"] == set_name and row["raw_verdict"] != "ERROR"
        ]

    core = sv("core")
    extra = sv("stretch")
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
        "freeze_commit": _git(root, "rev-parse", "eval-freeze-v1^{}"),
        "set_sha256": set_sha256(root),
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
            name: score(
                [row for row in rows if row["baseline"] == name and row["set"] == "core" and row["raw_verdict"] != "ERROR"],
                "raw_verdict",
            )
            for name in BASELINES
        },
        "latency_ms": latency_stats([row["latency_ms"] for row in core if isinstance(row.get("latency_ms"), (int, float))]),
        "calls": call_stats(core),
        "determinism_ok": meta["determinism_ok"],
        "tamper_detected": meta["tamper_detected"],
        "read_only_ok": meta["read_only_ok"],
        "note": "author-designed scenarios, not real agent traces",
    }


def _counts(rows: list[dict]) -> dict:
    out = {name: 0 for name in ("PASS", "FAIL", "NOT_ASSESSED")}
    truth = {"true": 0, "false": 0, "null": 0}
    for row in rows:
        if row.get("raw_verdict") in out:
            out[row["raw_verdict"]] += 1
        value = row.get("claim_true")
        if value is True:
            truth["true"] += 1
        elif value is False:
            truth["false"] += 1
        else:
            truth["null"] += 1
    out["truth"] = truth
    return out


def _write(out: Path, rows: list[dict], summary: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows]
    (out / "results.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", newline="\n")
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _known_gaps(root: Path) -> set[str]:
    data = json.loads((root / "eval" / "labels" / "known_gaps.json").read_text(encoding="utf-8"))
    return set(data)


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def os_commit(commit: str) -> None:
    import os

    os.environ["SV_TOOL_COMMIT"] = commit


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MOCKED Shadow Verify eval. No network and no live AWS.")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--scenario", action="append", default=None)
    parser.add_argument("--include-stretch", action="store_true")
    parser.add_argument("--heldout", action="store_true")
    parser.add_argument("--check-determinism", action="store_true")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--out", default=None)
    parser.add_argument("--root", default=None)
    return parser


if __name__ == "__main__":
    sys.exit(main())
