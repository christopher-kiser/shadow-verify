"""Offline runner. MOCKED. A manifest mismatch exits 2 before any seed."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
from moto import mock_aws

from eval.adapter import load_allowlist, run_verify, verify_evidence
from eval.baselines import always_not_assessed, naive_exists, self_report
from eval.faults import FaultPlan
from eval.fidelity import coverage, gate
from eval.guard import GuardViolation, audit_only, protect
from eval.manifest import check, repo_root, set_sha256
from eval.placeholders import substitute
from eval.rows import RowParts, error_rows, row_dict
from eval.schema import validate_scenario
from eval.scoring import build_summary, gate_exit
from eval.seed import apply, install_fake_env, seed_random

FIXED = datetime(2026, 1, 1, tzinfo=timezone.utc)
HMAC_KEY = b"shadow-verify-eval-v1"
BASELINES = ("self_report", "naive_exists", "always_not_assessed", "shadow_verify")


def clock() -> datetime:
    return FIXED


def _sleep(_seconds: float) -> None:
    return None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(args.root).resolve() if args.root else repo_root()
    refused = _refuse(args, root)
    if refused is not None:
        return refused
    scenarios, unknown = _select(root, args.scenario, args.include_stretch)
    schema_errors = _schema(scenarios)
    if unknown or schema_errors:
        print(unknown or schema_errors, file=sys.stderr)
        return 2
    return _finish(args, root, scenarios)


def _refuse(args, root: Path) -> int | None:
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
    if args.heldout and not args.all and not args.scenario:
        print("held-out pin ok; cases were not run")
        return 0
    return None


def _schema(scenarios) -> str:
    problems = []
    for scenario, path in scenarios:
        problems.extend(validate_scenario(scenario, filename=path.name))
    return "\n".join(problems)


def _finish(args, root: Path, scenarios) -> int:
    out = Path(args.out) if args.out else root / "eval" / "results" / "mocked"
    install_fake_env(str(out / "no-aws"))
    commit = _git(root, "rev-parse", "HEAD") or "unknown"
    _remember_commit(commit)
    rows, meta = _execute(root, scenarios, out / "evidence", args.check_determinism)
    summary = build_summary(
        root,
        rows,
        meta,
        commit,
        bool(args.include_stretch),
        _git(root, "rev-parse", "eval-freeze-v1^{}"),
        set_sha256(root),
    )
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
            determinism_ok = determinism_ok and ok
            _note_tamper(produced, evidence_root / scenario["id"], tamper)
        except GuardViolation as exc:
            read_only_ok = False
            rows.extend(error_rows(scenario, f"guard: {exc}", BASELINES))
        except Exception as exc:
            rows.extend(error_rows(scenario, f"{type(exc).__name__}: {exc}", BASELINES))
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
    left, right = _sv(rows), _sv(again)
    ok = left.get("raw_verdict") == right.get("raw_verdict") and left.get("evidence_sha256") == right.get(
        "evidence_sha256"
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
        rows = [_plain(scenario, "self_report", self_report(resources), ratio, None)]
        with audit_only():
            started = time.perf_counter()
            naive = naive_exists(session, resources)
            naive_ms = (time.perf_counter() - started) * 1000
        rows.append(_plain(scenario, "naive_exists", naive, ratio, naive_ms))
        rows.append(_plain(scenario, "always_not_assessed", always_not_assessed(resources), ratio, None))
        faults = FaultPlan(scenario["seed"]["fault"], scenario["seed"]["page_size"])
        with protect(session, faults, allow, denied) as state:
            started = time.perf_counter()
            outcome = run_verify(claim, session, clock, _sleep, HMAC_KEY, evidence_dir)
            outcome["verdict_latency_ms"] = (time.perf_counter() - started) * 1000
            outcome["api_ops"] = list(state.ops) or outcome["api_ops"]
        outcome["gated_verdict"] = gate(outcome["verdict"], fidelity_claim)
        rows.append(_sv_row(scenario, outcome, ratio))
        return rows


def _plain(scenario, baseline, outcome, ratio, latency) -> dict:
    ops = list(outcome.get("api_ops") or [])
    verdict = outcome["verdict"]
    return row_dict(RowParts(scenario, baseline, verdict, verdict, outcome.get("reasons") or [], ops, latency, ratio))


def _sv_row(scenario, outcome, ratio) -> dict:
    ops = list(outcome.get("api_ops") or [])
    row = row_dict(
        RowParts(
            scenario,
            "shadow_verify",
            outcome["verdict"],
            outcome["gated_verdict"],
            outcome.get("reasons") or [],
            ops,
            outcome.get("verdict_latency_ms"),
            ratio,
        )
    )
    row["checked_account"] = outcome.get("checked_account")
    row["evidence_sha256"] = outcome.get("evidence_sha256")
    row["unchecked"] = outcome.get("unchecked") or []
    return row


def _sv(rows: list[dict]) -> dict:
    for row in rows:
        if row["baseline"] == "shadow_verify":
            return row
    return {}


def _note_tamper(rows, evidence_dir: Path, tamper: dict) -> None:
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
    flipped = text[:pos] + ("0" if text[pos] != "0" else "1") + text[pos + 1 :]
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
        missing = ", ".join(sorted(named - {item[0]["id"] for item in chosen}))
        return [], f"unknown scenario: {missing}"
    return chosen, ""


def _write(out: Path, rows: list[dict], summary: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows]
    (out / "results.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", newline="\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _known_gaps(root: Path) -> set[str]:
    data = json.loads((root / "eval" / "labels" / "known_gaps.json").read_text(encoding="utf-8"))
    return set(data)


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def _remember_commit(commit: str) -> None:
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
