"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ProfileNotFound

from shadow_verify import __version__
from shadow_verify.aws import BotoAws
from shadow_verify.claims import load_claims_file
from shadow_verify.engine import run_checks
from shadow_verify.errors import ShadowVerifyError
from shadow_verify.evidence import EvidenceLog, bundle_problems
from shadow_verify.models import Verdict
from shadow_verify.report import build_report, render_human
from shadow_verify.terraform import plan_notes, read_plan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadow-verify",
        description=(
            "Compare explicit AWS claims to live read-only account state. "
            "Verdicts are PASS, FAIL, or NOT ASSESSED. Rules only; model text cannot grant PASS."
        ),
    )
    parser.add_argument("--version", action="version", version=f"shadow-verify {__version__}")
    parser.add_argument("--claims", help="Path to a claims YAML or JSON file")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--profile", default=None, help="Optional AWS shared-config profile")
    parser.add_argument(
        "--evidence",
        default="shadow-verify-evidence.json",
        help="Where to write the evidence bundle (default: shadow-verify-evidence.json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Write the machine-readable report to stdout",
    )
    parser.add_argument(
        "--plan",
        default=None,
        help="Optional terraform show -json file. Informational in v0; does not change verdicts.",
    )
    parser.add_argument(
        "--fail-on-not-assessed",
        action="store_true",
        help="Exit 1 when any claim is NOT ASSESSED. Default: exit 1 only on FAIL.",
    )
    parser.add_argument(
        "--verify-evidence",
        default=None,
        help="Check an evidence bundle's item and bundle hashes, then exit",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    sys.exit(run(argv))


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.verify_evidence:
            return _verify(Path(args.verify_evidence))
        if not args.claims:
            parser.error("--claims is required unless --verify-evidence is set")
        return _verify_claims(args)
    except ShadowVerifyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _verify(path: Path) -> int:
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: cannot read evidence file: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: evidence file is not JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(bundle, dict):
        print("error: evidence file must be a JSON object", file=sys.stderr)
        return 2
    problems = bundle_problems(bundle)
    if problems:
        print("evidence bundle hash check failed:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print(f"evidence bundle ok: {bundle.get('bundle_sha256')}")
    return 0


def _verify_claims(args: argparse.Namespace) -> int:
    claims_path = Path(args.claims)
    claims, claims_sha256 = load_claims_file(claims_path)
    plan = read_plan(Path(args.plan)) if args.plan else None
    notes = plan_notes(claims, plan)
    session_kwargs: dict = {"region_name": args.region}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    try:
        session = boto3.Session(**session_kwargs)
    except ProfileNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    evidence = EvidenceLog()
    aws = BotoAws.from_session(session, args.region, evidence)
    results = run_checks(claims, aws)
    result_dicts = [item.to_dict() for item in results]
    bundle = evidence.bundle(
        generated_at=datetime.now(timezone.utc).isoformat(),
        claims_file=args.claims,
        claims_sha256=claims_sha256,
        region=args.region,
        results=result_dicts,
        plan_notes=notes,
    )
    evidence_path = Path(args.evidence)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    report = build_report(
        results,
        evidence_path=args.evidence,
        bundle_sha256=bundle["bundle_sha256"],
        plan_notes=notes,
    )
    if args.json_output:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(report))
    if any(item.verdict == Verdict.FAIL for item in results):
        return 1
    if args.fail_on_not_assessed and any(item.verdict == Verdict.NOT_ASSESSED for item in results):
        return 1
    return 0
