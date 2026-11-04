"""Command line entry point.

Subcommands:
  run     Compare claims to AWS. Accepts an injected boto3 Session and clock.
  verify  Recompute evidence hashes.

Exit codes for ``run``:
  0  every claim is PASS
  1  any claim is FAIL (FAIL outranks NOT ASSESSED)
  2  no FAIL, and at least one claim is NOT ASSESSED
  3  the claims file, plan, profile, or an unexpected crash

``verify`` exits 0 when the hashes match and 3 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import traceback
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ProfileNotFound

from shadow_verify import __version__
from shadow_verify.report import build_report, render_human
from shadow_verify.aws import BotoAws
from shadow_verify.claims import load_claims_file
from shadow_verify.engine import run_checks
from shadow_verify.errors import ShadowVerifyError
from shadow_verify.evidence import EvidenceLog, bundle_problems
from shadow_verify.models import Verdict
from shadow_verify.terraform import plan_notes, read_plan

Clock = Callable[[], datetime]


def system_clock() -> datetime:
    return datetime.now(timezone.utc)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(3, f"error: {message}\n")


def _tool_commit() -> str:
    override = os.environ.get("SV_TOOL_COMMIT")
    if override:
        return override
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[2],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return f"shadow-verify=={__version__}"
    sha = completed.stdout.strip()
    return sha or f"shadow-verify=={__version__}"


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="shadow-verify",
        description=(
            "Compare explicit AWS claims to live read-only account state. "
            "PASS only when every assertion was read and matched. "
            "Precedence is FAIL, then NOT ASSESSED, then PASS. "
            "Model text cannot grant PASS."
        ),
    )
    parser.add_argument("--version", action="version", version=f"shadow-verify {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    run_parser = commands.add_parser("run", help="Check claims against live AWS state")
    run_parser.add_argument("--claims", required=True, help="Path to a claims YAML or JSON file")
    run_parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    run_parser.add_argument("--profile", default=None, help="Optional AWS shared-config profile")
    run_parser.add_argument(
        "--evidence",
        default="shadow-verify-evidence.json",
        help="Where to write the evidence bundle (default: shadow-verify-evidence.json)",
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Write the machine-readable report to stdout",
    )
    run_parser.add_argument(
        "--plan",
        default=None,
        help="Optional terraform show -json file. Informational in v0; does not change verdicts.",
    )
    run_parser.add_argument(
        "--mode",
        choices=("MOCKED", "LIVE"),
        default="LIVE",
        help="Record whether this run used mocks or a live account (default: LIVE).",
    )

    verify_parser = commands.add_parser("verify", help="Check an evidence bundle's hashes")
    verify_parser.add_argument("evidence", help="Path to an evidence bundle JSON file")
    return parser


def main(argv: list[str] | None = None) -> None:
    try:
        sys.exit(run(argv))
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        sys.exit(3)


def run(
    argv: list[str] | None = None,
    *,
    session=None,
    clock: Clock | None = None,
) -> int:
    """Run the CLI.

    session: a boto3.Session, or any object with client(service, region_name=).
    When omitted, a session is built from --profile and --region.
    clock: callable returning an aware datetime. Tests inject a fixed clock.
    """

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            return _verify(Path(args.evidence))
        return _run_claims(args, session=session, clock=clock or system_clock)
    except ShadowVerifyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except Exception:
        traceback.print_exc()
        return 3


def _verify(path: Path) -> int:
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: cannot read evidence file: {exc}", file=sys.stderr)
        return 3
    except json.JSONDecodeError as exc:
        print(f"error: evidence file is not JSON: {exc}", file=sys.stderr)
        return 3
    if not isinstance(bundle, dict):
        print("error: evidence file must be a JSON object", file=sys.stderr)
        return 3
    problems = bundle_problems(bundle)
    if problems:
        print("evidence bundle hash check failed:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 3
    print(f"evidence bundle ok: {bundle.get('bundle_sha256')}")
    return 0


def _run_claims(args: argparse.Namespace, *, session, clock: Clock) -> int:
    claims_path = Path(args.claims)
    claims, claims_sha256 = load_claims_file(claims_path)
    plan = read_plan(Path(args.plan)) if args.plan else None
    notes = plan_notes(claims, plan)
    if session is None:
        session_kwargs: dict = {"region_name": args.region}
        if args.profile:
            session_kwargs["profile_name"] = args.profile
        try:
            session = boto3.Session(**session_kwargs)
        except ProfileNotFound as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
    evidence = EvidenceLog()
    aws = BotoAws.from_session(session, args.region, evidence)
    results = run_checks(claims, aws)
    result_dicts = [item.to_dict() for item in results]
    moment = clock()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    bundle = evidence.bundle(
        generated_at=moment.isoformat(),
        claims_file=args.claims,
        claims_sha256=claims_sha256,
        region=args.region,
        results=result_dicts,
        plan_notes=notes,
        mode=args.mode,
        tool_commit=_tool_commit(),
    )
    evidence_path = Path(args.evidence)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    report = build_report(
        bundle["results"],
        evidence_path=args.evidence,
        bundle_sha256=bundle["bundle_sha256"],
        plan_notes=bundle["plan_notes"],
        mode=bundle["mode"],
        tool_commit=bundle["tool_commit"],
    )
    if args.json_output:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(report))
    if any(item.verdict == Verdict.FAIL for item in results):
        return 1
    if any(item.verdict == Verdict.NOT_ASSESSED for item in results):
        return 2
    return 0
