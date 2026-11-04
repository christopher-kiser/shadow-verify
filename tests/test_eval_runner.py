"""Runner, coverage abstention, and the exit gate. Labels are not edited."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import boto3
from botocore.stub import Stubber
from moto import mock_aws

from eval.adapter import load_allowlist, run_verify
from eval.guard import protect
from eval.run import FIXED, HMAC_KEY, _pass, _sleep, clock, main
from eval.scoring import gate_exit
from eval.seed import install_fake_env
from shadow_verify.aws import BotoAws

ROOT = Path(__file__).resolve().parents[1]
S3_GOLDEN = "e9d1c3ad64baa521ff1323f0cf0e70316d52c138f0a142d53f80991f8df53bed"


def _pab(value=True):
    return [
        {"property": f"pab.{name}", "op": "eq", "value": value}
        for name in (
            "block_public_acls",
            "ignore_public_acls",
            "block_public_policy",
            "restrict_public_buckets",
        )
    ]


def _sv(path: Path) -> dict[str, dict]:
    rows = [
        json.loads(line)
        for line in (path / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return {
        row["scenario_id"]: row
        for row in rows
        if row["baseline"] == "shadow_verify"
    }


def test_unsupported_property_blocks_an_otherwise_passing_claim(tmp_path):
    install_fake_env(str(tmp_path))
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="sv-eval-logs")
        s3.put_public_access_block(
            Bucket="sv-eval-logs",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        allow, denied = load_allowlist(ROOT / "docs" / "iam-policy.json")

        def claim(assertions, sid):
            return {
                "id": sid,
                "text": "pab",
                "resources": [
                    {
                        "resource_type": "s3_bucket",
                        "resource_id": "sv-eval-logs",
                        "region": "us-east-1",
                        "account_id": None,
                        "assertions": assertions,
                    }
                ],
            }

        with protect(session, None, allow, denied):
            passed = run_verify(claim(_pab(), "only-pab"), session, clock, _sleep, HMAC_KEY, tmp_path / "a")
            blocked = run_verify(
                claim(
                    _pab() + [{"property": "encryption.sse_algorithm", "op": "eq", "value": "AES256"}],
                    "pab-plus",
                ),
                session,
                clock,
                _sleep,
                HMAC_KEY,
                tmp_path / "b",
            )
    assert passed["verdict"] == "PASS"
    assert blocked["verdict"] == "NOT_ASSESSED"
    assert "unsupported_property" in blocked["reasons"]
    assert blocked["verdict"] != "PASS"


def test_two_resources_use_fail_then_not_assessed(tmp_path):
    install_fake_env(str(tmp_path))
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        for name, flags in (
            ("good", True),
            ("bad", False),
        ):
            s3.create_bucket(Bucket=name)
            s3.put_public_access_block(
                Bucket=name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": flags,
                    "IgnorePublicAcls": flags,
                    "BlockPublicPolicy": flags,
                    "RestrictPublicBuckets": flags,
                },
            )
        allow, denied = load_allowlist(ROOT / "docs" / "iam-policy.json")
        claim = {
            "id": "two",
            "text": "both",
            "resources": [
                {
                    "resource_type": "s3_bucket",
                    "resource_id": "good",
                    "region": "us-east-1",
                    "account_id": None,
                    "assertions": _pab(True),
                },
                {
                    "resource_type": "s3_bucket",
                    "resource_id": "bad",
                    "region": "us-east-1",
                    "account_id": None,
                    "assertions": _pab(True),
                },
            ],
        }
        with protect(session, None, allow, denied):
            failed = run_verify(claim, session, clock, _sleep, HMAC_KEY, tmp_path / "f")
            claim["resources"][1]["assertions"] = [
                {"property": "encryption.sse_algorithm", "op": "eq", "value": "AES256"}
            ]
            abstained = run_verify(claim, session, clock, _sleep, HMAC_KEY, tmp_path / "n")
    assert failed["verdict"] == "FAIL"
    assert abstained["verdict"] == "NOT_ASSESSED"


def test_x02_and_unsupported_account_make_no_calls(tmp_path):
    code = main(
        ["--scenario", "X-02", "--out", str(tmp_path / "out"), "--root", str(ROOT)]
    )
    assert code == 0
    row = _sv(tmp_path / "out")["X-02"]
    assert row["raw_verdict"] == "NOT_ASSESSED"
    assert row["api_calls"] == 0
    assert "unsupported_resource" in row["reasons"]
    scenario = json.loads((ROOT / "eval" / "scenarios" / "X-02.json").read_text(encoding="utf-8"))
    assert scenario["agent_claim"]["structured"]["resources"][0]["account_id"] is None
    install_fake_env(str(tmp_path))
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        allow, denied = load_allowlist(ROOT / "docs" / "iam-policy.json")
        claim = {
            "id": "x",
            "text": "no",
            "resources": [
                {
                    "resource_type": "rds_instance",
                    "resource_id": "db",
                    "region": "us-east-1",
                    "account_id": "111122223333",
                    "assertions": [{"property": "publicly_accessible", "op": "eq", "value": False}],
                }
            ],
        }
        with protect(session, None, allow, denied) as state:
            outcome = run_verify(claim, session, clock, _sleep, HMAC_KEY, tmp_path / "x")
        assert outcome["verdict"] == "NOT_ASSESSED"
        assert state.ops == []
        assert outcome["api_ops"] == []


def test_named_scenarios_are_scored_without_hiding_misses(tmp_path):
    code = main(
        [
            "--scenario",
            "S3-01",
            "--scenario",
            "SG-06",
            "--scenario",
            "S3-11",
            "--scenario",
            "REG-01",
            "--scenario",
            "REG-02",
            "--scenario",
            "SG-09",
            "--scenario",
            "SG-14",
            "--scenario",
            "SG-15",
            "--scenario",
            "SG-16",
            "--scenario",
            "EC-01",
            "--scenario",
            "PG-03",
            "--scenario",
            "ACC-01",
            "--scenario",
            "X-02",
            "--out",
            str(tmp_path),
            "--root",
            str(ROOT),
        ]
    )
    rows = _sv(tmp_path)
    assert rows["S3-01"]["raw_verdict"] == "PASS"
    assert rows["S3-11"]["raw_verdict"] == "NOT_ASSESSED"
    assert rows["SG-09"]["raw_verdict"] == "FAIL"
    assert rows["SG-14"]["raw_verdict"] == "NOT_ASSESSED"
    assert any("unresolvable_source" in reason for reason in rows["SG-14"]["reasons"])
    assert rows["SG-16"]["raw_verdict"] == "PASS"
    assert rows["ACC-01"]["raw_verdict"] == "NOT_ASSESSED"
    assert "sts:GetCallerIdentity" in rows["ACC-01"]["api_ops"]
    assert "iam:GetRole" not in rows["ACC-01"]["api_ops"]
    assert rows["X-02"]["api_calls"] == 0
    # v0 cannot express these. NOT_ASSESSED is the miss, not a tuned PASS.
    for sid in ("SG-06", "SG-15", "REG-02", "EC-01"):
        assert rows[sid]["raw_verdict"] == "NOT_ASSESSED"
        assert "unsupported_property" in rows[sid]["reasons"]
        assert rows[sid]["expected_verdict"] in {"PASS", "FAIL"}
    assert rows["PG-03"]["raw_verdict"] == "NOT_ASSESSED"
    assert "unsupported_property" in rows["PG-03"]["reasons"]
    # Region is not a v0 check. The PASS is a real wrong PASS.
    assert rows["REG-01"]["raw_verdict"] == "PASS"
    assert rows["REG-01"]["expected_verdict"] == "FAIL"
    assert rows["REG-01"]["claim_true"] is False
    assert code == 1


def test_case_error_is_recorded_and_the_next_case_runs(tmp_path, monkeypatch):
    real = __import__("eval.run", fromlist=["apply"]).apply

    def wrapped(session, scenario, **kwargs):
        if scenario["id"] == "S3-02" and not kwargs.get("post"):
            raise RuntimeError("boom")
        return real(session, scenario, **kwargs)

    monkeypatch.setattr("eval.run.apply", wrapped)
    code = main(
        ["--scenario", "S3-02", "--scenario", "S3-01", "--out", str(tmp_path), "--root", str(ROOT)]
    )
    rows = _sv(tmp_path)
    assert rows["S3-02"]["error"]
    assert rows["S3-02"]["raw_verdict"] == "ERROR"
    assert rows["S3-01"]["raw_verdict"] == "PASS"
    assert code == 1


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
    code, _ = gate_exit([row("CF-04", "PASS", "FAIL", "FAIL", False)], gaps, read_only_ok=True, determinism_ok=True, determinism_checked=False)
    assert code == 1
    code, _ = gate_exit([row("S3-06", "PASS", "FAIL", "FAIL", False)], gaps, read_only_ok=True, determinism_ok=True, determinism_checked=False)
    assert code == 1
    code, _ = gate_exit(
        [row("L-02", "PASS", "FAIL", "FAIL", False, True)],
        gaps,
        read_only_ok=True,
        determinism_ok=True,
        determinism_checked=False,
    )
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


def test_s3_owner_header_and_stubbed_403(tmp_path, monkeypatch):
    install_fake_env(str(tmp_path))
    flags = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")
        stub = Stubber(s3)
        expected = {"Bucket": "logs", "ExpectedBucketOwner": "123456789012"}
        stub.add_response(
            "get_public_access_block",
            {"PublicAccessBlockConfiguration": flags},
            expected,
        )
        stub.activate()

        def fake_from_session(bound, region, evidence):
            return BotoAws(
                s3=s3,
                ec2=bound.client("ec2", region_name=region),
                iam=bound.client("iam", region_name=region),
                evidence=evidence,
            )

        monkeypatch.setattr("eval.adapter.BotoAws.from_session", fake_from_session)
        allow, denied = load_allowlist(ROOT / "docs" / "iam-policy.json")
        claim = {
            "id": "owner",
            "text": "pab",
            "resources": [
                {
                    "resource_type": "s3_bucket",
                    "resource_id": "logs",
                    "region": "us-east-1",
                    "account_id": "123456789012",
                    "assertions": _pab(),
                }
            ],
        }
        with protect(session, None, allow, denied):
            passed = run_verify(claim, session, clock, _sleep, HMAC_KEY, tmp_path / "p")
        stub.assert_no_pending_responses()
        assert passed["verdict"] == "PASS"
        stub.add_client_error(
            "get_public_access_block",
            service_error_code="403",
            service_message="Forbidden",
            http_status_code=403,
            expected_params=expected,
        )
        with protect(session, None, allow, denied):
            denied_out = run_verify(claim, session, clock, _sleep, HMAC_KEY, tmp_path / "d")
        assert denied_out["verdict"] == "NOT_ASSESSED"
        assert "owner_mismatch_or_denied" in denied_out["reasons"]


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
