"""Offline checks for the legacy eval set. No AWS and no network.

The legacy cases are scored apart from the core freeze and the held-out pin.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from eval.manifest import (
    CORE_FILES,
    HELD_OUT_PIN,
    MANIFEST_AUTHOR,
    MANIFEST_CREATED,
    check,
    heldout_problems,
    main,
    set_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "eval" / "legacy"
SCENARIOS = LEGACY / "scenarios"
CORE_SET = "7b4cd4f1e447f0cee054c32aeaa5eafef3a670bd2e671b38f9316f69aa4af113"
LEGACY_CREATED = "2026-11-04"
LEGACY_AUTHOR = "Forge"
LEGACY_ID = re.compile(r"^LG-\d{2}$")

# Spec section 2 SEED_ALLOWLIST, core calls only. Stretch calls are rejected.
SEED_ALLOWLIST = {
    "s3.create_bucket",
    "s3.put_public_access_block",
    "s3.put_bucket_encryption",
    "s3.put_bucket_versioning",
    "s3.put_bucket_policy",
    "s3.delete_bucket_policy",
    "kms.create_key",
    "ec2.create_vpc",
    "ec2.create_security_group",
    "ec2.authorize_security_group_ingress",
    "ec2.revoke_security_group_ingress",
    "iam.create_role",
    "iam.update_assume_role_policy",
    "iam.create_policy",
    "iam.create_policy_version",
    "iam.attach_role_policy",
    "iam.detach_role_policy",
    "ec2.create_managed_prefix_list",
    "dynamodb.create_table",
    "sts.assume_role",
}

# Properties v0 reads today, in the eval scenario vocabulary.
# security_group forbids map to ingress_forbidden. The four PAB flags are the
# s3 checker. attached_policy_arns is the IAM set. Encryption, versioning,
# security-group contains/equals_set, and iam_policy are outside this list.
V0_OPS = {
    "security_group": {"ingress": {"not_contains"}},
    "s3_bucket": {
        "pab.block_public_acls": {"eq"},
        "pab.ignore_public_acls": {"eq"},
        "pab.block_public_policy": {"eq"},
        "pab.restrict_public_buckets": {"eq"},
    },
    "iam_role": {"attached_policy_arns": {"equals_set"}},
}

CONDITIONS = {
    "none",
    "wrong_region",
    "wrong_account",
    "stale_read",
    "access_denied",
    "throttling",
    "timeout",
    "not_found",
    "pagination",
    "truncated_pagination",
    "underspecified_claim",
    "cidr_semantics",
    "unresolvable_source",
}
FAILURE_TYPES = {
    "truthful_success",
    "silent_partial_apply",
    "hallucinated_success",
    "out_of_scope_mutation",
    "drift_after_apply",
    "stale_after_retry",
    "unverifiable",
}
VERDICTS = {"PASS", "FAIL", "NOT_ASSESSED"}
_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _legacy_files() -> tuple[str, ...]:
    names = sorted(path.name for path in SCENARIOS.glob("*.json"))
    return tuple(f"eval/legacy/scenarios/{name}" for name in names)


def _file_args(files: tuple[str, ...]) -> list[str]:
    args: list[str] = []
    for rel in files:
        args.extend(["--files", rel])
    return args


def _schema_problems(path: Path) -> list[str]:
    raw = path.read_bytes()
    problems: list[str] = []
    if b"\r" in raw:
        problems.append(f"{path.name} has CR")
    if not raw.endswith(b"\n"):
        problems.append(f"{path.name} missing trailing newline")
    try:
        scenario = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"{path.name} is not utf-8 JSON: {exc}"]
    example = json.loads(
        (ROOT / "eval" / "scenarios" / "SG-05.json").read_text(encoding="utf-8")
    )
    if set(scenario) != set(example):
        problems.append(f"{path.name} keys {sorted(set(scenario) ^ set(example))}")
    sid = scenario.get("id")
    if sid != path.stem or LEGACY_ID.fullmatch(str(sid)) is None:
        problems.append(f"{path.name} id {sid}")
    resource_type = scenario.get("resource_type")
    if not isinstance(resource_type, str) or re.fullmatch(r"[a-z0-9_]+", resource_type) is None:
        problems.append(f"{sid} resource_type")
    if resource_type not in V0_OPS:
        problems.append(f"{sid} resource_type {resource_type} is outside v0")
    claim = scenario.get("agent_claim")
    if not isinstance(claim, dict) or set(claim) != {"text", "structured", "prose_assertions"}:
        problems.append(f"{sid} agent_claim")
        return problems
    if not isinstance(claim.get("text"), str) or not claim["text"].strip():
        problems.append(f"{sid} empty text")
    if claim.get("prose_assertions") != "same":
        problems.append(f"{sid} prose_assertions")
    structured = claim.get("structured")
    resources = structured.get("resources") if isinstance(structured, dict) else None
    if set(structured or {}) != {"resources"} or not isinstance(resources, list) or not resources:
        problems.append(f"{sid} structured")
        return problems
    for index, resource in enumerate(resources):
        if set(resource) != {
            "resource_type",
            "resource_id",
            "region",
            "account_id",
            "assertions",
        }:
            problems.append(f"{sid} resource {index} keys")
            continue
        if resource["resource_type"] != resource_type:
            problems.append(f"{sid} resource {index} type")
        if not isinstance(resource["resource_id"], str) or not resource["resource_id"]:
            problems.append(f"{sid} resource {index} id")
        region = resource["region"]
        if resource_type == "iam_role":
            if region is not None:
                problems.append(f"{sid} iam region")
        elif not isinstance(region, str) or not region:
            problems.append(f"{sid} region")
        if resource["account_id"] is not None:
            problems.append(f"{sid} account_id")
        assertions = resource["assertions"]
        if not isinstance(assertions, list) or not assertions:
            problems.append(f"{sid} resource {index} assertions")
            continue
        allowed = V0_OPS[resource_type]
        for assertion in assertions:
            if set(assertion) != {"property", "op", "value"}:
                problems.append(f"{sid} assertion keys")
                continue
            prop = assertion["property"]
            op = assertion["op"]
            if prop not in allowed or op not in allowed[prop]:
                problems.append(f"{sid} property {prop} op {op}")
    seed = scenario.get("seed")
    if not isinstance(seed, dict) or set(seed) != {
        "region",
        "steps",
        "post_claim",
        "fault",
        "page_size",
    }:
        problems.append(f"{sid} seed")
        return problems
    if not isinstance(seed["region"], str) or not seed["region"]:
        problems.append(f"{sid} seed.region")
    if seed["page_size"] is not None:
        problems.append(f"{sid} page_size")
    if seed["post_claim"] != [] or seed["fault"] != []:
        problems.append(f"{sid} post_claim or fault")
    saves: set[str] = set()
    if not isinstance(seed["steps"], list) or not seed["steps"]:
        problems.append(f"{sid} steps")
    else:
        for step in seed["steps"]:
            if not isinstance(step, dict) or "call" not in step or "params" not in step:
                problems.append(f"{sid} step")
                continue
            extra = set(step) - {"call", "params", "save", "region", "account"}
            if extra:
                problems.append(f"{sid} step keys {sorted(extra)}")
            if step["call"] not in SEED_ALLOWLIST:
                problems.append(f"{sid} call {step['call']}")
            if not isinstance(step["params"], dict):
                problems.append(f"{sid} params")
            else:
                problems.extend(_placeholder_problems(sid, step["params"], saves))
            save = step.get("save")
            if save is not None:
                if not isinstance(save, dict) or not save:
                    problems.append(f"{sid} save")
                else:
                    saves.update(str(key) for key in save)
    problems.extend(_placeholder_problems(sid, claim, saves))
    if scenario.get("condition") not in CONDITIONS:
        problems.append(f"{sid} condition")
    if scenario.get("failure_type") not in FAILURE_TYPES:
        problems.append(f"{sid} failure_type")
    if scenario.get("failure_type") == "unverifiable":
        problems.append(f"{sid} unverifiable")
    elif scenario.get("na_cause") is not None:
        problems.append(f"{sid} na_cause")
    if scenario.get("expected_verdict") not in VERDICTS:
        problems.append(f"{sid} verdict")
    if scenario.get("expected_raw_verdict") != scenario.get("expected_verdict"):
        problems.append(f"{sid} raw verdict")
    if not isinstance(scenario.get("claim_true"), bool):
        problems.append(f"{sid} claim_true")
    if scenario.get("stretch") is not False:
        problems.append(f"{sid} stretch")
    if not isinstance(scenario.get("rationale"), str) or not scenario["rationale"].strip():
        problems.append(f"{sid} rationale")
    return problems


def _placeholder_problems(sid: str, value, saves: set[str]) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        for name in _PLACEHOLDER.findall(value):
            if name not in saves:
                found.append(f"{sid} unknown placeholder {name}")
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(_placeholder_problems(sid, item, saves))
    elif isinstance(value, list):
        for item in value:
            found.extend(_placeholder_problems(sid, item, saves))
    return found


def _copy_tree(work: Path, rels: tuple[str, ...]) -> None:
    for rel in rels:
        source = ROOT / rel
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())


def test_core_set_hash_and_check_ignore_legacy():
    assert set_sha256(ROOT) == CORE_SET
    assert check(ROOT) == []
    assert main(["--check"]) == 0
    document = json.loads((ROOT / "eval" / "manifest.json").read_text(encoding="utf-8"))
    assert document["set_sha256"] == CORE_SET
    assert all("LG-" not in rel for rel in document["files"])
    assert all("LG-" not in rel for rel in CORE_FILES)
    assert heldout_problems(ROOT) == []
    pin = json.loads((ROOT / "eval" / "heldout.manifest.json").read_text(encoding="utf-8"))
    assert pin["set_sha256"] == HELD_OUT_PIN


def test_legacy_ids_labels_and_counts():
    files = _legacy_files()
    assert files == tuple(f"eval/legacy/scenarios/LG-{number:02d}.json" for number in range(1, 7))
    verdicts = {"PASS": 0, "FAIL": 0}
    truth = {True: 0, False: 0}
    for rel in files:
        scenario = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        assert LEGACY_ID.fullmatch(scenario["id"])
        assert scenario["id"] == Path(rel).stem
        for key in ("expected_verdict", "expected_raw_verdict", "claim_true"):
            assert key in scenario
        verdicts[scenario["expected_verdict"]] += 1
        truth[scenario["claim_true"]] += 1
    assert verdicts == {"PASS": 3, "FAIL": 3}
    assert truth == {True: 3, False: 3}


def test_legacy_scenarios_match_the_core_schema_and_v0_properties():
    problems: list[str] = []
    for path in sorted(SCENARIOS.glob("*.json")):
        problems.extend(_schema_problems(path))
    assert problems == []


def test_files_without_out_exits_2_and_writes_nothing(capsys):
    core_json = (ROOT / "eval" / "manifest.json").read_bytes()
    core_sha = (ROOT / "eval" / "MANIFEST.sha256").read_bytes()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        destination = work / "eval"
        destination.mkdir(parents=True)
        (destination / "manifest.json").write_bytes(core_json)
        (destination / "MANIFEST.sha256").write_bytes(core_sha)
        code = main(
            ["--root", str(work), "--files", "eval/legacy/scenarios/LG-01.json"]
        )
        assert code == 2
        assert "--files requires --out" in capsys.readouterr().err
        assert (destination / "manifest.json").read_bytes() == core_json
        assert (destination / "MANIFEST.sha256").read_bytes() == core_sha
        assert not (work / "eval" / "legacy" / "manifest.json").exists()
    assert main(["--files", "eval/legacy/scenarios/LG-01.json"]) == 2
    assert "--files requires --out" in capsys.readouterr().err
    assert (ROOT / "eval" / "manifest.json").read_bytes() == core_json
    assert (ROOT / "eval" / "MANIFEST.sha256").read_bytes() == core_sha


def test_created_without_out_exits_2(capsys):
    before = (ROOT / "eval" / "manifest.json").read_bytes()
    assert main(["--created", "2026-11-04", "--author", "Forge"]) == 2
    assert "--created and --author require --out" in capsys.readouterr().err
    assert (ROOT / "eval" / "manifest.json").read_bytes() == before


def test_legacy_check_covers_only_that_set():
    files = _legacy_files()
    assert main(["--check", "--out", "eval/legacy", *_file_args(files)]) == 0
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        _copy_tree(work, files)
        (work / "eval").mkdir(exist_ok=True)
        (work / "eval" / "heldout.manifest.json").write_text("{}\n", encoding="utf-8")
        extra_core = work / "eval" / "scenarios"
        extra_core.mkdir()
        (extra_core / "EXTRA.json").write_bytes(b"{}\n")
        args = ["--root", str(work), "--out", "eval/legacy", *_file_args(files)]
        assert main([*args, "--created", LEGACY_CREATED, "--author", LEGACY_AUTHOR]) == 0
        assert main(["--check", *args]) == 0
        # A broken held-out pin and an extra core scenario stay out of this check.


def test_legacy_check_names_a_changed_extra_or_missing_file(capsys):
    files = _legacy_files()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        _copy_tree(work, files)
        args = [
            "--root",
            str(work),
            "--out",
            "eval/legacy",
            "--created",
            LEGACY_CREATED,
            "--author",
            LEGACY_AUTHOR,
            *_file_args(files),
        ]
        assert main(args) == 0
        target = work / "eval" / "legacy" / "scenarios" / "LG-01.json"
        original = target.read_bytes()
        target.write_bytes(original + b" ")
        assert main(["--check", "--root", str(work), "--out", "eval/legacy", *_file_args(files)]) == 2
        assert "mismatch eval/legacy/scenarios/LG-01.json" in capsys.readouterr().err
        target.write_bytes(original)
        extra = work / "eval" / "legacy" / "scenarios" / "LG-07.json"
        extra.write_bytes(b"{}\n")
        assert main(["--check", "--root", str(work), "--out", "eval/legacy", *_file_args(files)]) == 2
        assert "extra eval/legacy/scenarios/LG-07.json" in capsys.readouterr().err
        extra.unlink()
        target.unlink()
        assert main(["--check", "--root", str(work), "--out", "eval/legacy", *_file_args(files)]) == 2
        assert "missing eval/legacy/scenarios/LG-01.json" in capsys.readouterr().err


def test_generating_legacy_manifest_leaves_core_bytes_unchanged():
    core_json = (ROOT / "eval" / "manifest.json").read_bytes()
    core_sha = (ROOT / "eval" / "MANIFEST.sha256").read_bytes()
    files = _legacy_files()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        (work / "eval").mkdir()
        (work / "eval" / "manifest.json").write_bytes(core_json)
        (work / "eval" / "MANIFEST.sha256").write_bytes(core_sha)
        _copy_tree(work, files)
        code = main(
            [
                "--root",
                str(work),
                "--out",
                "eval/legacy",
                "--created",
                LEGACY_CREATED,
                "--author",
                LEGACY_AUTHOR,
                *_file_args(files),
            ]
        )
        assert code == 0
        assert (work / "eval" / "manifest.json").read_bytes() == core_json
        assert (work / "eval" / "MANIFEST.sha256").read_bytes() == core_sha
        written = (work / "eval" / "legacy" / "manifest.json").read_bytes()
        recorded = (LEGACY / "manifest.json").read_bytes()
        assert written == recorded
        assert b"\r" not in written
        assert written.endswith(b"\n")
    assert (ROOT / "eval" / "manifest.json").read_bytes() == core_json
    assert (ROOT / "eval" / "MANIFEST.sha256").read_bytes() == core_sha


def test_default_out_keeps_core_constants_and_bytes():
    core_json = (ROOT / "eval" / "manifest.json").read_bytes()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        rel = "eval/scenarios/S3-01.json"
        _copy_tree(work, (rel,))
        assert main(["--root", str(work), "--out", "eval", "--files", rel]) == 0
        document = json.loads((work / "eval" / "manifest.json").read_text(encoding="utf-8"))
        assert document["created"] == MANIFEST_CREATED
        assert document["author"] == MANIFEST_AUTHOR
        assert document["version"] == 1
    assert (ROOT / "eval" / "manifest.json").read_bytes() == core_json


def test_default_check_does_not_scan_legacy_scenarios():
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        rel = "eval/scenarios/S3-01.json"
        _copy_tree(work, (rel,))
        legacy = work / "eval" / "legacy" / "scenarios"
        legacy.mkdir(parents=True)
        (legacy / "LG-07.json").write_bytes(b"{}\n")
        assert main(["--root", str(work), "--out", "eval", "--files", rel]) == 0
        assert check(work, (rel,), check_heldout=False) == []
