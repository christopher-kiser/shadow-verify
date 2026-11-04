"""CLI guards for a non-core manifest. Offline. No AWS and no network.

Every command that can write runs against a temporary root inside the
repository. A broken guard rewrites that copy, not the real freeze.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from eval.manifest import MANIFEST_AUTHOR, MANIFEST_CREATED, main, write_manifest

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "eval" / "legacy"
LEGACY_CREATED = "2026-11-04"
LEGACY_AUTHOR = "Forge"


def _legacy_files() -> tuple[str, ...]:
    names = sorted(path.name for path in (LEGACY / "scenarios").glob("*.json"))
    return tuple(f"eval/legacy/scenarios/{name}" for name in names)


def _file_args(files: tuple[str, ...]) -> list[str]:
    args: list[str] = []
    for rel in files:
        args.extend(["--files", rel])
    return args


def _copy_tree(work: Path, rels: tuple[str, ...]) -> None:
    for rel in rels:
        source = ROOT / rel
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())


def _snapshot(root: Path) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    if not root.exists():
        return found
    for path in root.rglob("*"):
        if path.is_file():
            found[path.relative_to(root).as_posix()] = path.read_bytes()
    return found


def _real_core() -> tuple[bytes, bytes]:
    return (
        (ROOT / "eval" / "manifest.json").read_bytes(),
        (ROOT / "eval" / "MANIFEST.sha256").read_bytes(),
    )


def test_script_entry_check_exits_0():
    real = _real_core()
    completed = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "manifest.py"), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert _real_core() == real


def test_files_without_out_exits_2_and_writes_nothing(capsys):
    real = _real_core()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        destination = work / "eval"
        destination.mkdir(parents=True)
        (destination / "manifest.json").write_bytes(b"keep\n")
        (destination / "MANIFEST.sha256").write_bytes(b"keep\n")
        before = _snapshot(work)
        code = main(
            ["--root", str(work), "--files", "eval/legacy/scenarios/LG-01.json"]
        )
        assert code == 2
        assert "--files requires --out" in capsys.readouterr().err
        assert _snapshot(work) == before
    assert _real_core() == real


def test_created_without_out_exits_2(capsys):
    real = _real_core()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        (work / "eval").mkdir()
        (work / "eval" / "manifest.json").write_bytes(b"keep\n")
        before = _snapshot(work)
        code = main(
            ["--root", str(work), "--created", "2026-11-04", "--author", "Forge"]
        )
        assert code == 2
        assert "--created and --author require --out" in capsys.readouterr().err
        assert _snapshot(work) == before
    assert _real_core() == real


def test_out_resolving_to_a_core_directory_exits_2(capsys):
    """eval, its core children, case, slash, and an absolute path all exit 2."""
    real = _real_core()
    forms = (
        "eval",
        "./eval/",
        "eval\\",
        "EVAL",
        "eval/scenarios",
        "eval/labels",
        "eval/heldout",
        "Eval/Scenarios",
    )
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        sample = work / "eval" / "legacy" / "scenarios" / "LG-01.json"
        sample.parent.mkdir(parents=True)
        sample.write_bytes(b"{}\n")
        (work / "eval" / "scenarios").mkdir()
        (work / "eval" / "scenarios" / "S3-01.json").write_bytes(b"{}\n")
        (work / "eval" / "labels").mkdir()
        (work / "eval" / "labels" / "sentinel.json").write_bytes(b"{}\n")
        (work / "eval" / "heldout").mkdir()
        (work / "eval" / "heldout" / "HB-01.json").write_bytes(b"{}\n")
        (work / "Eval" / "Scenarios").mkdir(parents=True, exist_ok=True)
        (work / "Eval" / "Scenarios" / "S3-01.json").write_bytes(b"{}\n")
        (work / "eval" / "manifest.json").write_bytes(b"keep\n")
        (work / "eval" / "MANIFEST.sha256").write_bytes(b"keep\n")
        absolute = str((work / "eval").resolve())
        for out in (*forms, absolute):
            file_rel = "eval/legacy/scenarios/LG-01.json"
            if out.casefold().endswith("scenarios"):
                file_rel = "eval/scenarios/S3-01.json" if out == "eval/scenarios" else "Eval/Scenarios/S3-01.json"
            elif out.casefold().endswith("labels"):
                file_rel = "eval/labels/sentinel.json"
            elif out.casefold().endswith("heldout"):
                file_rel = "eval/heldout/HB-01.json"
            before = _snapshot(work)
            code = main(["--root", str(work), "--out", out, "--files", file_rel])
            assert code == 2, out
            assert "refuses to overwrite the core manifest" in capsys.readouterr().err
            assert _snapshot(work) == before
    assert _real_core() == real


def test_files_must_resolve_under_out(capsys):
    real = _real_core()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        sibling = work / "eval" / "legacy-other" / "LG-01.json"
        sibling.parent.mkdir(parents=True)
        sibling.write_bytes(b"{}\n")
        (work / "eval" / "legacy").mkdir()
        before = _snapshot(work)
        code = main(
            [
                "--root",
                str(work),
                "--out",
                "eval/legacy",
                "--files",
                "eval/legacy-other/LG-01.json",
            ]
        )
        assert code == 2
        assert "file is outside --out: eval/legacy-other/LG-01.json" in capsys.readouterr().err
        assert _snapshot(work) == before
    assert _real_core() == real


def test_created_must_be_a_date(capsys):
    real = _real_core()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        target = work / "scratch" / "a.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"{}\n")
        for created in ("yesterday", "2026-02-31", "20261104"):
            before = _snapshot(work)
            code = main(
                [
                    "--root",
                    str(work),
                    "--out",
                    "scratch",
                    "--files",
                    "scratch/a.json",
                    "--created",
                    created,
                    "--author",
                    "Forge",
                ]
            )
            assert code == 2, created
            assert "--created must be YYYY-MM-DD" in capsys.readouterr().err
            assert _snapshot(work) == before
    assert _real_core() == real


def test_write_manifest_records_a_passed_created(tmp_path: Path):
    target = tmp_path / "scratch" / "a.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"{}\n")
    write_manifest(
        tmp_path,
        ("scratch/a.json",),
        check_heldout=False,
        created="2026-11-04",
        author="Forge",
    )
    document = json.loads((tmp_path / "eval" / "manifest.json").read_text(encoding="utf-8"))
    assert document["created"] == "2026-11-04"
    assert document["author"] == "Forge"
    assert document["created"] != MANIFEST_CREATED


def test_legacy_manifest_is_built_in_a_temp_copy(capsys):
    real = _real_core()
    files = _legacy_files()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        (work / "eval").mkdir()
        (work / "eval" / "manifest.json").write_bytes(real[0])
        (work / "eval" / "MANIFEST.sha256").write_bytes(real[1])
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
        assert (work / "eval" / "manifest.json").read_bytes() == real[0]
        assert (work / "eval" / "MANIFEST.sha256").read_bytes() == real[1]
        assert main(["--check", "--root", str(work), "--out", "eval/legacy", *_file_args(files)]) == 0
        document = json.loads(
            (work / "eval" / "legacy" / "manifest.json").read_text(encoding="utf-8")
        )
        assert document["created"] == LEGACY_CREATED
        assert document["author"] == LEGACY_AUTHOR
        assert set(document["files"]) == set(files)
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
    assert _real_core() == real
    assert not (LEGACY / "manifest.json").exists()


def test_legacy_check_ignores_core_scenarios_and_heldout():
    files = _legacy_files()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        _copy_tree(work, files)
        (work / "eval").mkdir(exist_ok=True)
        (work / "eval" / "heldout.manifest.json").write_text("{}\n", encoding="utf-8")
        extra = work / "eval" / "scenarios"
        extra.mkdir()
        (extra / "EXTRA.json").write_bytes(b"{}\n")
        args = ["--root", str(work), "--out", "eval/legacy", *_file_args(files)]
        assert main([*args, "--created", LEGACY_CREATED, "--author", LEGACY_AUTHOR]) == 0
        assert main(["--check", *args]) == 0


def test_omitted_author_uses_core_constants_outside_eval():
    real = _real_core()
    with tempfile.TemporaryDirectory(dir=ROOT) as raw:
        work = Path(raw)
        rel = "scratch/scenarios/S3-01.json"
        target = work / rel
        target.parent.mkdir(parents=True)
        target.write_bytes(b"{}\n")
        assert main(["--root", str(work), "--out", "scratch", "--files", rel]) == 0
        document = json.loads((work / "scratch" / "manifest.json").read_text(encoding="utf-8"))
        assert document["created"] == MANIFEST_CREATED
        assert document["author"] == MANIFEST_AUTHOR
        assert document["version"] == 1
        assert not (work / "eval" / "manifest.json").exists()
    assert _real_core() == real
