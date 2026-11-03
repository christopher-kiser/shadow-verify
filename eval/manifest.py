"""Core eval manifest. Stdlib only. OFFLINE: no AWS and no network.

The set hash is SHA-256 over ``path\\0file_sha256\\n`` lines, sorted by the
UTF-8 bytes of the POSIX path. ``eval/MANIFEST.sha256`` stores that hex digest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

HELD_OUT_PIN = "69fda69f4d2716d9f5ece79724f13d415bee268fd40990db0b3d4ca147a3bb37"
HELD_OUT_ID = re.compile(r"^HB-\d{2}$")

# Named explicitly. The hash sorts these by UTF-8 bytes; this tuple is already
# in that order. Do not discover files with a glob at hash time.
CORE_FILES: tuple[str, ...] = (
    "eval/labels/adjudication.md",
    "eval/labels/known_gaps.json",
    "eval/labels/sentinel.json",
    "eval/scenarios/ACC-01.json",
    "eval/scenarios/CF-01.json",
    "eval/scenarios/CF-02.json",
    "eval/scenarios/CF-03.json",
    "eval/scenarios/CF-04.json",
    "eval/scenarios/EC-01.json",
    "eval/scenarios/EC-02.json",
    "eval/scenarios/ERR-01.json",
    "eval/scenarios/ERR-02.json",
    "eval/scenarios/ERR-03.json",
    "eval/scenarios/ERR-04.json",
    "eval/scenarios/IAM-01.json",
    "eval/scenarios/IAM-02.json",
    "eval/scenarios/IAM-03.json",
    "eval/scenarios/IAM-04.json",
    "eval/scenarios/IAM-05.json",
    "eval/scenarios/IAM-06.json",
    "eval/scenarios/IAM-07.json",
    "eval/scenarios/IAM-08.json",
    "eval/scenarios/IAM-09.json",
    "eval/scenarios/L-01.json",
    "eval/scenarios/L-02.json",
    "eval/scenarios/L-03.json",
    "eval/scenarios/L-04.json",
    "eval/scenarios/PG-01.json",
    "eval/scenarios/PG-02.json",
    "eval/scenarios/PG-03.json",
    "eval/scenarios/REG-01.json",
    "eval/scenarios/REG-02.json",
    "eval/scenarios/S3-01.json",
    "eval/scenarios/S3-02.json",
    "eval/scenarios/S3-03.json",
    "eval/scenarios/S3-04.json",
    "eval/scenarios/S3-05.json",
    "eval/scenarios/S3-06.json",
    "eval/scenarios/S3-07.json",
    "eval/scenarios/S3-08.json",
    "eval/scenarios/S3-09.json",
    "eval/scenarios/S3-10.json",
    "eval/scenarios/S3-11.json",
    "eval/scenarios/SG-01.json",
    "eval/scenarios/SG-02.json",
    "eval/scenarios/SG-03.json",
    "eval/scenarios/SG-04.json",
    "eval/scenarios/SG-05.json",
    "eval/scenarios/SG-06.json",
    "eval/scenarios/SG-07.json",
    "eval/scenarios/SG-08.json",
    "eval/scenarios/SG-09.json",
    "eval/scenarios/SG-10.json",
    "eval/scenarios/SG-11.json",
    "eval/scenarios/SG-12.json",
    "eval/scenarios/SG-13.json",
    "eval/scenarios/SG-14.json",
    "eval/scenarios/SG-15.json",
    "eval/scenarios/SG-16.json",
    "eval/scenarios/X-01.json",
    "eval/scenarios/X-02.json",
)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def canonical_payload(entries: Iterable[tuple[str, str]]) -> bytes:
    rows = [(path.encode("utf-8"), digest) for path, digest in entries]
    rows.sort(key=lambda row: row[0])
    parts = [path + b"\0" + digest.encode("ascii") + b"\n" for path, digest in rows]
    return b"".join(parts)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bytes(root: Path, rel: str) -> bytes:
    return (root / rel).read_bytes()


def set_sha256(root: Path, files: Iterable[str] | None = None) -> str:
    chosen = tuple(CORE_FILES if files is None else files)
    entries = [(rel, _sha256_bytes(_read_bytes(root, rel))) for rel in chosen]
    return _sha256_bytes(canonical_payload(entries))


def is_void_heldout(digest: str) -> bool:
    return digest.startswith("231a58c6") and digest.endswith("70aa0")


def heldout_problems(root: Path) -> list[str]:
    path = root / "eval" / "heldout.manifest.json"
    if not path.is_file():
        return ["missing eval/heldout.manifest.json"]
    data = json.loads(path.read_text(encoding="utf-8"))
    problems: list[str] = []
    files = data.get("files")
    if not isinstance(files, dict):
        return ["held-out files is not an object"]
    for rel in files:
        stem = _stem(rel)
        if HELD_OUT_ID.fullmatch(stem) is None:
            problems.append(f"bad held-out id {stem}")
    recomputed = _sha256_bytes(canonical_payload(files.items()))
    digest = data.get("set_sha256")
    if recomputed != HELD_OUT_PIN:
        problems.append(f"recomputed held-out set hash {recomputed} != pin")
    if digest != HELD_OUT_PIN:
        problems.append(f"held-out set_sha256 is {digest}")
    if isinstance(digest, str) and is_void_heldout(digest):
        problems.append("void held-out hash")
    return problems


def _stem(rel: str) -> str:
    return PurePosixPath(rel.replace("\\", "/")).stem


def _scenario_names(files: Iterable[str]) -> set[str]:
    return {
        rel
        for rel in files
        if rel.startswith("eval/scenarios/") and rel.endswith(".json")
    }


def check(
    root: Path,
    files: Iterable[str] | None = None,
    check_heldout: bool = True,
) -> list[str]:
    chosen = tuple(CORE_FILES if files is None else files)
    problems: list[str] = []
    if check_heldout:
        problems.extend(heldout_problems(root))
    scenario_dir = root / "eval" / "scenarios"
    on_disk: set[str] = set()
    if scenario_dir.is_dir():
        on_disk = {f"eval/scenarios/{path.name}" for path in scenario_dir.glob("*.json")}
    named = _scenario_names(chosen)
    for rel in sorted(on_disk - named):
        problems.append(f"extra {rel}")
    missing = [rel for rel in chosen if not (root / rel).is_file()]
    for rel in missing:
        problems.append(f"missing {rel}")
    if missing:
        return problems
    expected = set_sha256(root, chosen)
    manifest_path = root / "eval" / "MANIFEST.sha256"
    if not manifest_path.is_file():
        problems.append("missing eval/MANIFEST.sha256")
        return problems
    text = manifest_path.read_text(encoding="utf-8")
    if text != expected + "\n":
        problems.append("manifest mismatch")
    return problems


def write_manifest(
    root: Path,
    files: Iterable[str] | None = None,
    check_heldout: bool = True,
) -> str:
    chosen = tuple(CORE_FILES if files is None else files)
    if check_heldout:
        problems = heldout_problems(root)
        if problems:
            raise SystemExit(2)
    digest = set_sha256(root, chosen)
    path = root / "eval" / "MANIFEST.sha256"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((digest + "\n").encode("ascii"))
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute or check the OFFLINE core eval manifest."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 2 if the manifest or the held-out pin does not match",
    )
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--files", action="append", default=None)
    args = parser.parse_args(argv)
    root = args.root if args.root is not None else repo_root()
    chosen = tuple(args.files) if args.files else None
    check_heldout = chosen is None
    if args.check:
        problems = check(root, chosen, check_heldout=check_heldout)
        for item in problems:
            print(item, file=sys.stderr)
        return 2 if problems else 0
    if check_heldout:
        problems = heldout_problems(root)
        if problems:
            for item in problems:
                print(item, file=sys.stderr)
            return 2
    digest = write_manifest(root, chosen, check_heldout=False)
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
