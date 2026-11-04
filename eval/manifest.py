"""Core eval manifest. Stdlib only. OFFLINE: no AWS and no network.

The set hash is SHA-256 over ``path\\0file_sha256\\n`` lines, sorted by the
UTF-8 bytes of the POSIX path. ``eval/manifest.json`` stores the spec record.
``eval/MANIFEST.sha256`` stores that same set digest.

``--files`` writes a different set, so it requires ``--out DIR``. The manifest
and the scenario scan then use ``DIR`` instead of ``eval/``. The core command,
with neither flag, still reads and writes ``eval/``.
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
_DRIVE = re.compile(r"^[A-Za-z]:")

# Spec section 6. With Christopher's approval, the agent commits the freeze record.
MANIFEST_VERSION = 1
MANIFEST_CREATED = "2026-11-03"
MANIFEST_AUTHOR = "Christopher"

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


def file_digests(root: Path, files: Iterable[str]) -> dict[str, str]:
    return {rel: _sha256_bytes(_read_bytes(root, rel)) for rel in files}


def set_sha256(root: Path, files: Iterable[str] | None = None) -> str:
    chosen = tuple(CORE_FILES if files is None else files)
    return _sha256_bytes(canonical_payload(file_digests(root, chosen).items()))


def manifest_document(
    root: Path,
    files: Iterable[str] | None = None,
    *,
    created: str | None = None,
    author: str | None = None,
) -> dict:
    chosen = tuple(CORE_FILES if files is None else files)
    ordered = dict(
        sorted(
            file_digests(root, chosen).items(),
            key=lambda item: item[0].encode("utf-8"),
        )
    )
    return {
        "version": MANIFEST_VERSION,
        "created": MANIFEST_CREATED if created is None else created,
        "author": MANIFEST_AUTHOR if author is None else author,
        "files": ordered,
        "set_sha256": _sha256_bytes(canonical_payload(ordered.items())),
    }


def is_void_heldout(digest: str) -> bool:
    # The retired H-01..H-10 set (231a58c6…70aa0) may have been exposed.
    # A pin of that hash must fail instead of being run.
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


def _rel_escapes(rel: str) -> bool:
    text = rel.replace("\\", "/")
    if text.startswith("/") or _DRIVE.match(text):
        return True
    path = PurePosixPath(text)
    return path.is_absolute() or ".." in path.parts


def _output_dir(out: str | None) -> str:
    if out is None:
        return "eval"
    text = out.replace("\\", "/").strip("/")
    if text == "" or text == "." or _rel_escapes(text):
        raise ValueError(out)
    return text


def cli_path_problems(root: Path, files: Iterable[str] | None) -> list[str]:
    """Reject --root and --files values that leave the repository root."""
    problems: list[str] = []
    repo = repo_root().resolve()
    try:
        root.resolve().relative_to(repo)
    except ValueError:
        problems.append(f"root escapes repository: {root}")
    if not files:
        return problems
    for rel in files:
        if _rel_escapes(rel):
            problems.append(f"path escapes repository: {rel}")
            continue
        if problems and not root.resolve().is_relative_to(repo):
            continue
        try:
            (root.resolve() / rel).resolve().relative_to(repo)
        except ValueError:
            problems.append(f"path escapes repository: {rel}")
    return problems


def cli_out_problems(root: Path, out: str) -> list[str]:
    """Reject an --out directory that leaves the repository root."""
    text = out.replace("\\", "/")
    if text.strip("/") in {"", "."} or _rel_escapes(text):
        return [f"path escapes repository: {out}"]
    repo = repo_root().resolve()
    try:
        root.resolve().relative_to(repo)
    except ValueError:
        return [f"path escapes repository: {out}"]
    try:
        (root.resolve() / text).resolve().relative_to(repo)
    except ValueError:
        return [f"path escapes repository: {out}"]
    return []


def _scenario_names(files: Iterable[str], scenario_rel: str = "eval/scenarios") -> set[str]:
    prefix = scenario_rel + "/"
    return {rel for rel in files if rel.startswith(prefix) and rel.endswith(".json")}


def check(
    root: Path,
    files: Iterable[str] | None = None,
    check_heldout: bool = True,
    *,
    out: str | None = None,
) -> list[str]:
    chosen = tuple(CORE_FILES if files is None else files)
    directory = _output_dir(out)
    problems: list[str] = []
    if check_heldout:
        problems.extend(heldout_problems(root))
    scenario_rel = f"{directory}/scenarios"
    scenario_dir = root.joinpath(*scenario_rel.split("/"))
    on_disk: set[str] = set()
    if scenario_dir.is_dir():
        on_disk = {f"{scenario_rel}/{path.name}" for path in scenario_dir.glob("*.json")}
    named = _scenario_names(chosen, scenario_rel)
    for rel in sorted(on_disk - named):
        problems.append(f"extra {rel}")
    missing = [rel for rel in chosen if not (root / rel).is_file()]
    for rel in missing:
        problems.append(f"missing {rel}")
    if missing:
        return problems
    expected = set_sha256(root, chosen)
    manifest_rel = f"{directory}/manifest.json"
    problems.extend(_json_manifest_problems(root, chosen, expected, manifest_rel))
    sha_rel = f"{directory}/MANIFEST.sha256"
    sha_path = root.joinpath(*sha_rel.split("/"))
    if not sha_path.is_file():
        problems.append(f"missing {sha_rel}")
    elif sha_path.read_text(encoding="utf-8") != expected + "\n":
        problems.append(f"mismatch {sha_rel}")
    return problems


def _json_manifest_problems(
    root: Path,
    chosen: tuple[str, ...],
    expected: str,
    manifest_rel: str,
) -> list[str]:
    path = root.joinpath(*manifest_rel.split("/"))
    if not path.is_file():
        return [f"missing {manifest_rel}"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [f"{manifest_rel} is not valid JSON"]
    recorded = data.get("files")
    if not isinstance(recorded, dict):
        return [f"{manifest_rel} files is not an object"]
    problems: list[str] = []
    chosen_set = set(chosen)
    digests = file_digests(root, chosen)
    for rel in chosen:
        seen = recorded.get(rel)
        if seen is None:
            problems.append(f"missing from manifest {rel}")
        elif seen != digests[rel]:
            problems.append(f"mismatch {rel}")
    for rel in recorded:
        if rel not in chosen_set:
            problems.append(f"extra in manifest {rel}")
    if data.get("set_sha256") != expected:
        problems.append("set_sha256 mismatch")
    return problems


def write_manifest(
    root: Path,
    files: Iterable[str] | None = None,
    check_heldout: bool = True,
    *,
    out: str | None = None,
    created: str | None = None,
    author: str | None = None,
) -> str:
    chosen = tuple(CORE_FILES if files is None else files)
    if check_heldout:
        problems = heldout_problems(root)
        if problems:
            raise SystemExit(2)
    document = manifest_document(
        root,
        chosen,
        created=None if out is None else created,
        author=None if out is None else author,
    )
    digest = document["set_sha256"]
    directory = root.joinpath(*_output_dir(out).split("/"))
    directory.mkdir(parents=True, exist_ok=True)
    text = json.dumps(document, indent=2) + "\n"
    (directory / "manifest.json").write_bytes(text.encode("utf-8"))
    (directory / "MANIFEST.sha256").write_bytes((digest + "\n").encode("ascii"))
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
    parser.add_argument(
        "--out",
        default=None,
        help="repo-relative directory for manifest.json, MANIFEST.sha256, and scenarios/",
    )
    parser.add_argument(
        "--created",
        default=None,
        help="manifest created date; requires --out",
    )
    parser.add_argument(
        "--author",
        default=None,
        help="manifest author; requires --out",
    )
    parser.add_argument("--files", action="append", default=None)
    args = parser.parse_args(argv)
    if args.created is not None or args.author is not None:
        if not args.out:
            print("--created and --author require --out", file=sys.stderr)
            return 2
    if (args.files is None) != (args.out is None):
        if args.files is not None:
            print("--files requires --out", file=sys.stderr)
        else:
            print("--out requires --files", file=sys.stderr)
        return 2
    root = args.root if args.root is not None else repo_root()
    chosen = tuple(args.files) if args.files else None
    escaped = cli_path_problems(root, chosen)
    if args.out is not None:
        escaped = [*escaped, *cli_out_problems(root, args.out)]
    if escaped:
        for item in escaped:
            print(item, file=sys.stderr)
        return 2
    check_heldout = chosen is None
    if args.check:
        problems = check(root, chosen, check_heldout=check_heldout, out=args.out)
        for item in problems:
            print(item, file=sys.stderr)
        return 2 if problems else 0
    if check_heldout:
        problems = heldout_problems(root)
        if problems:
            for item in problems:
                print(item, file=sys.stderr)
            return 2
    digest = write_manifest(
        root,
        chosen,
        check_heldout=False,
        out=args.out,
        created=args.created,
        author=args.author,
    )
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
