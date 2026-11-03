import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_demo_catches_the_false_done_claim():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "demo" / "run_demo.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1, completed.stderr
    assert "FAIL  logs-bucket" in completed.stdout
    assert "block_public_policy is false; expected true" in completed.stdout
    assert "untrusted, ignored" in completed.stdout
    assert "bundle_sha256:" in completed.stdout
