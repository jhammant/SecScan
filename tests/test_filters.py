from pathlib import Path
import pytest
from secscan.filters import classify, SKIP_DIRS


def test_skips_lockfile(tmp_path: Path):
    f = tmp_path / "package-lock.json"
    f.write_text("{}")
    assert not classify(f, tmp_path).include


def test_skips_node_modules(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    f = tmp_path / "node_modules" / "a.js"
    f.parent.mkdir(exist_ok=True)
    f.write_text("x")
    assert not classify(f, tmp_path).include


def test_includes_python(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("print('hi')\n")
    assert classify(f, tmp_path).include


def test_skips_binary(tmp_path: Path):
    f = tmp_path / "blob.py"
    f.write_bytes(b"\x00\x01\x02\x03" * 50)
    assert not classify(f, tmp_path).include
