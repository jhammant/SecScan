from pathlib import Path
from secscan.deps import _parse_python, _parse_npm


def test_parse_requirements(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask>=2.0\n# comment\n")
    deps = _parse_python(tmp_path)
    names = {d.name for d in deps}
    assert "requests" in names and "flask" in names


def test_parse_package_json(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies":{"lodash":"4.17.20"}}')
    deps = _parse_npm(tmp_path)
    assert any(d.name == "lodash" and d.version == "4.17.20" for d in deps)
