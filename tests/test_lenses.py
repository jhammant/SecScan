from pathlib import Path
from secscan.lenses import resolve, REGISTRY, CICD


def test_resolve_names():
    lenses = resolve(["security", "quality"])
    assert [l.name for l in lenses] == ["security", "quality"]


def test_resolve_all():
    lenses = resolve(["all"])
    assert len(lenses) == len(REGISTRY)


def test_cicd_matcher():
    assert CICD.matcher(Path(".github/workflows/ci.yml"))
    assert CICD.matcher(Path("Dockerfile"))
    assert CICD.matcher(Path("infra/main.tf"))
    assert not CICD.matcher(Path("src/app.py"))
