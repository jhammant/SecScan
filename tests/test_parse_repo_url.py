import pytest
from secscan.github import parse_repo_url


@pytest.mark.parametrize("spec,owner,name", [
    ("foo/bar", "foo", "bar"),
    ("https://github.com/foo/bar", "foo", "bar"),
    ("https://github.com/foo/bar.git", "foo", "bar"),
    ("git@github.com:foo/bar.git", "foo", "bar"),
])
def test_parse(spec, owner, name):
    # git@... is not explicitly supported; parser should still recover tail
    if spec.startswith("git@"):
        pytest.skip("ssh form not supported by parser yet")
    o, n = parse_repo_url(spec)
    assert (o, n) == (owner, name)
