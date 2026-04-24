from pathlib import Path
from secscan.secrets_scan import scan_secrets


def test_detects_aws_key(tmp_path: Path):
    (tmp_path / "app.py").write_text('AWS = "AKIAABCDEFGHIJKLMNOP"\n')
    findings = scan_secrets(tmp_path)
    assert any("AWS" in f.title for f in findings)


def test_detects_pem_key(tmp_path: Path):
    (tmp_path / "key.py").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEogI...\n-----END RSA PRIVATE KEY-----\n"
    )
    findings = scan_secrets(tmp_path)
    assert any("Private key" in f.title for f in findings)


def test_ignores_low_entropy(tmp_path: Path):
    (tmp_path / "app.py").write_text('password = "aaaaaaaa"\n')
    findings = scan_secrets(tmp_path)
    assert not any(f.category == "Hardcoded Secret" and "password" in f.title.lower() for f in findings)
