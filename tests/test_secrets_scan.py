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


def test_skips_simulator_fixture_path(tmp_path: Path):
    # Chia-style: chia/simulator/ssl_certs_5.py contains real-looking PEMs but
    # they're known public test material. These must not be reported.
    sim = tmp_path / "chia" / "simulator"
    sim.mkdir(parents=True)
    (sim / "ssl_certs_5.py").write_text(
        "CERT = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEogI...\n-----END RSA PRIVATE KEY-----'''\n"
    )
    findings = scan_secrets(tmp_path)
    assert not findings, f"expected no findings in simulator fixture path, got {len(findings)}"


def test_skips_filename_fixture_pattern(tmp_path: Path):
    # Even outside /simulator/, a file literally named test_certs.py is a fixture.
    (tmp_path / "test_certs.py").write_text(
        "KEY = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEogI...\n-----END RSA PRIVATE KEY-----'''\n"
    )
    findings = scan_secrets(tmp_path)
    assert not findings


def test_still_detects_pem_in_production_path(tmp_path: Path):
    # The filter must not be too broad — a PEM in /src/ or /app/ still fires.
    src = tmp_path / "src"
    src.mkdir()
    (src / "keys.py").write_text(
        "REAL_KEY = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEogI...\n-----END RSA PRIVATE KEY-----'''\n"
    )
    findings = scan_secrets(tmp_path)
    assert findings, "PEM outside fixture paths must still be flagged"
