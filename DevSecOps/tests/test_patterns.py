import pytest
from scanner.pattern_detector import PatternDetector


@pytest.fixture
def detector():
    return PatternDetector()


def test_rsa_private_key_detection(detector):
    content = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y1+dummydata
    -----END RSA PRIVATE KEY-----
    """
    findings = detector.scan_content("certs/server.key", content)
    assert len(findings) >= 1
    assert any(f["rule_id"] == "SEC-KEY-001" for f in findings)
    assert any(f["severity"] == "Critical" for f in findings)


def test_aws_access_key_detection(detector):
    content = """
    aws_access_key_id = 'AKIA1234567890ABCDEF'
    aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    """
    findings = detector.scan_content("config.py", content)
    rule_ids = [f["rule_id"] for f in findings]
    assert "SEC-AWS-001" in rule_ids
    assert "SEC-AWS-002" in rule_ids


def test_github_token_detection(detector):
    classic_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    fine_grained = "github_pat_11AAAAAAA01234567890abcdefghijklmnopqrstuvwxyz_abcdefghijklmnopqrstuvwxyz12345678"
    content = f"GH_TOKEN = '{classic_token}'\nPAT = '{fine_grained}'"
    findings = detector.scan_content("deploy.py", content)
    assert len(findings) >= 2
    assert all(f["rule_id"] == "SEC-GH-001" for f in findings)


def test_database_uri_detection(detector):
    content = """
    DATABASE_URL = "postgres://appuser:SecretPassword123@prod-db.internal:5432/app"
    MONGO_URI = "mongodb+srv://admin:pass456@cluster0.mongodb.net/test"
    """
    findings = detector.scan_content("settings.py", content)
    assert len(findings) >= 2
    assert all(f["rule_id"] == "SEC-DB-001" for f in findings)


def test_openai_api_key_detection(detector):
    content = "OPENAI_KEY = 'sk-proj-abc1234567890abcdefghijklmnopqrstuvwxyz123456'"
    findings = detector.scan_content("ai.py", content)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-OAI-001"


def test_jwt_token_detection(detector):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    content = f"auth_header = 'Bearer {jwt}'"
    findings = detector.scan_content("auth.py", content)
    assert len(findings) >= 1
    assert any(f["rule_id"] == "SEC-JWT-001" for f in findings)


def test_clean_content_no_false_alerts(detector):
    clean = """
    def calculate_total(items):
        total = sum(i.price for i in items)
        return total
    """
    findings = detector.scan_content("cart.py", clean)
    assert len(findings) == 0
