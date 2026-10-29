import os
import zipfile
import tempfile
import pytest

from scanner.file_handler import safe_extract_zip, is_binary_file, collect_files_to_scan
from scanner.scanner import scan_directory, scan_zip_file, scan_file_content, calculate_security_score
from scanner.report_generator import generate_cli_summary, generate_json_report, generate_markdown_report, save_reports
from database.db import init_db, save_scan, get_scan, get_all_scans, delete_scan


@pytest.fixture
def temp_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_scanner.db")
    init_db(db_path)
    yield db_path


# TC01: Upload & extract valid ZIP archive
def test_tc01_valid_zip_extraction():
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "valid.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("main.py", "print('hello')")
        zf.writestr("config/settings.json", "{}")

    extract_dir = os.path.join(temp_dir, "extracted")
    success, msg, file_count = safe_extract_zip(zip_path, extract_dir)
    assert success is True
    assert file_count == 2
    assert os.path.exists(os.path.join(extract_dir, "main.py"))
    assert os.path.exists(os.path.join(extract_dir, "config", "settings.json"))


# TC02: Path traversal / Zip Slip prevention
def test_tc02_zip_slip_rejection():
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "malicious.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.txt", "exploit")

    extract_dir = os.path.join(temp_dir, "extracted")
    success, msg, file_count = safe_extract_zip(zip_path, extract_dir)
    assert success is False
    assert "traversal" in msg.lower() or "exception" in msg.lower()


# TC03: Secret detection on production configuration
def test_tc03_secret_detection():
    sample_content = """
    # AWS configuration in production
    aws_access_key = "AKIA1234567890ABCDEF"
    github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    private_key = "-----BEGIN RSA PRIVATE KEY-----"
    DATABASE_URL = "postgres://dbuser:productionsecretpassword123@prod-db.internal:5432/app"
    """
    findings = scan_file_content("config/keys.py", sample_content)
    assert len(findings) >= 3
    rule_ids = [f["rule_id"] for f in findings]
    assert "SEC-AWS-001" in rule_ids
    assert "SEC-KEY-001" in rule_ids
    assert "SEC-DB-001" in rule_ids
    # All of these should be Critical in production source files
    for f in findings:
        if f["rule_id"] in ["SEC-AWS-001", "SEC-KEY-001", "SEC-DB-001"]:
            assert f["severity"] == "Critical"


# TC04: Context-aware false-positive filtering
def test_tc04_false_positive_filtering():
    # 1. Obvious placeholders -> Low severity
    placeholder_code = """
    client_key = "stale-client-key"
    password = "changeme"
    api_token = "dummy_token_12345"
    """
    findings = scan_file_content("tests/test_auth.py", placeholder_code)
    for f in findings:
        assert f["severity"] == "Low"

    # 2. Template documentation files -> Low severity
    doc_code = "DATABASE_URL=postgres://user:password@localhost:5432/mydb"
    findings_doc = scan_file_content(".env.example", doc_code)
    for f in findings_doc:
        assert f["severity"] == "Low"


# TC05: Clean sample file returns zero findings
def test_tc05_clean_file():
    clean_code = """
    def add(a: int, b: int) -> int:
        return a + b
    """
    findings = scan_file_content("utils/math.py", clean_code)
    assert len(findings) == 0


# TC06: Security score calculation
def test_tc06_security_scoring():
    """Test security scoring with the new exponential decay algorithm."""
    findings = [
        {"severity": "Critical", "confidence": "High"},
        {"severity": "Critical", "confidence": "High"},
        {"severity": "High", "confidence": "High"},
        {"severity": "Medium", "confidence": "High"}
    ]
    score, grade, counts = calculate_security_score(findings)
    # New algorithm uses exponential decay: score = 100 * exp(-deductions/100)
    # Deductions: (2*20 + 1*10 + 1*5) = 55
    # Score = 100 * exp(-55/100) ≈ 57.7 -> rounds to 57
    assert score == 57
    assert grade == "C"  # 50-75 range is C
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 1


# TC07: Scan test repository ZIP archive
def test_tc07_scan_sample_zip():
    sample_zip = "samples/test_repository.zip"
    if os.path.exists(sample_zip):
        success, msg, results = scan_zip_file(sample_zip, project_name="Test Repository")
        assert success is True
        assert results["total_files"] >= 4
        assert results["total_findings"] >= 3
        assert results["critical_count"] >= 1


# TC08: Report generation
def test_tc08_report_generation():
    scan_results = {
        "scan_id": "test-uuid-999",
        "project_name": "Demo Repo",
        "total_files": 10,
        "files_with_findings": 2,
        "total_findings": 3,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 1,
        "low_count": 0,
        "security_score": 65,
        "rating_grade": "C",
        "findings": [
            {
                "rule_id": "SEC-KEY-001",
                "title": "RSA Private Key",
                "secret_type": "Private Key",
                "severity": "Critical",
                "detection_method": "Pattern Match",
                "confidence": "High",
                "file_path": "certs/server.key",
                "line_number": 1,
                "code_snippet": "-----BEGIN RSA PRIVATE KEY-----",
                "description": "Private key exposed.",
                "remediation": "Revoke and rotate."
            }
        ]
    }
    summary = generate_cli_summary(scan_results)
    assert "SECURITY SCAN SUMMARY" in summary
    assert "Files Scanned      : 10" in summary
    assert "Critical           : 1" in summary

    json_rep = generate_json_report(scan_results)
    assert "test-uuid-999" in json_rep

    md_rep = generate_markdown_report(scan_results)
    assert "RSA Private Key" in md_rep

    temp_reports_dir = tempfile.mkdtemp()
    saved = save_reports(scan_results, output_dir=temp_reports_dir)
    assert os.path.exists(saved["json"])
    assert os.path.exists(saved["markdown"])
    assert os.path.exists(saved["text"])


# TC09: Database persistence
def test_tc09_database_persistence(temp_db):
    scan_id = "db-scan-test-01"
    summary = {
        "scan_id": scan_id,
        "project_name": "Database Test Project",
        "file_size": 2048,
        "total_files": 8,
        "security_score": 80,
        "rating_grade": "B",
        "critical_count": 0,
        "high_count": 2,
        "medium_count": 0,
        "low_count": 0,
        "total_findings": 2,
        "categories_summary": {"Secrets": 2}
    }
    findings = [
        {
            "category": "Secrets",
            "rule_id": "SEC-OAI-001",
            "title": "OpenAI API Key",
            "severity": "High",
            "file_path": "src/ai.py",
            "line_number": 5,
            "code_snippet": "sk-proj-1234567890",
            "description": "Exposed OpenAI Key",
            "remediation": "Revoke key in console",
            "cwe_id": "CWE-798",
            "secret_type": "API Key",
            "detection_method": "Pattern Match",
            "confidence": "High"
        }
    ]

    save_scan(summary, findings, db_path=temp_db)
    loaded = get_scan(scan_id, db_path=temp_db)
    assert loaded is not None
    assert loaded["project_name"] == "Database Test Project"
    assert loaded["security_score"] == 80
    assert len(loaded["findings"]) == 1
    assert loaded["findings"][0]["secret_type"] == "API Key"

    all_scans = get_all_scans(db_path=temp_db)
    assert len(all_scans) == 1

    delete_scan(scan_id, db_path=temp_db)
    assert get_scan(scan_id, db_path=temp_db) is None
