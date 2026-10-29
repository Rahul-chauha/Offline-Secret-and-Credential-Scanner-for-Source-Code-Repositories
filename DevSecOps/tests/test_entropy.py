import pytest
from scanner.entropy_analyzer import (
    calculate_shannon_entropy,
    is_high_entropy,
    find_high_entropy_assignments,
    analyze_token_entropy
)


def test_shannon_entropy_identical_chars():
    # Repeated single character has zero entropy
    entropy = calculate_shannon_entropy("aaaaaaaaaaaaaaaa")
    assert entropy == 0.0


def test_shannon_entropy_simple_word():
    # Regular english words have low entropy (< 3.0)
    entropy = calculate_shannon_entropy("password")
    assert entropy < 3.0


def test_shannon_entropy_random_hex():
    # 32-character random hex token (MD5/SHA/API key style)
    hex_token = "4f8a9b2c3d1e7f6a5b4c3d2e1f0a9b8c"
    entropy = calculate_shannon_entropy(hex_token)
    assert entropy >= 3.2
    assert is_high_entropy(hex_token) is True


def test_shannon_entropy_random_base64():
    # Base64 random token
    b64_token = "K9xZb2P8qR1vT4wY7mN0sU3lJ6hF5dA="
    entropy = calculate_shannon_entropy(b64_token)
    assert entropy >= 4.0


def test_short_string_rejected():
    # Strings shorter than min_length (16) should not trigger false alarms
    assert is_high_entropy("abc123") is False
    assert is_high_entropy("") is False


def test_find_high_entropy_assignments():
    line = 'client_secret = "4f8a9b2c3d1e7f6a5b4c3d2e1f0a9b8c"'
    findings = find_high_entropy_assignments(line, line_number=12, file_path="api.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "ENTROPY-001"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["detection_method"] == "Entropy Analysis"
    assert findings[0]["line_number"] == 12


def test_analyze_token_metadata():
    token = "a9b8c7d6e5f40123456789abcdef0123"
    meta = analyze_token_entropy(token)
    assert "entropy" in meta
    assert "threshold" in meta
    assert meta["is_high_entropy"] is True
