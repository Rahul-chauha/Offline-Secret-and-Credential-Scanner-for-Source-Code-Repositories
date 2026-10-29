import pytest
from scanner.scanner import scan_file_content
from scanner.severity_classifier import calculate_scan_score

def test_regression_placeholders_not_leaked():
    """Test that obvious placeholders are filtered out."""
    content = """
    DATABASE_URL = "postgres://user:...@localhost:5432/app"
    password = "..."
    api_key = "..."
    """
    findings = scan_file_content("config.py", content)
    # They should be ignored as false positives entirely
    assert len(findings) == 0

def test_regression_comments_ignored():
    """Test that credentials in comments are ignored."""
    content = """
    # aws_access_key_id = 'AKIA1234567890ABCDEF'
    // password = "real_password_here"
    /* DATABASE_URL = "postgres://dbuser:productionsecretpassword123@prod-db.internal:5432/app" */
    <!-- API_KEY = "dummy" -->
    """
    findings = scan_file_content("comments.py", content)
    assert len(findings) == 0

def test_regression_test_files_low_confidence():
    """Test that findings in test files get low confidence and severity."""
    content = """
    aws_access_key_id = 'AKIA1234567890ABCDEF'
    DATABASE_URL = "postgres://dbuser:productionsecretpassword123@prod-db.internal:5432/app"
    """
    # If it's a test file, it should be detected but confidence Low
    findings = scan_file_content("tests/test_aws.py", content)
    assert len(findings) > 0
    for f in findings:
        assert f["confidence"] == "Low"
        assert f["severity"] == "Low"

def test_regression_scoring_with_low_confidence():
    """Test that low confidence findings have minimal impact on score."""
    content = """
    # True positive
    aws_access_key_id = 'AKIA1234567890ABCDEF'
    """
    findings_real = scan_file_content("main.py", content)
    score_real, _, _ = calculate_scan_score(findings_real)
    
    # Test context
    findings_test = scan_file_content("tests/test_main.py", content)
    score_test, _, _ = calculate_scan_score(findings_test)
    
    # Test score should be less impacted (higher score) than real score
    assert score_test > score_real
    assert score_test == 100 # Low confidence deductions = 0.0, so score = 100

def test_regression_env_vars():
    """.env.example files should have low confidence."""
    content = "DATABASE_URL=postgres://user:password@prod-db.internal:5432/mydb"
    findings = scan_file_content(".env.example", content)
    # .env.example is a template file, should still report findings but with low confidence
    if len(findings) > 0:  # If detected
        for f in findings:
            assert f["confidence"] == "Low"
    # If not detected, that's also acceptable for this pattern in a template

def test_regression_env_var_references_not_secrets():
    """Environment variable references should not be reported as hardcoded secrets."""
    content = """
    const apiKey = process.env.OPENAI_API_KEY;
    const dbUrl = os.environ.get("DATABASE_URL");
    api_key = os.getenv("API_KEY")
    const token = ENV['AUTH_TOKEN'];
    """
    findings = scan_file_content("config.js", content)
    # Should not report environment variable references as secrets
    assert len(findings) == 0

def test_regression_function_call_retrievals_not_secrets():
    """Function calls that retrieve keys dynamically should not be reported."""
    content = """
    const apiKey = resolveVideoApiKey(providerId);
    apiKey: resolvePDFApiKey(id) || undefined;
    const secret = getSecretFromVault('my-secret');
    token = fetchApiToken(user_id);
    """
    findings = scan_file_content("api.js", content)
    # Function calls that retrieve secrets are not hardcoded secrets
    assert len(findings) == 0

def test_regression_property_flags_not_secrets():
    """Property definitions like 'requiresApiKey: true' should not be flagged."""
    content = """
    requiresApiKey: WEB_SEARCH_PROVIDERS[providerId].requiresApiKey;
    hasSecretKey: provider.hasSecretKey;
    needsAuthentication: true;
    """
    findings = scan_file_content("providers.ts", content)
    # Property flags are not secrets
    assert len(findings) == 0

def test_regression_base64_font_data_not_flagged():
    """Embedded Base64 font data should not be classified as API tokens."""
    # Typical base64 encoded font data (shortened for test)
    content = """
    const fontData = "data:font/woff2;base64,d09GMgABAAAAABEYAA4AAAAAnwwAABDCAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGhYbgWocg14GYACEIgq";
    const imageData = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    """
    findings = scan_file_content("assets.js", content)
    # Should not flag embedded asset data as secrets
    # This may still find some depending on patterns, but confidence should be low or filtered
    for f in findings:
        # If any found, they should be low confidence
        assert f.get("confidence") in ["Low", "Medium"]

def test_regression_real_credential_still_detected():
    """Ensure real-looking hardcoded credentials are still detected in production code."""
    content = """
    aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    DATABASE_URL = "postgres://admin:SuperSecret123@prod-db.example.com:5432/production"
    """
    findings = scan_file_content("production_config.py", content)
    # Should detect at least 2 credentials (AWS secret key and DB URL)
    assert len(findings) >= 2
    # Should have high confidence since it's in production code
    high_conf_findings = [f for f in findings if f["confidence"] == "High"]
    assert len(high_conf_findings) >= 1

def test_regression_placeholder_values_filtered():
    """Common placeholder values should be filtered."""
    content = """
    password = "changeme"
    api_key = "your_api_key_here"
    token = "dummy_token"
    secret = "xxxxxxxxxxxx"
    db_password = "placeholder"
    """
    findings = scan_file_content("config.py", content)
    # All should be filtered as obvious placeholders
    assert len(findings) == 0

def test_regression_mixed_content():
    """Test file with mix of real secrets and false positives."""
    content = """
    # This is fine - environment variable
    api_key = process.env.API_KEY
    
    # This should be flagged - actual hardcoded key
    github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    
    # This is fine - placeholder
    password = "changeme"
    
    # This should be flagged - real-looking secret key
    secret_key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901"
    """
    findings = scan_file_content("app.py", content)
    # Should find at least 2: github_token and secret_key
    assert len(findings) >= 2
    # Should be at least Medium confidence (GitHub and OpenAI patterns)
    for f in findings:
        assert f["confidence"] in ["High", "Medium"]

def test_regression_entropy_not_on_identifiers():
    """Entropy analysis should not flag variable names or identifiers."""
    content = """
    const resolveOpenAIApiKey = (config) => config.openai.key;
    function determineVideoApiKeyProvider(providerId) { return providers[providerId]; }
    let authenticateWithClientSecret = true;
    """
    findings = scan_file_content("utils.js", content)
    # Should not flag identifiers or function names as high-entropy secrets
    assert len(findings) == 0

def test_regression_localhost_credentials_low_severity():
    """Localhost database connections should be marked as low severity."""
    content = """
    DATABASE_URL = "postgres://user:devpassword123@localhost:5432/devdb"
    REDIS_URL = "redis://:localpass@127.0.0.1:6379/0"
    """
    findings = scan_file_content("dev_config.py", content)
    assert len(findings) >= 1
    # All should be low severity due to localhost
    for f in findings:
        assert f["severity"] == "Low"
        assert f["confidence"] == "Low"


# ============================================================================
# NEW REGRESSION TESTS FOR REMAINING ISSUES
# ============================================================================

def test_regression_ci_workflow_localhost_credentials():
    """CI workflow files with localhost credentials should be Low severity/confidence."""
    content = """
    - name: Test Database
      run: |
        POSTGRES_PASSWORD: postgres
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/openmaic
    """
    findings = scan_file_content(".github/workflows/test.yml", content)
    # Should detect the credentials but mark as CI context with Low severity
    assert len(findings) >= 1
    for f in findings:
        assert f["severity"] == "Low"
        assert f["confidence"] == "Low"
        assert f["context"] == "ci"


def test_regression_property_references_not_secrets():
    """Property references like 'apiKey: config.apiKey' should not be flagged."""
    content = """
    apiKey: settingsSnapshot.pdfProvidersConfig[providerId].apiKey
    ttsApiKey: ttsProviderConfig?.apiKey || undefined
    secretKey: provider?.secretKey
    authToken: config.auth?.token
    """
    findings = scan_file_content("config.ts", content)
    # Property references are not hardcoded secrets
    assert len(findings) == 0


def test_regression_entropy_on_expressions():
    """Entropy analysis should not flag expressions and variable references."""
    content = """
    const token = ++previewTokenRef.current;
    requiresApiKey: providerData.requiresApiKey
    accessKeySecret: input.config.accessKeySecret
    const counter = index + offset;
    value = oldValue || newValue;
    """
    findings = scan_file_content("app.ts", content)
    # Expressions and property references should not trigger entropy analysis
    assert len(findings) == 0


def test_regression_base64_font_data_not_twilio():
    """Base64 font data should not be flagged as Twilio API key."""
    content = """
    const katexFont = "data:font/woff2;base64,d09GMgABAAAAABEYAA4AAAAAnwwAABDCAAEAAAAAAAAA";
    const imageData = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAY";
    const pdfData = "data:application/pdf;base64,JVBERi0xLjQKJeLjz9MKMSAwIG9iag";
    """
    findings = scan_file_content("assets.js", content)
    # Should not flag data URLs as API keys
    assert len(findings) == 0


def test_regression_generic_api_key_pattern_too_broad():
    """Generic API key pattern should not match property names without values."""
    content = """
    const config = {
        api_key: getApiKey(),
        auth_token: process.env.AUTH_TOKEN,
        client_secret: await loadSecret('client_secret'),
        access_token: undefined
    };
    """
    findings = scan_file_content("config.js", content)
    # Should not flag property names when values are function calls or env vars
    assert len(findings) == 0


def test_regression_ci_file_detection():
    """Test that various CI/CD files are correctly identified."""
    ci_files = [
        ".github/workflows/ci.yml",
        ".gitlab-ci.yml",
        ".circleci/config.yml",
        ".travis.yml",
        "Jenkinsfile",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml"
    ]
    
    content = """
    DATABASE_URL: postgresql://test:test@localhost:5432/testdb
    """
    
    for ci_file in ci_files:
        findings = scan_file_content(ci_file, content)
        if findings:
            # If found, should be marked as CI context
            for f in findings:
                assert f["context"] == "ci"
                assert f["severity"] == "Low"
                assert f["confidence"] == "Low"


def test_regression_real_production_db_still_detected():
    """Production database credentials should still be detected with high severity."""
    content = """
    DATABASE_URL="postgresql://admin:SuperSecret2024@prod-db.company.com:5432/production"
    """
    findings = scan_file_content("config/production.py", content)
    # Should detect production database credential
    assert len(findings) >= 1
    # Should have high confidence since it's production (not localhost, not CI)
    production_findings = [f for f in findings if "localhost" not in f.get("code_snippet", "").lower()]
    assert len(production_findings) >= 1
    for f in production_findings:
        assert f["context"] == "production"
        assert f["confidence"] == "High"


def test_regression_property_with_literal_value_detected():
    """Property assignments with actual literal values should still be detected."""
    content = """
    api_key: "sk-proj-abc123def456ghi789jkl012mno345pqr678"
    auth_token: "ghp_1234567890abcdefghijklmnopqrstuvwxy"
    """
    findings = scan_file_content("hardcoded_secrets.js", content)
    # Should detect actual hardcoded values
    assert len(findings) >= 2

