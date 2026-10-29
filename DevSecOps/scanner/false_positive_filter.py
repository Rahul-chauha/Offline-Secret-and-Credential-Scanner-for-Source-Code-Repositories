import os
import re
from typing import Tuple, List, Set

# Exact placeholder values (checked against stripped value)
KNOWN_EXACT_PLACEHOLDERS: Set[str] = {
    "password", "admin", "123456", "secret", "changeme", "change_me",
    "placeholder", "dummy", "fake", "test", "sample", "example",
    "demo", "none", "null", "root", "qwerty", "password123", "...",
    "undefined", "xxx", "xxxxxx"
}

# Substrings that uniquely indicate a placeholder or sample
SPECIFIC_PLACEHOLDER_SUBSTRINGS: List[str] = [
    "stale-client-key", "your_key", "your-key", "your_api", "your-api",
    "your_token", "your_secret", "your_password", "replace_me", "replace-me",
    "dummy_token", "fake_token", "sample_key", "sample_token", "test_key",
    "test_token", "xxxx", "akiaiosfodnn7example", "openmaic-dev", "local-dev",
    "example.com", "example_", "_example", "test_secret", "mock_", "_mock"
]

# Regex to detect bracketed or templated variables (e.g., <YOUR_KEY>, ${API_TOKEN}, {{secret}})
TEMPLATE_EXPRESSION_PATTERN = re.compile(
    r"""(?:<[^>]{3,}>|\$\{[^}]{2,}\}|\{\{[^}]{2,}\}|%\{[^}]{2,}\}@|YOUR_[A-Z0-9_]+|INSERT_[A-Z0-9_]+|ENTER_[A-Z0-9_]+)"""
)

# Regex to detect placeholder assignments (e.g. password="changeme", api_key="dummy")
PLACEHOLDER_ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)(?:password|passwd|api_key|secret|token|auth|access_key|client_key)\s*[:=]\s*['"]?(?:test|dummy|fake|example|sample|placeholder|changeme|admin|123456|password|stale-client-key|your[-_]?key(?:[-_]here)?|your[-_]?api[-_]?key|replace[-_]?me|xxxx+|none|null|undefined|<[^>]+>)['"]?"""
)

# Environment variable reference patterns
ENV_VAR_REFERENCE_PATTERN = re.compile(
    r"""(?:process\.env\.[A-Z_]+|os\.environ|os\.getenv\(['"]\w+['"]\)|ENV\[['"]\w+['"]\]|env\.\w+|getenv\(['"]\w+['"]\)|std::env::var|System\.getenv)""",
    re.IGNORECASE
)

# Function call patterns that retrieve secrets dynamically
DYNAMIC_SECRET_RETRIEVAL_PATTERN = re.compile(
    r"""(?:resolve\w*\(|get\w*\(|fetch\w*\(|load\w*\(|retrieve\w*\()[^)]*\)""",
    re.IGNORECASE
)

# Documentation and template filename regexes
DOC_AND_TEMPLATE_PATTERNS = [
    re.compile(r"(?i)(?:\.env\.example|\.env\.sample|\.env\.template|\.env\.dist|\.env\.default|\.env\.test|\.example\.env|\.sample\.env)$"),
    re.compile(r"(?i)(?:example\.env|sample\.env|template\.env|mock\.env)$"),
    re.compile(r"(?i)(?:config\.example\.|config\.sample\.|settings\.example\.|settings\.sample\.)"),
    re.compile(r"(?i)\.(?:example|sample|template|dist|stub|mock)$"),
    re.compile(r"(?i)(?:readme|changelog|contributing|license)(?:\.[a-z]+)?$"),
    re.compile(r"(?i)\.(?:md|markdown|rst|txt)$")
]

# Test, Mock, Fixtures, and Sample path patterns
TEST_PATH_PATTERNS = [
    re.compile(r"(?:^|[\\/])(?:tests?|testing|__tests__|specs?|mocks?|fixtures?|samples?|examples?)(?:[\\/]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])(?:test_[^\\/]+\.py|[^\\/]+_test\.py|[^\\/]+\.test\.[a-z]+|[^\\/]+\.spec\.[a-z]+)$", re.IGNORECASE)
]

# CI/CD and workflow path patterns
CI_PATH_PATTERNS = [
    re.compile(r"(?:^|[\\/])\.github[\\/]workflows[\\/]", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])\.gitlab-ci\.yml$", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])\.circleci[\\/]", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])\.travis\.yml$", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])jenkinsfile$", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])azure-pipelines\.yml$", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])bitbucket-pipelines\.yml$", re.IGNORECASE),
]

LOCAL_DEV_HOST_PATTERN = re.compile(
    r"(?:@|://)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|postgres|mysql|db|redis|mongo|sqlite|shared-provider-test|[a-zA-Z0-9._-]*test[a-zA-Z0-9._-]*)(?::\d+|/|$)",
    re.IGNORECASE
)


def is_placeholder(line: str, matched_value: str = "") -> bool:
    """
    Checks if a candidate secret or assignment line is an obvious placeholder.
    Now more precise by checking the extracted value separately from the line context.
    """
    line_clean = line.strip()
    if line_clean.startswith("#") or line_clean.startswith("//") or line_clean.startswith("/*") or line_clean.startswith("<!--"):
        return True

    # Check if the line is just an environment variable reference
    if ENV_VAR_REFERENCE_PATTERN.search(line):
        return True
    
    # Check if the line is just a function call retrieving a secret
    if DYNAMIC_SECRET_RETRIEVAL_PATTERN.search(line):
        # If no actual string literal is present, it's just a reference
        if not re.search(r'["\'][^"\']{8,}["\']', line):
            return True

    if matched_value:
        clean_val = matched_value.strip().strip("'\"").lower()
        
        # Check exact placeholders
        if clean_val in KNOWN_EXACT_PLACEHOLDERS:
            return True
            
        # Check template expressions in the value itself
        if TEMPLATE_EXPRESSION_PATTERN.search(matched_value):
            return True
            
        # Check specific placeholder substrings in the value
        # Be careful not to filter real hostnames
        for sub in SPECIFIC_PLACEHOLDER_SUBSTRINGS:
            # Skip 'example.com' check for URLs (they might use example domains but have real passwords)
            if sub == 'example.com' and '://' in matched_value:
                continue
            # Skip generic substrings for URLs with credentials
            if sub in ['example_', '_example'] and '://' in matched_value:
                continue
            if sub in clean_val:
                return True
                
        # Check for ellipsis patterns
        if "..." in clean_val or "://..." in clean_val or ":..." in clean_val:
            return True

    # Check placeholder assignment patterns in the full line
    if PLACEHOLDER_ASSIGNMENT_PATTERN.search(line):
        return True

    # Check for specific placeholder substrings in the line (only if no real value extracted)
    if not matched_value or len(matched_value.strip('\'"')) < 8:
        line_lower = line.lower()
        for sub in SPECIFIC_PLACEHOLDER_SUBSTRINGS:
            if sub in line_lower:
                return True

    if TEMPLATE_EXPRESSION_PATTERN.search(line):
        return True

    return False


def is_doc_or_template_file(file_path: str) -> bool:
    """
    Checks if a file path belongs to documentation or template configuration.
    """
    norm = file_path.replace("\\", "/").lower()
    filename = os.path.basename(norm)

    for p in DOC_AND_TEMPLATE_PATTERNS:
        if p.search(filename) or p.search(norm):
            return True

    return False


def is_test_file(file_path: str) -> bool:
    """
    Checks if a file resides in test, fixture, mock, or sample directories.
    """
    norm = file_path.replace("\\", "/").lower()
    for p in TEST_PATH_PATTERNS:
        if p.search(norm):
            return True
    return False


def is_ci_file(file_path: str) -> bool:
    """
    Checks if a file is a CI/CD workflow configuration.
    """
    norm = file_path.replace("\\", "/").lower()
    for p in CI_PATH_PATTERNS:
        if p.search(norm):
            return True
    return False


def is_local_dev_uri(text: str) -> bool:
    """
    Checks if a database connection URL points to a local loopback/docker host.
    Only returns True if it's clearly a local development environment.
    """
    # Check if it explicitly contains localhost or loopback addresses
    if not LOCAL_DEV_HOST_PATTERN.search(text):
        return False
    
    # Additional check: make sure it's actually in a connection string format
    # Don't filter it if it's just mentioned in a comment or description
    if re.search(r'(?:postgres|mysql|mongodb|redis|mssql)://', text, re.IGNORECASE):
        return True
    
    return False


def evaluate_finding(
    file_path: str,
    line: str,
    matched_value: str = ""
) -> Tuple[bool, str, str]:
    """
    Evaluates a candidate finding against false-positive filtering rules.
    Returns:
        (is_false_positive: bool, context_type: str, reason: str)
        context_type is one of: "production", "placeholder", "template", "test", "ci", "local_dev"
    """
    line_clean = line.strip()

    # 1. Obvious placeholder words or template bracket sequences
    if is_placeholder(line_clean, matched_value):
        return True, "placeholder", "Identified as a placeholder or template example credential."

    # 2. Local development service credentials (@localhost, @127.0.0.1)
    # Report these but with context indicating they're local dev
    if is_local_dev_uri(line_clean) or is_local_dev_uri(matched_value):
        return False, "local_dev", "Local development or test environment host connection."

    # 3. Documentation and example templates (.env.example, README.md, docs)
    if is_doc_or_template_file(file_path):
        return False, "template", "Found in documentation or configuration template."

    # 4. CI/CD workflow configurations (GitHub Actions, GitLab CI, etc.)
    if is_ci_file(file_path):
        # Check if it's also a localhost/test credential
        if is_local_dev_uri(line_clean) or is_local_dev_uri(matched_value):
            return False, "ci", "Found in CI/CD workflow with localhost/test database."
        # If it's a CI file but not localhost, report as CI context
        return False, "ci", "Found in CI/CD workflow configuration."

    # 5. Test code or mock fixtures
    if is_test_file(file_path):
        return False, "test", "Found in test suite, sample, or mock fixture."

    # 6. Production code
    return False, "production", "Found in production application code or live configuration."
