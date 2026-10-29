import os
import json
import re
from typing import List, Dict, Any, Optional

DEFAULT_PATTERNS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "patterns",
    "secret_patterns.json"
)

# Embedded fallback rules in case patterns file is missing
FALLBACK_RULES = [
    {
        "id": "SEC-KEY-001",
        "name": "RSA Private Key",
        "type": "Private Key",
        "category": "Private Keys",
        "pattern": "-----BEGIN RSA PRIVATE KEY-----",
        "is_regex": False,
        "severity": "Critical",
        "confidence": "High",
        "cwe_id": "CWE-312",
        "description": "Unencrypted RSA private cryptographic key detected in source code.",
        "remediation": "Remove the private key from the codebase, revoke the keypair, and store in a secure vault."
    },
    {
        "id": "SEC-KEY-002",
        "name": "Generic Private Key",
        "type": "Private Key",
        "category": "Private Keys",
        "pattern": r"-----BEGIN (?:DSA|EC|OPENSSH|PGP|ENCRYPTED)? PRIVATE KEY(?: BLOCK)?-----",
        "is_regex": True,
        "severity": "Critical",
        "confidence": "High",
        "cwe_id": "CWE-312",
        "description": "Cryptographic private key detected in source code.",
        "remediation": "Revoke and rotate the exposed private key."
    },
    {
        "id": "SEC-AWS-001",
        "name": "AWS Access Key ID",
        "type": "AWS Credential",
        "category": "Cloud Credentials",
        "pattern": r"(?:^|[^A-Z0-9])((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})(?:[^A-Z0-9]|$)",
        "is_regex": True,
        "severity": "Critical",
        "confidence": "High",
        "cwe_id": "CWE-798",
        "description": "Amazon Web Services (AWS) Access Key ID detected.",
        "remediation": "Deactivate and delete the exposed AWS access key via the AWS IAM Console immediately."
    },
    {
        "id": "SEC-AWS-002",
        "name": "AWS Secret Access Key",
        "type": "AWS Credential",
        "category": "Cloud Credentials",
        "pattern": r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "is_regex": True,
        "severity": "Critical",
        "confidence": "High",
        "cwe_id": "CWE-798",
        "description": "AWS Secret Access Key assignment detected.",
        "remediation": "Rotate the secret access key immediately in AWS IAM."
    },
    {
        "id": "SEC-GH-001",
        "name": "GitHub Personal Access Token",
        "type": "GitHub Token",
        "category": "API Keys & Tokens",
        "pattern": r"(?:gh[pousr]_[a-zA-Z0-9]{36,255}|github_pat_[a-zA-Z0-9_]{60,120})",
        "is_regex": True,
        "severity": "Critical",
        "confidence": "High",
        "cwe_id": "CWE-798",
        "description": "GitHub Personal Access Token or OAuth token detected.",
        "remediation": "Revoke the token immediately from your GitHub Account Settings."
    },
    {
        "id": "SEC-DB-001",
        "name": "Database Connection URI",
        "type": "Database Credential",
        "category": "Database Credentials",
        "pattern": r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[a-zA-Z0-9_\-\.]+:(?:[^@\s/:]+){3,}@[a-zA-Z0-9_\-\.]+",
        "is_regex": True,
        "severity": "Critical",
        "confidence": "High",
        "cwe_id": "CWE-312",
        "description": "Hardcoded database connection string with plaintext credentials detected.",
        "remediation": "Externalize database credentials into secure environment variables."
    },
    {
        "id": "SEC-DB-002",
        "name": "Database Password Assignment",
        "type": "Database Credential",
        "category": "Database Credentials",
        "pattern": r"(?i)(?:DATABASE_URL|DB_PASSWORD|PROD_DB_PASS|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "is_regex": True,
        "severity": "Critical",
        "confidence": "High",
        "cwe_id": "CWE-798",
        "description": "Plaintext database password assignment detected.",
        "remediation": "Store database passwords in environment variables or key vaults."
    },
    {
        "id": "SEC-JWT-001",
        "name": "JSON Web Token (JWT)",
        "type": "JWT Token",
        "category": "Authentication",
        "pattern": r"eyJ[A-Za-z0-9-_=]{10,}\.eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,}",
        "is_regex": True,
        "severity": "Medium",
        "confidence": "High",
        "cwe_id": "CWE-798",
        "description": "Static JSON Web Token (JWT) detected in source code.",
        "remediation": "Avoid hardcoding static tokens in code. Issue tokens dynamically."
    },
    {
        "id": "SEC-PASS-001",
        "name": "Hardcoded Password Assignment",
        "type": "Password Assignment",
        "category": "Credentials",
        "pattern": r"(?i)(?:password|passwd|user_password|admin_password)\s*[:=]\s*['\"]?([^'\"\s]{6,})['\"]?",
        "is_regex": True,
        "severity": "High",
        "confidence": "Medium",
        "cwe_id": "CWE-259",
        "description": "Hardcoded password variable assignment detected in source code.",
        "remediation": "Remove plaintext passwords from code."
    },
    {
        "id": "SEC-GEN-001",
        "name": "Generic API Key / Secret Token",
        "type": "Generic API Key",
        "category": "API Keys & Tokens",
        "pattern": r"(?i)(?:api[_-]?key|auth[_-]?token|client[_-]?secret|access[_-]?token|app[_-]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
        "is_regex": True,
        "severity": "Medium",
        "confidence": "Medium",
        "cwe_id": "CWE-798",
        "description": "Generic hardcoded API key or authorization token pattern detected.",
        "remediation": "Externalize API keys and secret tokens into environment configurations."
    }
]


class PatternDetector:
    """
    Loads pattern specifications and performs regular-expression based scanning.
    """
    def __init__(self, patterns_file: Optional[str] = None):
        self.patterns_file = patterns_file or DEFAULT_PATTERNS_FILE
        self.rules: List[Dict[str, Any]] = []
        self.compiled_rules: List[Dict[str, Any]] = []
        self._load_patterns()

    def _load_patterns(self):
        loaded = False
        if os.path.isfile(self.patterns_file):
            try:
                with open(self.patterns_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.rules = data.get("rules", [])
                    loaded = True
            except Exception:
                loaded = False

        if not loaded or not self.rules:
            self.rules = FALLBACK_RULES

        self.compiled_rules = []
        for r in self.rules:
            pat_str = r.get("pattern", "")
            is_regex = r.get("is_regex", True)
            try:
                if is_regex:
                    compiled = re.compile(pat_str)
                else:
                    compiled = re.compile(re.escape(pat_str))
                self.compiled_rules.append({
                    "meta": r,
                    "compiled": compiled
                })
            except re.error:
                continue

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def scan_content(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        Scans content line-by-line and checks against all compiled regex patterns.
        Now properly extracts candidate values and filters out environment variable
        references and function calls that merely reference secrets.
        """
        findings = []
        lines = content.splitlines()

        # Patterns to detect environment variable references and function calls
        env_var_pattern = re.compile(r'process\.env\.[A-Z_]+|os\.environ|os\.getenv|ENV\[|env\.|getenv\(|std::env::', re.IGNORECASE)
        function_call_pattern = re.compile(r'resolve[A-Za-z]*\(|get[A-Za-z]*\(|fetch[A-Za-z]*\(|load[A-Za-z]*\(', re.IGNORECASE)
        requires_pattern = re.compile(r'requires[A-Z][a-zA-Z]*\s*:', re.IGNORECASE)

        for line_num, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            
            # Skip lines with data URLs (embedded Base64 content like fonts, images)
            if re.search(r'data:(?:font|image|application)/[^;]+;base64,', line_str, re.IGNORECASE):
                continue

            for entry in self.compiled_rules:
                meta = entry["meta"]
                compiled_pat = entry["compiled"]

                match = compiled_pat.search(line)
                if match:
                    # Extract matched value (either group 1 or entire match)
                    matched_val = match.group(1) if match.groups() and match.group(1) else match.group(0)

                    # Filter out environment variable references
                    if env_var_pattern.search(line_str):
                        # Check if the matched value is just a variable name, not an actual credential
                        # Allow through if it's a substantial value (likely an actual secret)
                        if matched_val and (len(matched_val) < 20 or matched_val.isupper()):
                            # Skip short matches or all-caps env var names like "API_KEY"
                            if not re.search(r'[A-Za-z0-9+/=]{32,}', matched_val):
                                continue
                    
                    # Filter out function call references that retrieve keys dynamically
                    if function_call_pattern.search(line_str):
                        # If the entire matched portion is just part of a function call, skip it
                        if '(' in line_str[max(0, match.start()-10):match.end()+5]:
                            continue
                    
                    # Filter out property definitions like "requiresApiKey: true"
                    if requires_pattern.search(line_str):
                        continue
                    
                    # Filter out property references where value is another property access
                    # Example: apiKey: config.apiKey, ttsApiKey: provider?.apiKey
                    property_ref_pattern = re.compile(r':\s*[a-zA-Z_][\w.?]*\.[\w?]+\s*(?:\|\||&&|$)')
                    if property_ref_pattern.search(line_str):
                        # This is a property reference like "apiKey: config.apiKey"
                        continue
                    
                    # Also check for array/bracket notation property access
                    if re.search(r'\[[^\]]+\]', line_str):
                        # Contains array access like config[providerId].apiKey
                        # Check if the matched value is part of this access pattern
                        if matched_val and re.search(r'\[.*' + re.escape(matched_val[:10]), line_str):
                            continue
                    
                    # Filter out cases where matched value is clearly a property access or undefined
                    if matched_val:
                        # Skip if matched value is undefined or null
                        if matched_val.strip() in ['undefined', 'null']:
                            continue
                        
                        # Skip if contains optional chaining (? without ://)
                        if '?' in matched_val and '://' not in matched_val:
                            continue
                        
                        # Skip if this looks like a property access (has dot but not a URL scheme or hostname)
                        # Allow dots if it's a URL (contains ://) or looks like a hostname or JWT
                        if '.' in matched_val and '://' not in matched_val:
                            # Check if it's a JWT (starts with eyJ which is base64 for {"alg")
                            is_jwt = matched_val.startswith('eyJ')
                            
                            # Check if it's not a hostname-like pattern (letters-dots-letters)
                            # Skip only if it looks like JavaScript property access
                            # Allow URLs, hostnames, JWTs, or values with URL-like characters
                            if not is_jwt and not re.match(r'^[a-zA-Z0-9\-\.]+$', matched_val):
                                continue
                        
                        # Skip if this looks like a property name being assigned from another property
                        # Pattern: starts with lowercase identifier followed by dot (but not JWT)
                        # JWT starts with eyJ so exclude it
                        if not matched_val.startswith('eyJ') and re.search(r'^[a-z]\w*\s*\.', matched_val):
                            continue
                        
                        # Skip if matched value looks like a JavaScript/TypeScript property name
                        # (starts with lowercase or contains camelCase pattern without special chars)
                        if matched_val and len(matched_val) > 8:
                            # If it's a simple camelCase word without numbers/special chars, likely a variable name
                            if re.match(r'^[a-z][a-zA-Z]*[A-Z][a-zA-Z]*$', matched_val):
                                continue
                    
                    # Ensure we have an actual value, not just a variable name
                    # Skip if matched value is too short to be a real credential (unless it's a known pattern)
                    if matched_val:
                        val_len = len(matched_val.strip('\'"'))
                        # Exception for specific high-confidence patterns that have strict formats
                        is_strict_pattern = meta.get("id") in [
                            "SEC-AWS-001", "SEC-AWS-002", "SEC-KEY-001", "SEC-KEY-002", 
                            "SEC-KEY-003", "SEC-GH-001", "SEC-GCP-001", "SEC-OAI-001",
                            "SEC-DB-001", "SEC-DB-002"  # Database credentials are strict patterns
                        ]
                        
                        # For generic patterns, require minimum length
                        if not is_strict_pattern and val_len < 8:
                            continue

                    findings.append({
                        "rule_id": meta.get("id", "SEC-001"),
                        "title": meta.get("name", "Secret Detected"),
                        "secret_type": meta.get("type", "Generic Secret"),
                        "category": meta.get("category", "Secrets"),
                        "severity": meta.get("severity", "Medium"),
                        "confidence": meta.get("confidence", "High"),
                        "cwe_id": meta.get("cwe_id", "CWE-798"),
                        "file_path": file_path,
                        "line_number": line_num,
                        "matched_value": matched_val,
                        "code_snippet": line_str[:140],
                        "description": meta.get("description", "Potential secret detected."),
                        "remediation": meta.get("remediation", "Rotate and secure the credential."),
                        "detection_method": "Pattern Match"
                    })
                    # Avoid multiple rule hits on the exact same line for redundancy
                    break

        return findings


_shared_detector: Optional[PatternDetector] = None


def get_pattern_detector() -> PatternDetector:
    global _shared_detector
    if _shared_detector is None:
        _shared_detector = PatternDetector()
    return _shared_detector
