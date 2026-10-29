import math
import re
from typing import List, Dict, Any, Tuple

# Token extraction pattern: searches for string literals, assignments, or long credential-like alphanumeric words
CANDIDATE_ASSIGNMENT_PATTERN = re.compile(
    r"""(?i)(?:secret|token|api[_-]?key|password|passwd|auth|access[_-]?key|client[_-]?secret|private[_-]?key|credential)\s*[:=]\s*['"]?([A-Za-z0-9_\-\.\/\+=]{16,128})['"]?"""
)

QUOTED_STRING_PATTERN = re.compile(
    r"""['"]([A-Za-z0-9_\-\.\/\+=]{18,128})['"]"""
)

HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=]+$")


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy (information density) of a string.
    Formula: H = -sum(p * log2(p)) for each distinct character.
    Returns a float value between 0.0 and log2(len(charset)).
    """
    if not data or len(data) < 4:
        return 0.0

    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 3)


def get_entropy_threshold_for_charset(token: str) -> float:
    """
    Adjusts threshold dynamically according to the token's character set.
    Hexadecimal tokens (0-9, a-f) have a theoretical maximum entropy of 4.0.
    Base64 tokens have a theoretical maximum entropy of 6.0.
    """
    if HEX_PATTERN.match(token):
        return 3.2  # Hex string threshold
    elif BASE64_PATTERN.match(token):
        return 4.2  # Base64 string threshold
    else:
        return 3.8  # General alphanumeric threshold


def is_high_entropy(data: str, min_length: int = 16, threshold: float = None) -> bool:
    """
    Determines if a candidate string exhibits high randomness characteristic
    of machine-generated cryptographic keys, passwords, or access tokens.
    """
    if not data or len(data) < min_length:
        return False

    # Filter out obvious repetitive sequences (e.g. "aaaaaaaaaaaaaaaa", "1234567812345678")
    unique_chars = len(set(data))
    if unique_chars < 6:
        return False

    actual_entropy = calculate_shannon_entropy(data)
    target_threshold = threshold if threshold is not None else get_entropy_threshold_for_charset(data)

    return actual_entropy >= target_threshold


def analyze_token_entropy(token: str) -> Dict[str, Any]:
    """
    Analyzes a token and returns comprehensive entropy metadata.
    """
    entropy = calculate_shannon_entropy(token)
    threshold = get_entropy_threshold_for_charset(token)
    is_random = is_high_entropy(token, min_length=16, threshold=threshold)

    return {
        "token": token,
        "length": len(token),
        "entropy": entropy,
        "threshold": threshold,
        "is_high_entropy": is_random
    }


def find_high_entropy_assignments(line: str, line_number: int, file_path: str) -> List[Dict[str, Any]]:
    """
    Extracts high-entropy candidate credentials from variable assignments or suspicious statements.
    Now properly analyzes extracted values rather than entire source lines.
    Only processes actual string literals, not expressions or property references.
    """
    results = []
    
    # Patterns to detect environment variable references and function calls
    env_var_pattern = re.compile(r'process\.env\.[A-Z_]+|os\.environ|os\.getenv|ENV\[|env\.|getenv\(|std::env::', re.IGNORECASE)
    function_call_pattern = re.compile(r'resolve[A-Za-z]*\(|get[A-Za-z]*\(|fetch[A-Za-z]*\(|load[A-Za-z]*\(', re.IGNORECASE)
    
    # Pattern to detect property references (e.g., config.apiKey, provider?.key)
    property_ref_pattern = re.compile(r'\w+\s*[.?]\s*\w+')
    
    # Pattern to detect expressions (++, --, arithmetic, logical operations)
    expression_pattern = re.compile(r'[\+\-\*/%&|^][\+\-\*/%&|^]|[\+\-\*/%]|&&|\|\||===|!==|==|!=')
    
    # Skip lines that are just environment variable references or function calls
    if env_var_pattern.search(line):
        # Don't run entropy on lines like: const apiKey = process.env.OPENAI_API_KEY
        return results
    
    if function_call_pattern.search(line):
        # Don't run entropy on lines like: const apiKey = resolveVideoApiKey(providerId)
        return results
    
    # Skip lines with property references
    if property_ref_pattern.search(line):
        # Don't run entropy on lines like: apiKey: config.apiKey or key: provider?.apiKey
        return results
    
    # Skip lines with expressions
    if expression_pattern.search(line):
        # Don't run entropy on lines like: const token = ++previewTokenRef.current
        return results

    # 1. Check direct key/secret assignments first - extract the actual value
    matches = CANDIDATE_ASSIGNMENT_PATTERN.findall(line)
    for token in matches:
        token = token.strip().strip('\'"')
        
        # Skip if it's a placeholder or common test value
        if token.lower() in ['test', 'dummy', 'fake', 'example', 'sample', 'placeholder', 'changeme', 'your_key', 'undefined', 'null']:
            continue
        
        # Skip if it contains property access or looks like a variable/property name
        if '.' in token or '?' in token or token[0].islower():
            continue
            
        # Only check entropy on the extracted value, not identifiers or property names
        if is_high_entropy(token, min_length=20):  # Increased minimum length for entropy checks
            results.append({
                "rule_id": "ENTROPY-001",
                "title": "High-Entropy Suspicious Credential",
                "secret_type": "High-Entropy Secret",
                "category": "Entropy Analysis",
                "severity": "Medium",
                "confidence": "Medium",
                "detection_method": "Entropy Analysis",
                "file_path": file_path,
                "line_number": line_number,
                "matched_value": token,
                "entropy_score": calculate_shannon_entropy(token),
                "code_snippet": line.strip()[:140],
                "description": f"Variable assignment contains a string with high Shannon entropy ({calculate_shannon_entropy(token):.2f}), indicating a machine-generated secret or key.",
                "remediation": "Verify whether this high-randomness string is an active credential. Externalize to environment variables or secret vaults.",
                "cwe_id": "CWE-798"
            })

    return results
