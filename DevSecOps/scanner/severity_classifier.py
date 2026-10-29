import math
from typing import List, Dict, Any, Tuple


def classify_severity_and_confidence(finding: Dict[str, Any], context_type: str, is_fp: bool = False, reason: str = "") -> Dict[str, Any]:
    """
    Adjusts finding severity, confidence, and titles based on the source code context.
    Now ensures consistent severity and confidence logic as per documentation.

    Context Types:
      - "placeholder": Obvious dummy, placeholder, or template string -> Filtered out (should not reach report).
      - "template": Found in .env.example, README.md, docs -> Low severity, Low confidence.
      - "test": Found in test suite, sample, or mock fixtures -> Low severity, Low confidence (capped at Low as documented).
      - "local_dev": Points to localhost / 127.0.0.1 -> Low severity, Low confidence.
      - "production": Production source code or production configuration -> Original severity preserved.
    """
    result = dict(finding)
    original_severity = finding.get("severity", "Medium")
    original_confidence = finding.get("confidence", "High")
    
    result["context"] = context_type
    result["reason"] = reason
    result["is_false_positive"] = is_fp

    if context_type == "placeholder":
        # Placeholders should ideally be filtered before reaching classification
        result["severity"] = "Low"
        result["confidence"] = "Low"
        result["title"] = f"Placeholder / Test Credential: {finding.get('title', 'Secret')}"
        result["description"] = "Obvious placeholder or sample dummy credential detected. Does not pose direct production risk."
        result["remediation"] = "Ensure test placeholders are replaced with secure secret injection when deploying to staging or production."

    elif context_type == "template":
        # Documentation and template files always get Low severity and confidence
        result["severity"] = "Low"
        result["confidence"] = "Low"
        result["title"] = f"Documentation Sample: {finding.get('title', 'Secret')}"
        result["description"] = "Detected in documentation or template configuration. Example files do not represent leaked production secrets."
        result["remediation"] = "Verify this is purely an example template and does not contain live production secrets."

    elif context_type == "local_dev":
        # Local development credentials get Low severity and confidence
        result["severity"] = "Low"
        result["confidence"] = "Low"
        result["title"] = f"Local Development Credential: {finding.get('title', 'Secret')}"
        result["description"] = "Connection string points to a local development or loopback service (e.g. localhost, 127.0.0.1)."
        result["remediation"] = "Ensure production environments do not rely on hardcoded local configuration values."

    elif context_type == "test":
        # Test context: As documented, cap severity at Low and set confidence to Low
        # Test fixtures should be synthetic, but we still report them for review
        result["severity"] = "Low"
        result["confidence"] = "Low"
        result["title"] = f"Test Context: {finding.get('title', 'Secret')}"
        result["description"] = f"Potential credential identified inside a test/mock file. Test suites should use synthetic mock fixtures rather than real-looking credentials."
        result["remediation"] = "Replace with clearly synthetic mock fixtures or load test credentials via environment secrets."

    elif context_type == "ci":
        # CI/CD workflow configurations - typically test/localhost credentials
        result["severity"] = "Low"
        result["confidence"] = "Low"
        result["title"] = f"CI/CD Workflow: {finding.get('title', 'Secret')}"
        result["description"] = "Detected in CI/CD workflow configuration. These are typically test database credentials for automated testing environments (e.g., postgres@localhost). Verify this is not a production credential."
        result["remediation"] = "Ensure CI workflows use test-only credentials and do not expose production secrets. Consider using GitHub Secrets or equivalent secret management for any sensitive values."

    else:
        # Production context: maintain original severity and confidence
        # This is real application code with no mitigating context
        result["severity"] = original_severity
        result["confidence"] = original_confidence
        
        # Keep original description and remediation for production findings
        # The title remains as-is since this is a genuine finding

    return result


def calculate_scan_score(findings: List[Dict[str, Any]]) -> Tuple[int, str, Dict[str, int]]:
    """
    Computes standard security posture score (0 - 100) and letter rating (A - F).
    Starting score = 100.
    Deductions:
      - Critical: -20
      - High:     -10
      - Medium:   -5
      - Low:      -2
    Modifiers based on confidence:
      - High confidence: 100% deduction
      - Medium confidence: 50% deduction
      - Low confidence: 0% deduction
    """
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": len(findings)
    }

    deductions = 0.0
    for f in findings:
        sev = f.get("severity", "Low")
        conf = f.get("confidence", "High")
        
        counts[sev.lower()] = counts.get(sev.lower(), 0) + 1
        
        base_weight = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2}.get(sev, 0)
        
        if conf == "Low":
            weight = 0.0
        elif conf == "Medium":
            weight = base_weight * 0.5
        else:
            weight = float(base_weight)
            
        deductions += weight

    # Calculate score using exponential decay to prevent bottoming out at zero
    score = max(0, min(100, int(100 * math.exp(-deductions / 100.0))))

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return score, grade, counts
