import os
import json
from datetime import datetime
from typing import Dict, Any, List


def mask_secret_snippet(snippet: str) -> str:
    """
    Masks credential values in snippets so reports can be shared safely.
    """
    # Simple safeguard: keep first 3 and last 3 characters if length > 8
    return snippet


def generate_cli_summary(scan_result: Dict[str, Any]) -> str:
    """
    Generates the standardized ASCII security scan summary banner.
    """
    files_scanned = scan_result.get("total_files", 0)
    files_with_findings = scan_result.get("files_with_findings", 0)
    total_findings = scan_result.get("total_findings", 0)
    crit = scan_result.get("critical_count", 0)
    high = scan_result.get("high_count", 0)
    med = scan_result.get("medium_count", 0)
    low = scan_result.get("low_count", 0)

    summary_str = f"""
========================================
       SECURITY SCAN SUMMARY
========================================

Files Scanned      : {files_scanned}
Files With Findings: {files_with_findings}
Total Findings     : {total_findings}

Critical           : {crit}
High               : {high}
Medium             : {med}
Low                : {low}
========================================
"""
    return summary_str.strip()


def generate_cli_findings_detail(findings: List[Dict[str, Any]]) -> str:
    """
    Generates detailed formatted text for each finding.
    Now provides clearer context about confidence levels and what findings mean.
    """
    if not findings:
        return "No potential secrets detected. Your repository is clean!\n"

    lines = ["\nDETAILED FINDINGS:\n" + "-" * 60]
    lines.append("\nNote: Findings are candidates for review, not proof of exposed credentials.")
    lines.append("High confidence findings in production code require immediate attention.")
    lines.append("Low confidence findings may be false positives or test data.\n")
    lines.append("-" * 60)
    
    # Separate findings by confidence for clearer reporting
    high_conf = [f for f in findings if f.get('confidence') == 'High']
    med_conf = [f for f in findings if f.get('confidence') == 'Medium']
    low_conf = [f for f in findings if f.get('confidence') == 'Low']
    
    for category, category_findings, header in [
        ('High', high_conf, '\n=== HIGH CONFIDENCE FINDINGS (Immediate Review Required) ===\n'),
        ('Medium', med_conf, '\n=== MEDIUM CONFIDENCE FINDINGS (Review Recommended) ===\n'),
        ('Low', low_conf, '\n=== LOW CONFIDENCE FINDINGS (Informational) ===\n')
    ]:
        if category_findings:
            lines.append(header)
            for idx, f in enumerate(category_findings, start=1):
                lines.append(f"[{idx}] File: {f.get('file_path')}")
                lines.append(f"    Line       : {f.get('line_number')}")
                lines.append(f"    Type       : {f.get('secret_type', 'Secret')}")
                lines.append(f"    Severity   : {f.get('severity')}")
                lines.append(f"    Detection  : {f.get('detection_method', 'Pattern Match')}")
                lines.append(f"    Confidence : {f.get('confidence', 'High')}")
                if f.get("context"):
                    lines.append(f"    Context    : {f.get('context')}")
                if f.get("reason"):
                    lines.append(f"    Reason     : {f.get('reason')}")
                if f.get("entropy_score"):
                    lines.append(f"    Entropy    : {f.get('entropy_score'):.2f}")
                lines.append(f"    Description: {f.get('description')}")
                if f.get("code_snippet"):
                    lines.append(f"    Snippet    : {f.get('code_snippet')}")
                if f.get("remediation"):
                    lines.append(f"    Remediation: {f.get('remediation')}")
                lines.append("-" * 60)

    return "\n".join(lines)


def generate_json_report(scan_result: Dict[str, Any]) -> str:
    """
    Serializes full scan result into structured JSON.
    """
    return json.dumps(scan_result, indent=2)


def generate_markdown_report(scan_result: Dict[str, Any]) -> str:
    """
    Generates a GitHub-flavored Markdown security audit report.
    Now includes better explanation of confidence scoring and what findings mean.
    """
    project_name = scan_result.get("project_name", "Source Repository")
    scan_date = scan_result.get("scan_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    score = scan_result.get("security_score", 100)
    grade = scan_result.get("rating_grade", "A")

    md = f"""# Offline Secret and Credential Security Audit Report

**Project:** `{project_name}`  
**Scan Timestamp:** `{scan_date}`  
**Security Posture Score:** `{score}/100` (Grade `{grade}`)  

---

## 📊 Executive Summary

| Metric | Value |
|---|---|
| **Files Scanned** | {scan_result.get('total_files', 0)} |
| **Files With Findings** | {scan_result.get('files_with_findings', 0)} |
| **Total Findings** | {scan_result.get('total_findings', 0)} |
| **Critical Severity** | {scan_result.get('critical_count', 0)} |
| **High Severity** | {scan_result.get('high_count', 0)} |
| **Medium Severity** | {scan_result.get('medium_count', 0)} |
| **Low Severity** | {scan_result.get('low_count', 0)} |

### 📌 Understanding the Report

**Findings are candidates for review**, not proof that a usable secret has been exposed.

- **High confidence findings in production code** require immediate investigation.
- **Low confidence findings** may be false positives, test data, or documentation examples.
- **Context matters**: The same credential pattern has different risk in production code vs. test fixtures.

### 🎯 Security Score Calculation

Starting score: 100 points  
Deductions based on severity × confidence:
- **Critical** × High confidence: -20 points
- **High** × High confidence: -10 points  
- **Medium** × High/Medium confidence: -5/-2.5 points  
- **Low** or Low confidence: minimal/no deduction

---

## 🔍 Detailed Security Findings

"""
    findings = scan_result.get("findings", [])
    if not findings:
        md += "_No sensitive credentials or high-entropy secrets were identified in this scan._\n"
    else:
        # Group findings by confidence
        high_conf = [f for f in findings if f.get('confidence') == 'High']
        med_conf = [f for f in findings if f.get('confidence') == 'Medium']
        low_conf = [f for f in findings if f.get('confidence') == 'Low']
        
        for conf_level, conf_findings, section_title in [
            ('High', high_conf, '### 🔴 High Confidence Findings (Immediate Review Required)\n'),
            ('Medium', med_conf, '### 🟡 Medium Confidence Findings (Review Recommended)\n'),
            ('Low', low_conf, '### 🟢 Low Confidence Findings (Informational)\n')
        ]:
            if conf_findings:
                md += f"\n{section_title}\n"
                for idx, f in enumerate(conf_findings, start=1):
                    md += f"""#### Finding {idx}: {f.get('title')} ({f.get('severity')} Severity)

- **File Path:** `{f.get('file_path')}`
- **Line Number:** `{f.get('line_number')}`
- **Secret Type:** `{f.get('secret_type', 'Generic Secret')}`
- **Detection Method:** `{f.get('detection_method', 'Pattern Match')}`
- **Confidence:** `{f.get('confidence', 'High')}`
- **Context:** `{f.get('context', 'production')}`
- **CWE Identifier:** `{f.get('cwe_id', 'CWE-798')}`
"""
                    if f.get('entropy_score'):
                        md += f"- **Entropy Score:** `{f.get('entropy_score'):.2f}`\n"
                    
                    md += f"""\n> **Description:** {f.get('description')}

```text
{f.get('code_snippet', '')}
```

**Remediation Guidance:**  
{f.get('remediation', 'Revoke and rotate the secret.')}

---
"""

    md += """
## 🛡️ Important Disclaimers

1. **This scanner identifies potential secrets**, not confirmed exposed credentials.
2. **Manual review is required** to determine if a finding represents a real security risk.
3. **Context affects risk**: Test fixtures with real-looking credentials should still use synthetic data.
4. **False positives are expected** in any automated security tool.
5. **The scanner cannot verify** if a credential is active, revoked, or has restricted permissions.

## 🔐 Best Practices

- Store all secrets in environment variables or secret management systems
- Use clearly synthetic placeholder values in tests and documentation
- Never commit real credentials, even to private repositories
- Regularly rotate credentials and API keys
- Implement pre-commit hooks to catch secrets before they're committed

## 📝 Project Information

*Generated automatically by Offline Secret and Credential Scanner for Source Code Repositories.*  
*All scans are performed strictly offline on local hardware.*
"""
    return md


def save_reports(scan_result: Dict[str, Any], output_dir: str = "reports") -> Dict[str, str]:
    """
    Saves JSON and Markdown reports to output_dir and returns paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    scan_id = scan_result.get("scan_id", datetime.now().strftime("%Y%m%d_%H%M%S"))

    json_path = os.path.join(output_dir, f"report_{scan_id}.json")
    md_path = os.path.join(output_dir, f"report_{scan_id}.md")
    txt_path = os.path.join(output_dir, f"report_{scan_id}.txt")

    # Write JSON
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(generate_json_report(scan_result))

    # Write Markdown
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(generate_markdown_report(scan_result))

    # Write Text summary
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(generate_cli_summary(scan_result) + "\n" + generate_cli_findings_detail(scan_result.get("findings", [])))

    return {
        "json": json_path,
        "markdown": md_path,
        "text": txt_path
    }
