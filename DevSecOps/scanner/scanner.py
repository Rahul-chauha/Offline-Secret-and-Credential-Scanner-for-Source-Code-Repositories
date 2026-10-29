import os
import uuid
import shutil
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime

from .file_handler import (
    safe_extract_zip,
    collect_files_to_scan,
    read_file_safe,
    is_binary_file
)
from .pattern_detector import PatternDetector
from .entropy_analyzer import (
    find_high_entropy_assignments,
    calculate_shannon_entropy
)
from .false_positive_filter import evaluate_finding
from .severity_classifier import (
    classify_severity_and_confidence,
    calculate_scan_score
)
from .report_generator import (
    generate_cli_summary,
    save_reports
)

# Singleton pattern detector instance
_global_detector: Optional[PatternDetector] = None


def get_pattern_detector() -> PatternDetector:
    global _global_detector
    if _global_detector is None:
        _global_detector = PatternDetector()
    return _global_detector


def calculate_security_score(findings: List[Dict[str, Any]]) -> Tuple[int, str, Dict[str, int]]:
    """Alias for calculate_scan_score for backward compatibility."""
    return calculate_scan_score(findings)


def scan_file_content(file_path: str, content: str) -> List[Dict[str, Any]]:
    """
    Scans a single file's text content for secrets using pattern matching,
    entropy analysis, false-positive filtering, and severity classification.
    """
    detector = get_pattern_detector()
    findings = []
    seen_lines_and_types = set()

    # 1. Pattern-based detection
    raw_pattern_findings = detector.scan_content(file_path, content)
    for pf in raw_pattern_findings:
        line_num = pf["line_number"]
        code_snippet = pf.get("code_snippet", "")
        matched_val = pf.get("matched_value", "")

        is_fp, context, reason = evaluate_finding(file_path, code_snippet, matched_val)
        classified = classify_severity_and_confidence(pf, context, is_fp, reason)
        
        if is_fp:
            # Do not report obvious placeholders or local dev credentials as confirmed leaks
            continue

        key = (line_num, classified["secret_type"])
        if key not in seen_lines_and_types:
            seen_lines_and_types.add(key)
            findings.append(classified)

    # 2. Entropy-based detection for high-randomness strings
    lines = content.splitlines()
    for line_idx, line_str in enumerate(lines, start=1):
        clean_str = line_str.strip()
        if not clean_str:
            continue

        entropy_hits = find_high_entropy_assignments(clean_str, line_idx, file_path)
        for eh in entropy_hits:
            key = (line_idx, eh["secret_type"])
            if key not in seen_lines_and_types:
                is_fp, context, reason = evaluate_finding(file_path, clean_str, eh.get("matched_value", ""))
                if is_fp:
                    continue
                classified = classify_severity_and_confidence(eh, context, is_fp, reason)
                seen_lines_and_types.add(key)
                findings.append(classified)

    return findings


def scan_directory(base_dir: str, project_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Scans an entire directory tree for secrets and sensitive credentials.
    """
    base_dir_abs = os.path.abspath(base_dir)
    files = collect_files_to_scan(base_dir_abs)
    total_files = len(files)

    all_findings: List[Dict[str, Any]] = []
    files_with_findings_set = set()
    categories_summary: Dict[str, int] = {}

    for rel_path, abs_path in files:
        content = read_file_safe(abs_path)
        if content is None:
            continue

        file_findings = scan_file_content(rel_path, content)
        if file_findings:
            files_with_findings_set.add(rel_path)
            for f in file_findings:
                cat = f.get("category", "Secrets")
                categories_summary[cat] = categories_summary.get(cat, 0) + 1
            all_findings.extend(file_findings)

    score, grade, counts = calculate_scan_score(all_findings)
    scan_id = str(uuid.uuid4())
    proj = project_name or os.path.basename(base_dir_abs.rstrip("/\\")) or "Source Repository"

    return {
        "scan_id": scan_id,
        "project_name": proj,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files": total_files,
        "files_with_findings": len(files_with_findings_set),
        "total_findings": len(all_findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "security_score": score,
        "rating_grade": grade,
        "categories_summary": categories_summary,
        "findings": all_findings
    }


def scan_zip_file(zip_path: str, project_name: Optional[str] = None, temp_base_dir: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Safely unpacks a ZIP archive in a temporary sandboxed directory, scans all contents,
    and reliably cleans up temporary artifacts.
    """
    scan_id = str(uuid.uuid4())
    if temp_base_dir is None:
        temp_base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads", "extracted")

    extract_target = os.path.join(temp_base_dir, scan_id)
    success, msg, file_count = safe_extract_zip(zip_path, extract_target)

    if not success:
        return False, msg, {}

    try:
        proj = project_name or os.path.splitext(os.path.basename(zip_path))[0]
        scan_results = scan_directory(extract_target, project_name=proj)
        scan_results["scan_id"] = scan_id
        scan_results["file_size"] = os.path.getsize(zip_path) if os.path.exists(zip_path) else 0

        return True, "Scan completed successfully.", scan_results

    finally:
        if os.path.exists(extract_target):
            shutil.rmtree(extract_target, ignore_errors=True)
