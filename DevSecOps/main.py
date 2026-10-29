#!/usr/bin/env python3
"""
Offline Secret and Credential Scanner for Source Code Repositories
II-Year Mini Project | Academic Session: 2026-27 | Processing Mode: Offline/Local
"""

import os
import sys
import argparse
from typing import Dict, Any

from scanner.scanner import scan_directory, scan_zip_file
from scanner.report_generator import (
    generate_cli_summary,
    generate_cli_findings_detail,
    save_reports
)


def print_banner():
    banner = """
========================================================================
    OFFLINE SECRET AND CREDENTIAL SCANNER FOR SOURCE CODE REPOSITORIES
                 Academic Session 2026-27 | II-Year Mini Project
========================================================================
"""
    print(banner.strip())


def run_scanner(target_path: str, project_name: str = None) -> Dict[str, Any]:
    target_path = target_path.strip().strip("'\"")

    if not os.path.exists(target_path):
        print(f"\n[ERROR] Path does not exist: {target_path}")
        sys.exit(1)

    print(f"\n[*] Target: {target_path}")
    print("[*] Performing safe offline secret detection...")

    if os.path.isfile(target_path) and target_path.lower().endswith(".zip"):
        success, msg, scan_results = scan_zip_file(target_path, project_name=project_name)
        if not success:
            print(f"\n[ERROR] Failed to scan ZIP archive: {msg}")
            sys.exit(1)
    elif os.path.isdir(target_path):
        scan_results = scan_directory(target_path, project_name=project_name)
    else:
        print(f"\n[ERROR] Unsupported target. Please provide a local repository directory or a .zip archive.")
        sys.exit(1)

    return scan_results


def display_results(scan_results: Dict[str, Any]):
    print("\nScan Completed Successfully\n")
    print(generate_cli_summary(scan_results))

    findings = scan_results.get("findings", [])
    if findings:
        print(generate_cli_findings_detail(findings))
    else:
        print("\n[+] No exposed secrets or sensitive credentials detected. Repository is clean!")

    reports = save_reports(scan_results, output_dir="reports")
    print("\nReport generated successfully.")
    print(f"  - JSON Report    : {reports['json']}")
    print(f"  - Markdown Report: {reports['markdown']}")
    print(f"  - Text Summary   : {reports['text']}")


def main():
    parser = argparse.ArgumentParser(
        description="Offline Secret and Credential Scanner for Source Code Repositories."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to source-code repository folder or ZIP archive (.zip)."
    )
    parser.add_argument(
        "--name",
        dest="project_name",
        default=None,
        help="Optional custom project or repository name."
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the offline security web dashboard after scan or directly."
    )

    args = parser.parse_args()
    print_banner()

    if args.web and not args.target:
        print("\n[*] Starting Security Web Dashboard on http://127.0.0.1:5000 ...")
        from app import app
        app.run(host="127.0.0.1", port=5000, debug=False)
        return

    target_path = args.target
    if not target_path:
        try:
            target_path = input("\nEnter repository/ZIP path: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nScan aborted by user.")
            sys.exit(0)

    if not target_path:
        print("[ERROR] No path provided. Exiting.")
        sys.exit(1)

    scan_results = run_scanner(target_path, project_name=args.project_name)
    display_results(scan_results)

    if args.web:
        print("\n[*] Launching Security Web Dashboard...")
        from app import app
        app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
