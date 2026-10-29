import os
import sqlite3
import json
from datetime import datetime

DEFAULT_DB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "database.db")


def get_db_connection(db_path=None):
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            project_name TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            total_files INTEGER DEFAULT 0,
            security_score INTEGER NOT NULL,
            rating_grade TEXT NOT NULL,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            categories_summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            category TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER DEFAULT 0,
            code_snippet TEXT,
            description TEXT,
            remediation TEXT,
            cwe_id TEXT,
            secret_type TEXT DEFAULT 'Secret',
            detection_method TEXT DEFAULT 'Pattern Match',
            confidence TEXT DEFAULT 'High',
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
        )
    """)

    # Safe migration: add columns if an older database table already exists
    cursor.execute("PRAGMA table_info(findings)")
    columns = [col[1] for col in cursor.fetchall()]
    if "secret_type" not in columns:
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN secret_type TEXT DEFAULT 'Secret'")
        except Exception:
            pass
    if "detection_method" not in columns:
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN detection_method TEXT DEFAULT 'Pattern Match'")
        except Exception:
            pass
    if "confidence" not in columns:
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'High'")
        except Exception:
            pass

    conn.commit()
    conn.close()


def save_scan(scan_summary, findings, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    categories_json = json.dumps(scan_summary.get("categories_summary", {}))

    cursor.execute("""
        INSERT INTO scans (
            scan_id, project_name, file_size, total_files,
            security_score, rating_grade, critical_count, high_count,
            medium_count, low_count, total_findings, categories_summary, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_summary["scan_id"],
        scan_summary.get("project_name", "Unknown Project"),
        scan_summary.get("file_size", 0),
        scan_summary.get("total_files", 0),
        scan_summary.get("security_score", 100),
        scan_summary.get("rating_grade", "A"),
        scan_summary.get("critical_count", 0),
        scan_summary.get("high_count", 0),
        scan_summary.get("medium_count", 0),
        scan_summary.get("low_count", 0),
        scan_summary.get("total_findings", 0),
        categories_json,
        scan_summary.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ))

    for f in findings:
        cursor.execute("""
            INSERT INTO findings (
                scan_id, category, rule_id, title, severity,
                file_path, line_number, code_snippet, description,
                remediation, cwe_id, secret_type, detection_method, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_summary["scan_id"],
            f.get("category", "Secrets"),
            f.get("rule_id", "SEC-001"),
            f.get("title", "Secret Detected"),
            f.get("severity", "Medium"),
            f.get("file_path", "unknown"),
            f.get("line_number", 0),
            f.get("code_snippet", ""),
            f.get("description", ""),
            f.get("remediation", ""),
            f.get("cwe_id", "CWE-798"),
            f.get("secret_type", "Secret"),
            f.get("detection_method", "Pattern Match"),
            f.get("confidence", "High")
        ))

    conn.commit()
    conn.close()


def get_all_scans(db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()
    scans = []
    for r in rows:
        item = dict(r)
        try:
            item["categories_summary"] = json.loads(item["categories_summary"] or "{}")
        except Exception:
            item["categories_summary"] = {}
        scans.append(item)
    conn.close()
    return scans


def get_scan(scan_id, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return None

    scan = dict(scan_row)
    try:
        scan["categories_summary"] = json.loads(scan["categories_summary"] or "{}")
    except Exception:
        scan["categories_summary"] = {}

    cursor.execute("""
        SELECT * FROM findings WHERE scan_id = ? 
        ORDER BY CASE severity 
            WHEN 'Critical' THEN 1 
            WHEN 'High' THEN 2 
            WHEN 'Medium' THEN 3 
            WHEN 'Low' THEN 4 
            ELSE 5 END, id ASC
    """, (scan_id,))
    finding_rows = cursor.fetchall()
    scan["findings"] = [dict(f) for f in finding_rows]

    conn.close()
    return scan


def delete_scan(scan_id, db_path=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
    cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    conn.commit()
    conn.close()
