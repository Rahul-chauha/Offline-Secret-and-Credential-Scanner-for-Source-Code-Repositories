import os
import io
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename

import sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.db import init_db, save_scan, get_all_scans, get_scan, delete_scan
from scanner.scanner import scan_zip_file, scan_directory
from scanner.pattern_detector import get_pattern_detector
from scanner.entropy_analyzer import calculate_shannon_entropy

TEMPLATES_DIR = os.path.join(PROJECT_ROOT, "templates")
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, "uploads")
REPORTS_FOLDER = os.path.join(PROJECT_ROOT, "reports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Initialize database
init_db()

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR,
    static_folder=STATIC_DIR
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "offline-secret-scanner-academic-2026-key")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB max archive size


@app.route("/")
def index():
    scans = get_all_scans()
    total_scans = len(scans)
    total_findings_detected = sum(s.get("total_findings", 0) for s in scans)
    avg_score = round(sum(s.get("security_score", 100) for s in scans) / total_scans, 1) if total_scans > 0 else 100

    return render_template(
        "index.html",
        recent_scans=scans[:12],
        total_scans=total_scans,
        total_findings_detected=total_findings_detected,
        avg_score=avg_score
    )


@app.route("/scan", methods=["POST"])
def scan_project():
    # Option A: Local Directory Path on Machine
    folder_path = request.form.get("local_folder_path", "").strip()
    if folder_path:
        if not os.path.isdir(folder_path):
            flash(f"Directory path '{folder_path}' does not exist on the local system.", "danger")
            return redirect(url_for("index"))

        project_name = request.form.get("project_name") or os.path.basename(os.path.abspath(folder_path))
        scan_results = scan_directory(folder_path, project_name=project_name)

        scan_summary = {
            "scan_id": scan_results["scan_id"],
            "project_name": project_name,
            "file_size": 0,
            "total_files": scan_results["total_files"],
            "security_score": scan_results["security_score"],
            "rating_grade": scan_results["rating_grade"],
            "critical_count": scan_results["critical_count"],
            "high_count": scan_results["high_count"],
            "medium_count": scan_results["medium_count"],
            "low_count": scan_results["low_count"],
            "total_findings": scan_results["total_findings"],
            "categories_summary": scan_results["categories_summary"]
        }
        save_scan(scan_summary, scan_results["findings"])
        flash(f"Successfully audited local repository '{project_name}'!", "success")
        return redirect(url_for("results", scan_id=scan_results["scan_id"]))

    # Option B: ZIP Archive Upload
    if "project_zip" not in request.files:
        flash("No file part in the upload request.", "danger")
        return redirect(url_for("index"))

    file = request.files["project_zip"]
    if file.filename == "":
        flash("Please select a project ZIP archive to upload.", "warning")
        return redirect(url_for("index"))

    if not file.filename.lower().endswith(".zip"):
        flash("Invalid file format. Only ZIP archives (.zip) are supported for offline scanning.", "danger")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved_filename = f"{timestamp}_{filename}"
    saved_zip_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_filename)
    file.save(saved_zip_path)

    project_name = request.form.get("project_name") or os.path.splitext(filename)[0]

    # Perform Safe Extraction and Scanning
    success, msg, scan_results = scan_zip_file(saved_zip_path, project_name=project_name)

    # Clean up uploaded zip file from disk
    try:
        if os.path.exists(saved_zip_path):
            os.remove(saved_zip_path)
    except Exception:
        pass

    if not success:
        flash(f"Scanning failed: {msg}", "danger")
        return redirect(url_for("index"))

    findings = scan_results.pop("findings", [])
    save_scan(scan_results, findings)
    flash(f"Security scan completed for '{project_name}'!", "success")
    return redirect(url_for("results", scan_id=scan_results["scan_id"]))


@app.route("/results/<scan_id>")
def results(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        flash("Audit scan results not found or expired.", "danger")
        return redirect(url_for("index"))
    return render_template("results.html", scan=scan_data)


@app.route("/report/<scan_id>")
def report(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        flash("Audit report not found.", "danger")
        return redirect(url_for("index"))
    return render_template("report.html", scan=scan_data)


@app.route("/rules")
def rules():
    detector = get_pattern_detector()
    rules_list = detector.get_rules()
    return render_template("rules.html", rules=rules_list)


@app.route("/api/scans")
def api_scans():
    scans = get_all_scans()
    return jsonify({"success": True, "count": len(scans), "scans": scans})


@app.route("/api/scan/<scan_id>")
def api_scan_details(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        return jsonify({"success": False, "message": "Scan not found"}), 404
    return jsonify({"success": True, "scan": scan_data})


@app.route("/api/scan/<scan_id>/export/json")
def export_json(scan_id):
    scan_data = get_scan(scan_id)
    if not scan_data:
        return jsonify({"error": "Scan not found"}), 404

    json_str = json.dumps(scan_data, indent=2)
    buffer = io.BytesIO(json_str.encode("utf-8"))
    buffer.seek(0)
    filename = f"secret_scanner_report_{scan_id[:8]}.json"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/json"
    )


@app.route("/api/scan/<scan_id>/delete", methods=["POST"])
def delete_scan_route(scan_id):
    delete_scan(scan_id)
    flash("Scan record deleted.", "info")
    return redirect(url_for("index"))


if __name__ == "__main__":
    print("[*] Starting Offline Secret and Credential Scanner Dashboard on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=True)
