import pytest
import os
import tempfile
import zipfile
from dashboard.app import app
from database.db import init_db, get_all_scans, delete_scan

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_index_route(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Offline" in response.data
    assert b"SecretScanner" in response.data
    assert b"Scanner" in response.data

def test_rules_route(client):
    response = client.get("/rules")
    assert response.status_code == 200
    assert b"Secret &amp; Credential Detection Rule Catalog" in response.data or b"Detection Rule Catalog" in response.data

def test_api_scans_route(client):
    response = client.get("/api/scans")
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert "scans" in json_data

def test_local_directory_scan_route(client):
    # Scan sample_repo directory
    sample_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "sample_repo")
    response = client.post("/scan", data={
        "project_name": "Test Sample Repo",
        "local_folder_path": sample_dir
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Test Sample Repo" in response.data
    assert b"Scan Results" in response.data or b"Security Score" in response.data

def test_zip_upload_scan_route(client):
    # Create a temporary zip file with a dummy secret
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "test_repo.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("config.py", 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        
        with open(zip_path, "rb") as zf_file:
            response = client.post("/scan", data={
                "project_name": "Zip Upload Test",
                "project_zip": (zf_file, "test_repo.zip")
            }, follow_redirects=True)

        assert response.status_code == 200
        assert b"Zip Upload Test" in response.data

def test_results_and_report_and_export_and_delete_routes(client):
    scans = get_all_scans()
    if not scans:
        pytest.skip("No scans available to test results route")
    
    scan_id = scans[0]["scan_id"]

    # 1. Results page
    res_resp = client.get(f"/results/{scan_id}")
    assert res_resp.status_code == 200
    assert scan_id.encode() in res_resp.data or scans[0]["project_name"].encode() in res_resp.data

    # 2. Report page
    rep_resp = client.get(f"/report/{scan_id}")
    assert rep_resp.status_code == 200
    assert b"Offline Secret and Credential Security Audit Report" in rep_resp.data

    # 3. API detail
    api_resp = client.get(f"/api/scan/{scan_id}")
    assert api_resp.status_code == 200
    assert api_resp.get_json()["success"] is True

    # 4. Export JSON
    exp_resp = client.get(f"/api/scan/{scan_id}/export/json")
    assert exp_resp.status_code == 200
    assert exp_resp.mimetype == "application/json"

    # 5. Delete scan
    del_resp = client.post(f"/api/scan/{scan_id}/delete", follow_redirects=True)
    assert del_resp.status_code == 200
