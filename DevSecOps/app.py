#!/usr/bin/env python3
"""
Offline Secret and Credential Scanner for Source Code Repositories
Main Web Dashboard Entry Point
"""

from dashboard.app import app

if __name__ == "__main__":
    print("[*] Starting Offline Secret and Credential Scanner on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=True)
