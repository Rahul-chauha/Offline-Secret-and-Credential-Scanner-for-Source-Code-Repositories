# Offline Secret and Credential Scanner for Source Code Repositories

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Mode](https://img.shields.io/badge/security-100%25%20Offline%20%2F%20Local-emerald.svg)](#-privacy)
[![Tests](https://img.shields.io/badge/tests-30%20passed-success.svg)](#-testing)
[![Project](https://img.shields.io/badge/academic-II--Year%20Mini%20Project%202026--27-indigo.svg)](#-project-information)

An offline security auditing tool that scans source code repositories and ZIP archives for accidentally exposed secrets and credentials. The system uses pattern-based detection combined with Shannon entropy analysis to identify potentially sensitive information and classifies findings according to severity.

---

## 📌 What Does This Project Do?

This project is an **Offline Secret and Credential Scanner** designed to help developers secure their source code before deployment. 

It automatically scans local repository folders or ZIP archives to find accidentally committed sensitive information, such as:
- API Keys (AWS, Google, Stripe, OpenAI, etc.)
- Database Passwords (PostgreSQL, MongoDB, etc.)
- Private Cryptographic Keys (RSA, OpenSSH)
- Authentication Tokens (JWTs, Personal Access Tokens)

By using a combination of **pattern matching** (for known secret formats) and **Shannon entropy analysis** (for highly random, unknown credentials), it acts as a local security guard. It effectively detects these secrets and generates a detailed report, allowing developers to remove them before pushing code to public or shared environments.

The project is intentionally focused on **secret and credential detection** to maintain a feasible scope for an individual II-year mini project.

---

## 🎯 Objectives

- **Scan source-code repositories and ZIP archives** for exposed secrets.
- **Detect common credentials**: API keys, access tokens, passwords, private keys, and database credentials.
- **Use regular-expression/pattern-based detection** for known secret formats.
- **Apply Shannon entropy analysis** to identify high-randomness credential-like strings.
- **Reduce false positives** through filtering and validation rules (placeholders, documentation, test fixtures).
- **Classify detected findings** according to severity (`Critical`, `High`, `Medium`, `Low`).
- **Provide a simple dashboard** for viewing scan results.
- **Generate structured security reports** in JSON, Markdown, and Text format.
- **Perform all scanning locally** without uploading source code to external servers.

---

## 🔍 Key Features

### 1. Repository/ZIP Ingestion
The scanner accepts:
- ZIP archives (`.zip`) containing source code.
- Local source-code repositories.
- Project directories on disk.

Input is processed locally for strict security and privacy.

### 2. Safe File Handling
The system performs controlled extraction and scanning:
- **Zip-Slip Defense**: Path traversal protection against archives containing malicious filenames (`..`).
- **Zip-Bomb Defense**: Limits on total uncompressed size (500 MB) and max file count (50,000 files).
- **Binary Filtering**: Skips unnecessary binary files (`.png`, `.exe`, `.dll`, `.pyc`, `.db`) and checks for null bytes.
- **Dependency Directory Pruning**: Automatically ignores `.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`, etc.
- **Safe File Decoders**: Reads supported source and configuration files safely using UTF-8 with fallback.

### 3. Pattern-Based Secret Detection
The scanner searches for known secret formats loaded from `patterns/secret_patterns.json`:
- **Private Keys**: RSA, OpenSSH, DSA, EC, PGP private keys.
- **Cloud Credentials**: AWS Access Keys (`AKIA...`), AWS Secret Keys, GCP Service Account Keys, Google API keys (`AIza...`).
- **Platform Tokens**: GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`), Slack Tokens & Webhooks, OpenAI API Keys (`sk-...`, `sk-proj-...`), Stripe Live Keys (`sk_live_...`), SendGrid, Twilio.
- **Database Credentials**: PostgreSQL, MySQL, MongoDB, Redis, MSSQL connection URIs containing passwords.
- **Authentication Tokens**: Static JSON Web Tokens (JWT), session signing keys, client secrets.
- **Password Assignments**: Plaintext database and user password variables.

### 4. Entropy-Based Detection
Pattern matching alone cannot detect every possible secret. The scanner therefore uses **Shannon entropy analysis** to calculate the information density of candidate assignments:

$$H(X) = - \sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

- Hexadecimal strings (`[0-9a-fA-F]`): Threshold $\ge 3.2$
- Base64 tokens (`[A-Za-z0-9+/=]`): Threshold $\ge 4.2$
- Alphanumeric credentials: Threshold $\ge 3.8$

Entropy serves as an additional signal to catch machine-generated credentials that do not match predefined regex signatures.

### 5. False-Positive Filtering
The scanner applies rules to reduce unnecessary alerts:
- **Placeholders**: Filters out `changeme`, `your_key`, `dummy_token`, `stale-client-key`, `xxxx`, `<your-token>`.
- **Documentation & Templates**: Downgrades sample credentials found in `.env.example`, `sample.env`, `README.md`, or docs to Low severity.
- **Test Context**: Test suite fixtures (`tests/`, `mocks/`) are downgraded to Medium severity maximum.
- **Local Dev URIs**: Connection strings referencing `@localhost`, `@127.0.0.1`, or local docker hosts are categorized as Low severity.

### 6. Severity Classification

Detected findings are categorized according to potential security impact:

| Severity | Description | Deductions |
|---|---|:---:|
| **Critical** | Highly sensitive credentials such as private keys, live cloud tokens, or production DB credentials | -20 pts |
| **High** | Potentially exploitable API keys, access tokens, or critical secrets | -10 pts |
| **Medium** | Suspicious credentials, generic tokens, or high-entropy tokens | -5 pts |
| **Low** | Weak or low-confidence credential-like findings, placeholders, or template examples | -2 pts |

**Security Score:** Starts at 100 with deductions; Grade scale: A (90-100), B (75-89), C (50-74), D (30-49), F (<30).

### 7. Security Dashboard & CLI Summary
The system provides both a command-line interface (CLI) and an interactive web dashboard:

- **Web Dashboard (`app.py`)**:
  - **Scanner Homepage**: Repository ZIP drag-and-drop upload zone, local directory path input, statistics ribbon, core pipeline specifications, and SQLite scan history table.
  - **Results Page**: Rating grade badge (`A+`, `A`, `B`, `C`, `D`, `F`), security posture score, metrics cards grid, severity filter toolbar (`Critical`, `High`, `Medium`, `Low`), live search box, 1-click file path and code snippet copy buttons, remediation guidance boxes, and interactive pagination.
  - **Rule Catalog Page**: Regular expression pattern table with CWE identifiers, confidence ratings, and Shannon entropy threshold specifications.
  - **Printable Audit Report Page**: Clean, printable security report with PDF print stylesheet support (`window.print()`).

- **CLI Summary (`main.py`)**:
```text
========================================
       SECURITY SCAN SUMMARY
========================================

Files Scanned      : 142
Files With Findings: 11
Total Findings     : 17

Critical           : 3
High               : 7
Medium             : 5
Low                : 2
========================================
```

### 8. Security Report
For each finding, the scanner outputs:
- **File path & line number**
- **Detected secret type & rule ID**
- **Severity & confidence rating**
- **Detection method** (`Pattern Match` / `Entropy Analysis`)
- **Code snippet with syntax formatting**
- **Remediation guidance**

---

## 🏗️ System Workflow

```text
        Source Repository / ZIP
                  |
                  v
        +---------------------+
        | Safe File Handling  |  (ZipSlip & ZipBomb protection, binary check)
        +---------------------+
                  |
                  v
        +---------------------+
        | File Filtering      |  (Skip .git, node_modules, __pycache__)
        +---------------------+
                  |
                  v
        +---------------------+
        | Pattern Detection   |  (Match against patterns/secret_patterns.json)
        +---------------------+
                  |
                  v
        +---------------------+
        | Entropy Analysis    |  (Calculate Shannon entropy on assignments)
        +---------------------+
                  |
                  v
        +---------------------+
        | False Positive      |  (Filter placeholders, .env.example, tests)
        | Filtering           |
        +---------------------+
                  |
                  v
        +---------------------+
        | Severity            |  (Critical / High / Medium / Low + Scoring)
        | Classification      |
        +---------------------+
                  |
                  v
        +---------------------+
        | Dashboard & Report  |  (CLI summary, Web UI, JSON, Markdown, Text)
        +---------------------+
```

---

## 🧩 Main Modules

- **Module 1: Input Handler (`scanner/file_handler.py`)**: Accepts ZIP files and repository directories.
- **Module 2: Safe File Processor (`scanner/file_handler.py`)**: Handles secure extraction, file validation, and file-type filtering.
- **Module 3: Secret Pattern Detector (`scanner/pattern_detector.py`)**: Uses predefined patterns to identify known credential formats.
- **Module 4: Entropy Analyzer (`scanner/entropy_analyzer.py`)**: Calculates Shannon entropy of suspicious strings.
- **Module 5: False-Positive Filter (`scanner/false_positive_filter.py`)**: Reduces placeholder and template false positives.
- **Module 6: Severity Classifier (`scanner/severity_classifier.py`)**: Assigns severity levels, confidence, and security score.
- **Module 7: Report Generator (`scanner/report_generator.py`)**: Creates structured JSON, Markdown, and Text reports in `reports/`.
- **Module 8: Dashboard (`dashboard/app.py` & `templates/`)**: Web interface for viewing findings and audit history.

---

## 📂 Project Structure

```text
DevSecOps/
│
├── scanner/
│   ├── __init__.py                # Package exports and interfaces
│   ├── file_handler.py            # Module 1 & 2: Safe input and file processor
│   ├── pattern_detector.py        # Module 3: Regex pattern matching engine
│   ├── entropy_analyzer.py        # Module 4: Shannon entropy calculation
│   ├── false_positive_filter.py   # Module 5: False-positive filtering rules
│   ├── severity_classifier.py     # Module 6: Severity and confidence scoring
│   ├── report_generator.py        # Module 7: Multi-format report generation
│   └── scanner.py                 # Core scanner pipeline orchestrator
│
├── dashboard/
│   └── app.py                     # Module 8: Web dashboard application
│
├── patterns/
│   └── secret_patterns.json       # JSON catalog of secret detection rules
│
├── database/
│   └── db.py                      # SQLite database storage for audit history
│
├── templates/                     # Dashboard HTML templates
│   ├── base.html
│   ├── index.html
│   ├── results.html
│   ├── report.html
│   └── rules.html
│
├── static/                        # CSS and JavaScript frontend assets
│   ├── css/style.css
│   └── js/dashboard.js
│
├── reports/                       # Generated audit reports (.json, .md, .txt)
│
├── samples/                       # Test datasets and sample repository
│   ├── sample_repo/               # Unpacked test repository
│   └── test_repository.zip        # Packaged sample archive
│
├── tests/                         # Automated unit & integration tests
│   ├── test_patterns.py           # Pattern regex unit tests
│   ├── test_entropy.py            # Shannon entropy unit tests
│   ├── test_scanner.py            # End-to-end scanner pipeline tests
│   └── test_web_dashboard.py      # Flask web dashboard integration & route tests
│
├── requirements.txt               # Python package dependencies
├── README.md                      # Documentation
├── main.py                        # Interactive CLI scanner entry point
└── app.py                         # Web dashboard entry point
```

---

## 🛠️ Technology Stack

- **Programming Language:** Python 3.10+
- **Pattern Matching:** Regular Expressions (`re`)
- **Entropy Analysis:** Shannon Entropy algorithm (`math`)
- **Input Processing:** Python `zipfile`, `os`, `shutil`
- **Frontend / Dashboard:** Flask, HTML5, CSS3, JavaScript
- **Database:** SQLite3
- **Data Format:** JSON
- **Testing Framework:** `pytest`

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/offline-secret-scanner.git
cd offline-secret-scanner
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

**Windows:**
```bash
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### Option 1: Command Line Interface (CLI)

Run the interactive scanner:

```bash
python main.py
```

Provide the path of the repository directory or ZIP archive when prompted:

```text
Enter repository/ZIP path:
samples/test_repository.zip
```

Or pass the target path directly as an argument:

```bash
python main.py samples/test_repository.zip
```

To run a scan and immediately open the web dashboard:

```bash
python main.py samples/test_repository.zip --web
```

### Option 2: Web Dashboard

Start the offline web dashboard:

```bash
python app.py
```

Open your browser at:
```text
http://127.0.0.1:5000
```

Upload a `.zip` archive or specify a local folder path to view interactive scan metrics, severity filters, code snippets, and printable reports.

---

## 📊 Example Result

```text
========================================================================
    OFFLINE SECRET AND CREDENTIAL SCANNER FOR SOURCE CODE REPOSITORIES
                 Academic Session 2026-27 | II-Year Mini Project
========================================================================

[*] Target: samples/test_repository.zip
[*] Performing safe offline secret detection...

Scan Completed Successfully

========================================
       SECURITY SCAN SUMMARY
========================================

Files Scanned      : 5
Files With Findings: 4
Total Findings     : 15

Critical           : 4
High               : 1
Medium             : 5
Low                : 5
========================================

DETAILED FINDINGS:
------------------------------------------------------------
[1] File: config/keys.py
    Line       : 2
    Type       : AWS Credential
    Severity   : Critical
    Detection  : Pattern Match
    Confidence : High
    Description: Amazon Web Services (AWS) Access Key ID detected.
    Snippet    : AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
    Remediation: Deactivate and delete the exposed AWS access key via the AWS IAM Console immediately.
------------------------------------------------------------
[2] File: config/keys.py
    Line       : 8
    Type       : Private Key
    Severity   : Critical
    Detection  : Pattern Match
    Confidence : High
    Description: Unencrypted RSA private cryptographic key detected in source code.
    Snippet    : PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
    Remediation: Remove the private key from the codebase, revoke the keypair, and store in a secure vault.
------------------------------------------------------------

Report generated successfully.
  - JSON Report    : reports\report_94500019.json
  - Markdown Report: reports\report_94500019.md
  - Text Summary   : reports\report_94500019.txt
```

---

## 🔐 Privacy

This project is built from the ground up as an **offline security scanner**:
- All scanning and extraction operations run **locally** on your computer.
- No files, source code, or credentials are uploaded to external APIs or remote servers.
- Safe sandboxing ensures temporary files are pruned immediately after processing.

---

## 🧪 Testing

Run the automated test suite with `pytest`:

```bash
python -m pytest tests/ -v
```

The test suite covers:
- **`test_patterns.py`**: Regex accuracy for private keys, AWS tokens, GitHub PATs, database URIs, JWTs, and OpenAI keys.
- **`test_entropy.py`**: Shannon entropy calculation, high/low randomness detection, and charset thresholds.
- **`test_scanner.py`**: Zip-Slip rejection, safe extraction, directory traversal, false-positive filtering, score calculation, report generation, and database persistence.

---

## 📅 Ten-Week Development Plan

| Week | Planned Work | Status |
|---|---|:---:|
| **Week 1** | Requirement analysis and research | ✅ Completed |
| **Week 2** | Repository/ZIP ingestion and safe file handling | ✅ Completed |
| **Week 3** | Pattern-based secret detection | ✅ Completed |
| **Week 4** | Entropy analysis and filtering | ✅ Completed |
| **Week 5** | Severity classification and finding structure | ✅ Completed |
| **Week 6** | Working scanner and initial dashboard/report | ✅ Completed |
| **Week 7** | Improve detection accuracy and false-positive handling | ✅ Completed |
| **Week 8** | Dashboard and report improvements | ✅ Completed |
| **Week 9** | Testing with sample repositories | ✅ Completed |
| **Week 10** | Bug fixing, documentation and final demonstration | ✅ Completed |

---

## 📈 Expected Outcome

The system satisfies all core project requirements:
1. Accepts a source repository directory or ZIP archive.
2. Safely processes its contents (Zip-Slip defense and binary skipping).
3. Detects potential secrets using predefined patterns.
4. Applies Shannon entropy analysis to identify high-randomness credentials.
5. Reduces false positives through contextual filtering rules.
6. Classifies findings by severity (`Critical`, `High`, `Medium`, `Low`).
7. Displays scan statistics on both the terminal and interactive web dashboard.
8. Generates multi-format security reports (`.json`, `.md`, `.txt`).

---

## 🔮 Future Scope

The current project intentionally focuses on **secret and credential detection** to maintain a feasible scope for an individual II-year mini project.

Future versions may extend the system with:
- CI/CD pipeline security scanning
- Dockerfile and container security analysis
- Infrastructure-as-Code (IaC) security scanning
- Multi-repository automated batch scanning
- REST API integration
- GitHub / GitLab webhooks integration
- Continuous security monitoring and alerting

*These features are outside the scope of the current II-year mini project and are proposed as future enhancements.*

---

## ⚠️ Disclaimer

This tool is developed for educational and defensive security auditing purposes. It should be used exclusively on source code and repositories that you own or have explicit authorization to inspect.

---

## 👨‍💻 Project Information

- **Project Title:** Offline Secret and Credential Scanner for Source Code Repositories
- **Project Type:** II-Year Mini Project
- **Academic Session:** 2026–27
- **Domain:** Cybersecurity / Software Security
- **Primary Focus:** Secret and Credential Detection
- **Processing Mode:** Offline / Local
