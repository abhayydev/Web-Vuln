# WebVuln Scanner

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-25%20passed-brightgreen.svg)]()

**WebVuln Scanner** is a professional, modular, asynchronous web security assessment framework designed for educational analysis, CTF challenges, intentionally vulnerable applications, and authorized security assessments.

---

> [!WARNING]
> **LEGAL & ETHICAL NOTICE**
> WebVuln Scanner is strictly designed for systems you own or have **explicit, written authorization** to test. Unauthorized port scanning or vulnerability scanning of third-party systems is illegal.

---

## Key Capabilities

* **Target Discovery & Validation**: RFC-compliant URL canonicalization, port normalization, and strict scope boundary enforcement.
* **Asynchronous BFS Web Crawler**: Deep link extraction, HTML form/input field mapping, parameter extraction, and robots.txt / sitemap.xml ingestion.
* **Passive Technology Fingerprinting**: Multi-factor detection of web servers (Nginx, Apache, IIS), backend frameworks (Django, Laravel, Flask, Spring, PHP), and frontend UI engines (React, Vue, Angular).
* **Modular Vulnerability Audit Modules**:
  * **Security Headers**: CSP (evaluating `unsafe-inline`/`unsafe-eval`), HSTS, X-Frame-Options (Clickjacking), X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
  * **Cookie & Session Hardening**: Inspects `HttpOnly`, `Secure`, `SameSite` attributes; automatically masks sensitive cookie values.
  * **CORS Analysis**: Detects arbitrary origin reflection, wildcard policies, and `Access-Control-Allow-Credentials: true` misconfigurations.
  * **TLS/SSL Auditing**: Checks for obsolete protocols (TLS 1.0, 1.1, SSLv3) and certificate expiration dates.
  * **Contextual Reflection (XSS)**: Diagnostic marker reflection checks for unescaped HTML characters.
  * **SQL Syntax Diagnostics (SQLi)**: Non-destructive syntax error pattern matching across MySQL, PostgreSQL, MSSQL, SQLite, and Oracle.
  * **Path Traversal / LFI Probes**: Inspects file parameter handling and relative path sequence responses.
  * **Open Redirect Detection**: Audits parameter redirection against safe test domains.
  * **API & OpenAPI Security**: Discovers Swagger/OpenAPI documentation, flags unsafe HTTP methods (`PUT`, `DELETE`), and detects debug key disclosure in JSON responses.
  * **Authentication & Object Identifiers**: Detects password inputs over cleartext HTTP and flags predictable sequential numeric IDs (IDOR/BOLA).
* **Multi-Factor Risk Engine**: Weighted scoring (0.0 to 10.0) combining severity levels and confidence ratings with finding deduplication.
* **Comprehensive Reporting**: Rich terminal summary tables, structured JSON output, and modern responsive HTML executive reports.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/example/webvuln-scanner.git
cd webvuln-scanner

# Install dependencies
pip install -r requirements.txt
```

---

## Usage & CLI Examples

### 1. Full Automated Vulnerability Scan
```bash
python -m webvuln.cli scan http://localhost:8888 --depth 3 --max-urls 50 -o reports/
```

### 2. Attack Surface Discovery (Crawler)
```bash
python -m webvuln.cli crawl http://localhost:8888 --depth 2 --max-urls 25
```

### 3. Passive Technology Fingerprinting
```bash
python -m webvuln.cli fingerprint http://localhost:8888
```

### 4. REST API & OpenAPI Audit
```bash
python -m webvuln.cli api http://localhost:8888
```

---

## Running the Local Test Lab

A built-in intentionally vulnerable test application is included for local verification:

```bash
# Terminal 1: Start test lab application
python examples/vulnerable_app.py

# Terminal 2: Execute WebVuln Scanner
python -m webvuln.cli scan http://127.0.0.1:8888/
```

---

## Running Automated Tests

```bash
python -m pytest tests/ -v
```
note : the website i tested here is intentially vulnerable for public testing big thanks to them too

<img width="1920" height="953" alt="vuln3" src="https://github.com/user-attachments/assets/2f25f3fe-17b9-4ad6-ae97-859f0c3d4db4" />
<img width="1920" height="934" alt="vulnn1" src="https://github.com/user-attachments/assets/bae98a76-05ea-46a4-bdf4-3b9d4557ced6" />
<img width="1920" height="951" alt="vuln" src="https://github.com/user-attachments/assets/eb0d79f1-0b8c-420a-8c50-e610c537d493" />
<img width="1920" height="923" alt="web report 2" src="https://github.com/user-attachments/assets/dc139a77-e7a8-4b02-b918-7be68cc2c3c2" />
<img width="1920" height="925" alt="web report" src="https://github.com/user-attachments/assets/9b9e4eeb-41c3-4e93-b05b-caeb739435e2" />



Happy Hacking - Abhay 
