# QShield Automated Testing Specification

**Project:** QShield — QR Phishing Detection & Awareness System  
**Framework:** `pytest 8.2.0`  
**Execution Environment:** Python 3.12 (Isolated Virtualenv)  
**Total Tests:** 253 Automated Tests (100% Passing)

---

## 1. Prerequisites & Environment Setup

Ensure your local environment has the virtualenv activated and dependencies installed:

```powershell
# Windows
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Linux / macOS
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Test Execution Commands

### Run Full Test Suite
```powershell
pytest -v tests/
```

### Run Concise Summary
```powershell
pytest -q
```

### Run Specific Test Modules
```powershell
# Run security regression tests
pytest -v tests/unit/test_security_hardening.py

# Run QR decoder tests
pytest -v tests/unit/test_qr_decoder.py

# Run URL heuristic analysis tests
pytest -v tests/unit/test_url_analyzer.py

# Run SSRF redirect inspection tests
pytest -v tests/unit/test_redirect_inspector.py

# Run threat intelligence tests
pytest -v tests/unit/test_threat_intelligence.py

# Run Cyber Safety Academy integration tests
pytest -v tests/integration/test_academy_routes.py
```

---

## 3. Test Organization & Coverage Matrix

The test suite is organized into two primary tiers: `tests/unit/` for isolated algorithmic testing and `tests/integration/` for end-to-end Flask workflows.

| Test File | Test Count | Category | Key Behaviors Verified |
| :--- | :---: | :--- | :--- |
| `tests/unit/test_security_hardening.py` | 27 | Security & Privacy | Uniform JSON errors (400, 404, 405, 413, 429, 500), XSS & dangerous URI schemes, SQL injection search resilience, image decompression bombs, SSRF blocks, constant-time admin auth, sliding window rate limiting, ReportLab XML sanitization, sensitive token masking. |
| `tests/unit/test_url_analyzer.py` | 19 | Heuristics | 12 static rules, brand impersonation in subdomains, userinfo credentials, Punycode/IDN, IP hosts, shorteners, length boundaries, offline zero-outbound validation. |
| `tests/unit/test_risk_scorer.py` | 20 | Risk Engine | Deterministic 0–100 scoring, correlated indicator discounting, category thresholds (Low, Medium, High, Critical), Inconclusive handling. |
| `tests/unit/test_qr_decoder.py` | 11 | Computer Vision | In-memory OpenCV decoding, Pillow header validation, multi-pass detection, string truncation, empty/corrupt handling. |
| `tests/unit/test_payload_classifier.py` | 20 | Payload Classification | 12 payload formats, Wi-Fi password masking, UPI payment extraction, safe display copies. |
| `tests/unit/test_redirect_inspector.py` | 20 | Network Safety | SSRF blocks (loopback, RFC1918, AWS/GCP metadata), dual-homed DNS rejections, single-hop manual requests, max 5 hops, loops, scheme downgrades. |
| `tests/unit/test_threat_intelligence.py` | 18 | Threat Feeds | Safe Browsing API client, sensitive URL privacy skipping, mocked malicious/clean responses, timeout and quota error handling. |
| `tests/unit/test_pdf_reporter.py` | 13 | Reporting | In-memory PDF generation, table formatting, control character sanitization, disclaimers. |
| `tests/unit/test_quiz_service.py` | 20 | Education | 36 bilingual questions, server-side answer checking, performance tiers, deduplication. |
| `tests/unit/test_db.py` & `test_history_db.py` | 30 | Database | Parameterized queries, schema idempotency, pagination clamping, search filters, deletion. |
| `tests/unit/test_awareness.py` | 14 | Awareness | Scam scenario definitions, taxonomy categories, localized resources. |
| `tests/integration/test_routes.py` | 15 | Flask Routes | View routing, navigation links, layout rendering. |
| `tests/integration/test_api_history.py` | 5 | API Workflows | Scan creation, history listing, record retrieval, record deletion. |
| `tests/integration/test_history_and_admin_routes.py` | 8 | History & Admin | Admin summary metrics, health checks, admin key auth enforcement, live & historical PDF endpoints. |
| `tests/integration/test_academy_routes.py` | 18 | Academy API | Category listing, start quiz, answer validation, evaluate submission, bilingual support. |
| `tests/integration/test_awareness_routes.py` | 3 | Awareness API | Awareness page rendering, English & Tamil locale JSON endpoints. |
| `tests/integration/test_results_experience.py` | 12 | User Flows | Full end-to-end QR upload -> decode -> analyze -> score -> report flow. |

---

## 4. Mocking Strategy & Safety Principles

1. **Zero External Network Connections:**  
   Automated tests **never** initiate external network requests.
   - Socket operations (`socket.getaddrinfo`, `socket.socket`) are mocked with `unittest.mock.patch`.
   - Threat intelligence HTTP requests (`urllib.request.urlopen`) are mocked with synthetic HTTP 200, 401, 429, and 500 fixtures.
   - Redirect inspection requests are mocked via dependency injection on the single-hop executor.
2. **Ephemeral In-Memory Database:**  
   Integration tests use SQLite shared memory (`TestingConfig.DATABASE_PATH = ':memory:'`). Every test fixture executes `DELETE FROM scan_history` ensuring complete isolation between test runs.
3. **Synthetic Image Generation:**  
   QR decoder tests generate clean synthetic QR codes in RAM using the `qrcode` library; no proprietary or external image files are required.

---

## 5. Known Testing Boundaries

- **Browser DOM & Rendering:** Client JavaScript execution is verified through route integration tests and response schema assertions. Full browser-level end-to-end testing (e.g. Selenium/Playwright) is not included in the standard CI pipeline to keep the test suite lightweight, dependency-free, and fast (executing in under 5 seconds).
