# QShield Project Status & Feature Verification Matrix

**Project:** QShield — QR Phishing Detection & Awareness System  
**Tagline:** “Decode the QR. Detect the Threat.”  
**Milestone:** Prompt 17 — Final Integration, Verification & Deployment Readiness  
**Verification Date:** October 2026  
**Test Suite Summary:** 253 passed / 253 total (100% passing across unit, integration, and security regression suites)

---

## 1. Feature Status Matrix

| Feature | Implementation Status | Verification Status | Known Issues & Findings |
| :--- | :--- | :--- | :--- |
| **QR image upload** | **Implemented** (`POST /api/decode-qr`, `POST /scanner`, `scan.html`) | **Verified & Tested** (`test_qr_decoder.py`, `test_scanner.py`, `test_security_hardening.py`) | Enforces 5 MB limit, checks image headers via Pillow, processes in-memory bytes without saving to disk. Empty files and oversized files return HTTP 400 and 413 respectively. |
| **QR decoding** | **Implemented** (`app/core/qr_decoder.py`) | **Verified & Tested** (`test_qr_decoder.py`) | Multi-pass OpenCV (`cv2.QRCodeDetector`): standard RGB, grayscale enhancement, adaptive thresholding. Includes decompression bomb protections (max 4096×4096 px / 16 MP limit). |
| **URL analysis** | **Implemented** (`app/core/url_analyzer.py`, `app/core/rules_config.py`) | **Verified & Tested** (`test_url_analyzer.py`) | 12 static structural rules: userinfo `@` credential deception, raw IP hosts, Punycode/IDN, brand spoofing, credential keywords, long URLs, shorteners, unusual ports. 100% offline via `tldextract`. Zero outbound requests. |
| **Risk scoring** | **Implemented** (`app/core/risk_scorer.py`) | **Verified & Tested** (`test_risk_scorer.py`) | Deterministic weighted scoring (0–100 scale: Low, Medium, High, Critical). Non-URL or empty inputs evaluate cleanly as `Inconclusive`. Provides actionable recommendations and technical explanations. |
| **Payload classification** | **Implemented** (`app/core/payload_classifier.py`) | **Verified & Tested** (`test_payload_classifier.py`) | 12 format categories: URL, Wi-Fi (WPA/WEP), Contact (vCard), Calendar (VEVENT), Payment (UPI), Tel, Email, SMS, Geo, Plain Text, Structured Other, Unknown. Wi-Fi passwords masked (`••••••••`). |
| **Threat intelligence** | **Implemented** (`app/core/threat_intelligence.py`, `POST /api/check-reputation`) | **Verified & Tested** (`test_threat_intelligence.py`) | Optional Google Safe Browsing API v4 client. Requires explicit user consent. Automatically skips URLs containing credentials, tokens, or JWTs. Fails gracefully if unconfigured or unreachable. |
| **Redirect inspection** | **Implemented** (`app/core/redirect_inspector.py`, `POST /api/inspect-redirects`) | **Verified & Tested** (`test_redirect_inspector.py`) | Explicit consent required. Single-hop manual stepping (max 5 hops). Strict SSRF block for loopback, RFC1918 private IPs, and AWS/GCP cloud metadata. Blocks dual-homed DNS rebinding. |
| **Scan history** | **Implemented** (`app/database/db_manager.py`, `GET /api/scan-history`, `history.html`) | **Verified & Tested** (`test_db.py`, `test_history_db.py`, `test_api_history.py`) | Parameterized SQLite queries. Strict Privacy-by-Design: stores only sanitized domain hostnames and metrics. Raw payloads and query tokens are NEVER stored. Supports filtering, search, and individual deletion. |
| **PDF reports** | **Implemented** (`app/core/pdf_reporter.py`, `POST /api/scan-report/generate`, `GET /api/scan-history/<id>/report`) | **Verified & Tested** (`test_pdf_reporter.py`, `test_security_hardening.py`) | Generates live scan and historical metadata audit PDFs in-memory via ReportLab. Sanitizes XML injection and strips ASCII control characters (`\x00-\x1f`). Masks sensitive URL query parameters. |
| **Tamil/English UI** | **Implemented** (`locales/en.json`, `locales/ta.json`, `/api/locale/<lang>`) | **Verified & Tested** (`test_awareness.py`, `test_awareness_routes.py`) | Full bilingual support for Awareness Centre and Academy pages. Instant language toggle with persistent storage in browser `localStorage`. Acronyms (DNS, URL) kept in Latin for clarity. |
| **Awareness centre** | **Implemented** (`app/templates/awareness.html`, `app/static/js/awareness.js`) | **Verified & Tested** (`test_awareness_routes.py`) | 6 realistic scam scenarios (Fake UPI, Parking Meter, Malicious Wi-Fi, Shortener Trap, Quishing, vCard Exploit), interactive scam simulator, threat taxonomy, verifiable safety checklist. |
| **Quiz system** | **Implemented** (`quiz_data/en.json`, `quiz_data/ta.json`, `app/core/quiz_service.py`, `academy.html`) | **Verified & Tested** (`test_quiz_service.py`, `test_academy_routes.py`) | 36 bilingual questions across 6 categories. Server-side answer validation without leaking correct answers upfront. Explanations, takeaways, performance tiers, progress tracking. |
| **Admin dashboard** | **Implemented** (`app/templates/admin.html`, `app/static/js/admin.js`, `/api/admin/*`) | **Verified & Tested** (`test_history_and_admin_routes.py`, `test_security_hardening.py`) | Aggregated telemetry computed from real SQLite records. Operational health checks without leaking secrets. Requires `X-Admin-Key` header with constant-time verification; disabled in production if unset. |
| **Security controls** | **Implemented** (`app/__init__.py`, `app/core/rate_limiter.py`, `config.py`) | **Verified & Tested** (`test_security_hardening.py`) | Full CSP, Permissions-Policy, nosniff, Referrer-Policy, Cache-Control: no-store on sensitive endpoints, uniform JSON error handlers (400, 404, 405, 413, 429, 500), in-memory sliding window rate limiter. |

---

## 2. Component Health & Architecture Validation

- **Application Entry Point:** [`run.py`](file:///c:/Users/jaivj/OneDrive/Desktop/QShield/run.py) correctly instantiates Flask via `create_app()` and reads `FLASK_ENV`, `FLASK_DEBUG`, `HOST`, and `PORT`.
- **WSGI Callable:** Verified that `run:app` functions properly for Gunicorn and containerized deployments.
- **Blueprint Isolation:** Routes are cleanly partitioned into `main_bp` (`app/routes/main.py`) for views and `api_bp` (`app/routes/api.py`) for JSON endpoints.
- **Database Lifecycle:** Database connections are tied to the Flask application context using `teardown_appcontext(close_db)` and initialized idempotently via `init_db(app)`.
- **No Duplicate Routes:** Audited route table; all endpoints have unique names and methods.

---

## 3. Operational & Environmental Limitations

1. **In-Memory Rate Limiting:** The sliding window rate limiter protects against rapid abuse in single-process or local development setups. Multi-worker production clusters require a distributed Redis backend.
2. **ReportLab Font Constraints:** Standard PDF typography utilizes Helvetica and Courier. Full non-Latin scripts (e.g. Tamil characters) in PDF exports fall back to clean Romanized/English summaries.
3. **Ephemeral Hosting Filesystems:** On free cloud tiers with ephemeral filesystems (e.g., Render free tier), the SQLite database resets on service restart unless a persistent disk volume is mounted.
