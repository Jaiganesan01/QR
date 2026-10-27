# QShield Comprehensive Application Security & Privacy Audit

**Application:** QShield — QR Phishing Detection & Awareness System  
**Tagline:** “Decode the QR. Detect the Threat.”  
**Audit Phase:** Prompt 16 — Security Hardening, Privacy Audit & Application Protection  
**Target Environment:** Python 3.12, Flask 3.0.3, OpenCV (opencv-python-headless 4.9.0.80), Pillow 10.3.0, SQLite 3, ReportLab 5.1.0  
**Audit Standard:** OWASP Top 10 (2021), ASVS Level 2 guidelines, Privacy-by-Design principles.

---

## 1. Audit Scope & Methodology

The security audit covered all active layers of the QShield codebase:
1. **Network & Routing Boundary:** Flask app factory (`app/__init__.py`), public routes (`app/routes/main.py`), and REST API endpoints (`app/routes/api.py`).
2. **File Processing & Media Decoding:** In-memory OpenCV and Pillow QR matrix extraction (`app/core/qr_decoder.py`).
3. **Payload Inspection & URL Analysis:** Format classification (`app/core/payload_classifier.py`), static structural heuristic scoring (`app/core/url_analyzer.py`, `app/core/risk_scorer.py`), and rule configurations (`app/core/rules_config.py`).
4. **Network Fetching & External Integrations:** Google Safe Browsing client (`app/core/threat_intelligence.py`) and step-by-step redirect tracer (`app/core/redirect_inspector.py`).
5. **Data Layer & Persistence:** SQLite manager and SQL queries (`app/database/db_manager.py`, `app/database/schema.sql`).
6. **Reporting:** ReportLab PDF generator (`app/core/pdf_reporter.py`).
7. **Administrative Observability:** Dashboard and metrics endpoints (`app/routes/api.py`, `app/templates/admin.html`, `app/static/js/admin.js`).
8. **Client-Side Rendering:** Templates (`app/templates/`), DOM manipulation (`app/static/js/`), and styling.

---

## 2. Complete Security Inventory

| Component & Entry Point | Data Received & Processed | Trust Boundary | Potential Threats | Existing Protections (Pre-Audit) | Confirmed Vulnerabilities / Gaps | Remediation & Priority |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`POST /api/decode-qr`** | Multipart image file (`qr_file`), raw binary bytes | Untrusted public client | Image decompression bombs, memory exhaustion, arbitrary file execution, buffer overflow | Pillow header format check, in-memory decoding, 5MB size limit | No dimension bounds (e.g. 50k x 50k pixel bomb); missing rate limiting | Enforce max 4096×4096 / 16MP dimensions, catch `DecompressionBombError`, apply 30 req/min rate limit. **(High)** |
| **`POST /api/analyze-url`** | JSON body `{"url": "..."}` | Untrusted public client | SSRF, ReDoS, XSS, malformed URL parsing crashes | Static parser, strictly offline `tldextract`, no outbound network requests | Missing rate limiting; URLs could trigger excessive processing if unbounded | Enforced 2048-char maximum URL length, applied 60 req/min rate limit. **(Medium)** |
| **`POST /api/check-reputation`** | JSON body `{"url": "...", "user_consent": bool}` | Untrusted public client to third-party Google Safe Browsing API | Credential leakage to third parties, quota exhaustion, spoofing | Requires consent flag, URL structure check, sensitive query parameter filtering | Missing rate limiting; provider errors could crash endpoint | Rate limit (15 req/min), bounded 64KB response parsing, strict privacy token skipping. **(High)** |
| **`POST /api/inspect-redirects`** | JSON body `{"url": "...", "user_consent": bool}` | Server-initiated HTTP connections to external web servers | Server-Side Request Forgery (SSRF), DNS rebinding, internal network port scanning, cloud metadata theft | Loopback/RFC1918 blocks, metadata IP blocks, max 5 hops, no auto-redirects | Multiple DNS queries could permit rebinding if dual-homed; missing rate limiting | Dual-homed DNS validation (any private IP rejects host), rate limit (15 req/min). **(High)** |
| **`GET /api/scan-history`** | Query parameters `page`, `limit`, `search`, `status` | Untrusted public client to SQLite DB | SQL injection, denial of service via unbounded pagination | Parameterized queries (`?`), integer casting | Missing centralized JSON 404/400 error handling for malformed IDs/parameters | Enforce integer clamping (`max(1, min(limit, 100))`), parameterized substring searches. **(Medium)** |
| **`GET /api/scan-history/<id>` & `DELETE`** | URL path parameter `scan_id` | Untrusted public client | ID manipulation, SQL injection, deletion of arbitrary records | Flask `<int:scan_id>` route converter, parameterized SQL | Flask converter returned default HTML 404/500 rather than uniform JSON error | Implemented global JSON error handlers for 400, 404, 405, 500 on all `/api/*` routes. **(High)** |
| **`GET /api/admin/summary` & `/admin/health`** | HTTP headers (`X-Admin-Key`) or query parameter `api_key` | Public web to privileged operational telemetry | Information disclosure of server configuration, database stats, and operational health | Production block if `ADMIN_API_KEY` not configured | Standard string comparison (`!=`) susceptible to timing attacks; missing `ADMIN_API_KEY` in `.env.example` | Constant-time comparison (`hmac.compare_digest`), documented `.env.example`. **(Medium)** |
| **`POST /api/scan-report/generate` & `GET /api/.../report`** | JSON scan results, database metadata | Client input to ReportLab PDF engine | PDF markup injection, XML parser crash, memory exhaustion via long strings | HTML entity escaping (`html.escape`) | Control character injection (`\x00`, `\x0c`) could cause ReportLab parser failure | Strip control chars, clamp string lengths to 2048 chars, enforce rate limit (20 req/min). **(Medium)** |
| **HTTP Responses (All Routes)** | HTTP response headers | Browser client | Clickjacking, MIME sniffing, XSS, camera/mic hijacking, proxy cache leakage | Partial headers (`nosniff`, `DENY`, `strict-origin`) | Missing CSP, missing Permissions-Policy, missing Cache-Control on sensitive API/admin routes | Comprehensive CSP, Permissions-Policy, and `Cache-Control: no-store` on `/api/`, `/admin`, `/history`. **(High)** |

---

## 3. Confirmed Vulnerabilities & Implemented Hardening

### Finding 1: Missing Uniform JSON Error Responses & Potential Stack Trace Leakage
- **Severity:** HIGH
- **Vulnerability:** Unhandled routes, invalid HTTP methods, or uncaught server errors on `/api/*` paths defaulted to Werkzeug/Flask HTML error templates. In development or misconfigured environments, full interactive debug tracebacks exposed file paths and source lines.
- **Evidence:** Querying `/api/nonexistent` or sending `POST` to `/api/admin/summary` returned HTML error pages instead of machine-readable JSON.
- **Remediation:** Registered centralized error handlers in `app/__init__.py` for HTTP 400, 404, 405, 413, 429, and 500. All `/api/*` requests consistently return structured JSON (`{"success": false, "error_code": "...", "message": "..."}`) without leaking internal file paths or stack traces.

### Finding 2: Incomplete Security Headers (Missing CSP, Permissions-Policy, Cache-Control)
- **Severity:** HIGH
- **Vulnerability:** The application omitted Content-Security-Policy (CSP) headers, Permissions-Policy headers, and sensitive route cache controls. Without CSP, browsers lacked defense-in-depth against injected scripts or malicious frames.
- **Remediation:** Enhanced `@app.after_request` in `app/__init__.py`:
  - Added strict CSP directives: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`.
  - Added `Permissions-Policy: camera=(self), microphone=(), geolocation=(), payment=()`.
  - Added `Cache-Control: no-store, no-cache, must-revalidate, private` and `Pragma: no-cache` for `/api/*`, `/admin`, and `/history` endpoints.

### Finding 3: Image Decompression Bomb Risk in QR Decoding
- **Severity:** MEDIUM
- **Vulnerability:** While file size was limited to 5 MB, malicious PNG/JPEG files could define extreme pixel dimensions (e.g. 50,000 × 50,000 pixels), which upon decompression during OpenCV matrix decoding could exhaust host RAM.
- **Remediation:** Updated `app/core/qr_decoder.py` with strict dimension limits (`MAX_IMAGE_WIDTH = 4096`, `MAX_IMAGE_HEIGHT = 4096`, `MAX_IMAGE_PIXELS = 16_000_000`), Pillow `Image.MAX_IMAGE_PIXELS` enforcement, and explicit handling of `Image.DecompressionBombError`.

### Finding 4: Timing Side-Channel in Administrative Key Verification
- **Severity:** LOW/MEDIUM
- **Vulnerability:** Verification of `ADMIN_API_KEY` in `_check_admin_auth()` used standard Python string equality (`!=`), which terminates comparison on the first mismatched byte, creating a theoretical timing side-channel.
- **Remediation:** Replaced comparison with constant-time cryptographic verification using `hmac.compare_digest(provided_key.encode('utf-8'), admin_key.encode('utf-8'))`.

### Finding 5: ReportLab XML Parser Fragility with ASCII Control Characters
- **Severity:** LOW/MEDIUM
- **Vulnerability:** ReportLab flowable Paragraphs parse XML-like syntax. If untrusted input contains raw ASCII control characters (such as `\x00` through `\x08`, `\x0b`, `\x0c`), the ReportLab XML parser can raise exceptions or abort PDF generation.
- **Remediation:** Enhanced `_sanitize()` in `app/core/pdf_reporter.py` to strip ASCII control characters (`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`), clamp cell string lengths to 2048 characters to prevent layout overflow, and escape XML entities.

### Finding 6: Lack of Rate Limiting on Resource-Intensive Endpoints
- **Severity:** MEDIUM
- **Vulnerability:** Heavy endpoints (QR decoding, heuristic analysis, redirect tracing, threat reputation lookups, and PDF generation) could be subjected to rapid requests, consuming CPU and third-party quota.
- **Remediation:** Implemented thread-safe in-memory sliding window rate limiter (`app/core/rate_limiter.py`) with configurable thresholds per endpoint and standard HTTP 429 / `Retry-After` responses.

### Finding 7: Sensitive Parameter Redaction in URLs
- **Severity:** LOW
- **Vulnerability:** While `target_domain` stored in the database was already sanitized to hostname only, the application lacked a dedicated utility to mask sensitive parameters (passwords, tokens, keys) in displayed URLs or reports.
- **Remediation:** Added `mask_sensitive_url()` in `app/core/url_analyzer.py` that identifies sensitive parameters (`token`, `auth`, `key`, `password`, `session_id`, userinfo credentials) and replaces values with `[REDACTED]`.

---

## 4. Test Execution & Verification

Comprehensive automated tests were executed to verify security hardening:
- **Baseline Test Suite:** 226/226 passing across all functional modules (QR decoder, URL analyzer, risk scorer, threat intel, payload classifier, redirects, awareness, quizzes, history, admin, PDF reporter).
- **Security Hardening Suite (`tests/unit/test_security_hardening.py`):** Dedicated security regression tests covering:
  - Input validation, malformed payloads, and 400/404/405/413 error formats.
  - SQL injection resilience across history filters and search queries.
  - XSS payload sanitization and dangerous URI scheme rejection (`javascript:`, `data:`, `vbscript:`).
  - Decompression bomb detection and dimension limit rejection.
  - SSRF destination rejection (loopback, private subnets, cloud metadata).
  - Constant-time admin key authorization and production access lockdown.
  - Rate limiter triggering and HTTP 429 response structure.
  - Sensitive parameter masking and PDF control character sanitization.

---

## 5. Unresolved Limitations & Production Recommendations

1. **In-Memory Rate Limiting:** The sliding window rate limiter stores state in process memory. In a multi-worker production deployment (e.g. Gunicorn with 4 workers), rate limits are enforced per-worker rather than globally. A Redis-backed rate limiter (via Flask-Limiter) is recommended for distributed production setups.
2. **Reverse Proxy TLS Termination:** QShield configures application-level security headers, but full HTTPS enforcement (HSTS, secure cookie transmission) requires termination at a reverse proxy (e.g. Nginx, Caddy) in production.
3. **Database File Permissions:** In production deployments, ensure the SQLite database file (`instance/qshield.db`) is readable and writable exclusively by the web server service account (`chmod 600 instance/qshield.db`).
