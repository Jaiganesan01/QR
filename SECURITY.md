# QShield Security Policy & Defensive Model

**Project:** QShield — QR Phishing Detection & Awareness System  
**Tagline:** “Decode the QR. Detect the Threat.”

---

## 1. Supported Versions & Scope

Security updates and vulnerability remediation are actively maintained on the current development baseline:

| Version | Status | Security Updates |
| :--- | :--- | :--- |
| `1.0.0` (Current Development / Main) | Supported | Active patches and hardening |
| `< 1.0.0` | Deprecated | Unsupported |

### In-Scope Components
- Core Flask application factory (`app/__init__.py`), routing (`app/routes/api.py`, `app/routes/main.py`), and configuration (`config.py`).
- In-memory OpenCV QR decoder (`app/core/qr_decoder.py`).
- Static structural URL heuristic analyzer & explainable risk scorer (`app/core/url_analyzer.py`, `app/core/risk_scorer.py`).
- SSRF-shielded HTTP redirect inspector (`app/core/redirect_inspector.py`).
- Threat intelligence abstraction & Google Safe Browsing provider (`app/core/threat_intelligence.py`).
- QR payload classifier (`app/core/payload_classifier.py`).
- In-memory rate limiting engine (`app/core/rate_limiter.py`).
- PDF report generation (`app/core/pdf_reporter.py`).
- SQLite scan history and administrative observability telemetry (`app/database/db_manager.py`).

### Out-of-Scope Scenarios
- Physical optical manipulation / lens-distortion attacks outside digital decoding boundaries.
- Active browser-side exploitation occurring after a user deliberately clicks a malicious link outside QShield.
- Zero-day web vulnerabilities on external third-party threat feeds or target domains.
- Third-party infrastructure attacks (e.g., DNS provider poisoning outside QShield's destination resolution validation).

---

## 2. Reporting a Vulnerability

We prioritize application security, user privacy, and defensive robustness. If you discover a security vulnerability or bypass in QShield, please report it responsibly:

1. **Submission Channel:** Contact the project maintainer via the repository's established private vulnerability disclosure channel or security advisory tab on the host platform.
2. **Details to Include:**
   - Detailed description of the vulnerability, affected endpoint, and threat category.
   - Proof-of-concept (PoC) payload, request headers, or steps to reproduce.
   - Potential impact assessment (e.g., SSRF, XSS, DoS, information disclosure).
   - Any proposed remediation or patch if available.
3. **Disclosure Conduct:**
   - Please allow maintainers reasonable time to verify, triage, and patch the issue before public disclosure.
   - Do NOT exploit the issue against production systems or third-party targets.
   - Never use real malicious destinations or perform unauthorized network flooding.

---

## 3. Security Architecture & Threat Mitigations

QShield implements layered defense-in-depth:

### A. Zero-Outbound Default & SSRF Prevention
- Standard QR scanning and URL analysis are **100% offline and static**. No network sockets are opened during ordinary scanning.
- Optional redirect tracing is strictly opt-in, requires explicit user consent, and enforces comprehensive SSRF guards:
  - Blocks RFC1918 private IPv4 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Blocks IPv4 and IPv6 loopback addresses (`127.0.0.0/8`, `::1`).
  - Blocks cloud provider metadata endpoints (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`, `metadata.google.internal`).
  - Re-evaluates destination safety at every single hop before establishing connections.
  - Automatically terminates redirect loops and enforces a hard limit of 5 hops.
  - Validates all resolved IP addresses (rejecting dual-homed / DNS rebinding attempts resolving to private IPs).

### B. Input Validation & Upload Hardening
- File uploads are constrained to maximum 5 MB (`MAX_CONTENT_LENGTH`) at both the web server and application layers.
- In-memory decoding with OpenCV and Pillow enforces image dimension limits (maximum 4096×4096 pixels, 16 megapixels) and catches decompression bomb exploits (`Image.DecompressionBombError`).
- Uploaded files are processed strictly in RAM (`io.BytesIO`) without writing temporary files to disk.
- Non-image files, misleading file extensions, and empty files are rejected prior to pixel processing.

### C. Cross-Site Scripting (XSS) Defenses
- Jinja2 templates enforce automatic HTML escaping for all dynamic variables.
- Client-side DOM scripts (`scanner.js`, `history.js`, `academy.js`, `admin.js`) assign untrusted values via `textContent` rather than `innerHTML`.
- Where HTML formatting is necessary, all dynamic values pass through dedicated string-escaping routines (`escapeHtml`).
- Restrictive Content-Security-Policy (CSP) prevents framing (`frame-ancestors 'none'`) and limits resource loading origins.

### D. SQL Injection & Database Safety
- SQLite queries in `db_manager.py` exclusively use parameterized queries (`?` placeholders).
- Pagination parameters (`limit`, `offset`, `page`) are bounded with strict integer sanitization (`max(1, min(limit, 100))`).
- Search filters execute parameterized substring matching.
- Database access uses context teardown hooks (`close_db`) ensuring connections close cleanly.

### E. Rate Limiting & Resource Exhaustion Defense
- In-memory sliding window rate limiter protects CPU-intensive endpoints:
  - QR decoding: 30 requests/min
  - URL heuristic analysis: 60 requests/min
  - Threat reputation lookups: 15 requests/min
  - Redirect inspections: 15 requests/min
  - PDF report exports: 20 requests/min
- Exceeding thresholds yields standard HTTP 429 responses with `Retry-After` headers.

### F. Administrative Authorization
- Admin telemetry (`/api/admin/summary`, `/api/admin/health`) requires `ADMIN_API_KEY` verification via `X-Admin-Key` header.
- Token comparisons execute using constant-time cryptographic verification (`hmac.compare_digest`) to prevent timing side channels.
- In production environments (`DEBUG=False`), administrative endpoints fail-closed (HTTP 403) if `ADMIN_API_KEY` is unset.

---

## 4. Operational Assumptions & Limitations

1. **Heuristic Nature:** Static heuristic risk scores are educational and defensive; they do not constitute mathematical proof that an unflagged URL is harmless.
2. **Threat Feed Latency:** External threat intelligence (Google Safe Browsing) catalogs known threats; zero-day phishing sites may not yet be indexed.
3. **Single-Node Rate Limiter:** The built-in rate limiter operates in-process memory. Distributed multi-process production deployments (e.g., Gunicorn with multiple workers) should pair with a centralized Redis backend via Flask-Limiter.
4. **HTTPS Deployment:** While HTTP headers are configured defensively, full transport security requires deploying behind an HTTPS-terminating reverse proxy (Nginx, Caddy, or Cloudflare) with valid TLS certificates.
