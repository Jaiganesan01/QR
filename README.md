# QShield — QR Phishing Detection & Awareness System
> **Tagline:** *Decode the QR. Detect the Threat.*

---

## 1. Project Overview

**QShield** is a defensive cybersecurity platform engineered to protect users from QR-code-based social engineering attacks (*Quishing*). Designed with a **Privacy-by-Design** philosophy, QShield enables users to inspect unknown QR codes in-memory, classify their optical payload formats, evaluate lexical and structural threat indicators through an explainable heuristic scoring engine, safely trace redirect hops, and acquire practical defensive skills via an interactive bilingual (English & Tamil) Cyber Safety Academy.

---

## 2. Problem Statement

With the widespread adoption of contactless menus, smart parking meters, digital billboards, and UPI payments, QR codes have become ubiquitous. However, because QR codes are visually opaque matrices, human eyes cannot differentiate between a legitimate URL and a deceptive link. Attackers exploit this blind spot by placing physical stickers over legitimate QR codes or embedding them into phishing emails (*Quishing*). Traditional email security gateways and secure web gateways often fail to intercept quishing attacks because the malicious destination is encoded in an image rather than hyperlinked text.

---

## 3. Proposed Solution

QShield provides a secure, sandboxed client-server architecture that intercepts the quishing vector before interaction:
1. **Zero-Outbound In-Memory Decoding:** Decodes optical matrices in RAM using OpenCV without writing uploaded files to disk or automatically opening destination URLs.
2. **Payload Classification:** Identifies 12 payload formats (URLs, Wi-Fi, vCard, UPI payments, SMS, emails, phone numbers) and masks confidential credentials.
3. **Static Heuristic Risk Engine:** Inspects structural lexical features (brand spoofing in subdomains, userinfo `@` deception, raw IP hosts, Punycode, suspicious ports, shorteners) offline with zero outbound network calls.
4. **SSRF-Shielded Redirect Tracing:** Safely steps through HTTP redirects hop-by-hop with strict loopback, RFC1918, and cloud metadata destination blocks.
5. **Privacy-Preserving Audit History:** Persists only coarse domain-level metadata; full URLs, tokens, and query strings are never stored.
6. **Bilingual Awareness & Academy:** Educates vernacular users in Tamil and English with realistic threat simulations and interactive quizzes.

---

## 4. Primary Objectives

- **Defensive Inspection:** Provide reliable in-memory decoding and static analysis of QR codes without executing dynamic scripts.
- **Explainable Threat Scoring:** Present an understandable, deterministic 0–100 risk score with clear technical evidence rather than an opaque black box.
- **Absolute User Privacy:** Guarantee that sensitive data (passwords, payment pins, personal query tokens) are never persisted or logged.
- **Community Education:** Bridge the cybersecurity awareness gap for non-technical users in English and Tamil (தமிழ்).

---

## 5. Key Features

- **Live Camera QR Scanner:** Real-time camera preview, scanning reticle overlay with animated laser, device switching, and dual-strategy decoding (browser-native `BarcodeDetector` + backend OpenCV canvas fallback) with duplicate prevention and anti-auto-open safeguards.
- **In-Memory Optical Decoder:** OpenCV (`cv2.QRCodeDetector`) with multi-pass RGB, enhanced grayscale, and adaptive thresholding.
- **Decompression Bomb Protection:** Restricts upload file size to 5 MB and dimensions to 4096×4096 pixels (16 MP).
- **12-Format Payload Classifier:** Identifies URLs, Wi-Fi configs, vCards, UPI intents, telephone, SMS, email, geo coordinates, and custom URI schemes.
- **12 Static Heuristic Rules:** Analyzes URL syntax with an offline `tldextract` engine—strictly zero outbound network calls.
- **Safe Redirect Inspector:** Multi-hop redirect stepping enforcing strict SSRF blocks against private and cloud metadata addresses.
- **Optional Threat Feed:** Google Safe Browsing API v4 client with mandatory user consent and sensitive URL privacy filtering.
- **PDF Security Reports:** In-memory ReportLab generation of live audit reports and historical summaries with XML injection guards.
- **Bilingual Awareness & Academy:** 6 scam simulations, threat taxonomy, and 36 bilingual quiz questions across 6 categories.
- **Admin Observability:** Real-time database metrics protected by `ADMIN_API_KEY` with constant-time verification.
- **Hardened Security Architecture:** Strict CSP (`frame-ancestors 'none'`), Permissions-Policy, Referrer-Policy, nosniff, and sliding window rate limiting.

---

## 6. Technology Stack

- **Backend:** Python 3.12, Flask 3.0.3, Werkzeug 3.0.3, python-dotenv 1.0.1
- **Computer Vision & Imaging:** OpenCV (`opencv-python-headless 4.9.0.80`), Pillow 10.3.0, NumPy 1.26.4
- **URL & Domain Parsing:** `tldextract 5.1.2` (offline mode), `dnspython 2.6.1`
- **Database:** SQLite 3 (Standard Library `sqlite3`)
- **PDF Reporting:** ReportLab 5.1.0
- **Frontend:** HTML5, CSS3, Vanilla JavaScript (zero external JS runtime dependencies)
- **Production WSGI:** Gunicorn 22.0.0 (Linux/macOS)
- **Testing:** Pytest 8.2.0, Qrcode 8.2

---

## 7. System Requirements

- **Operating System:** Windows 10/11, macOS 12+, or Linux (Ubuntu 20.04+, Debian 11+)
- **Python Version:** Python 3.10, 3.11, or 3.12 (Recommended: 3.12)
- **RAM:** Minimum 512 MB (1 GB recommended)
- **Disk Space:** ~200 MB for repository, virtualenv, and dependencies

---

## 8. Repository Folder Structure

```
QShield/
├── app/
│   ├── __init__.py               # Flask factory, unified error handlers, CSP security headers
│   ├── core/
│   │   ├── qr_decoder.py         # OpenCV in-memory decoder & decompression bomb guards
│   │   ├── url_analyzer.py       # 12 static heuristic rules & sensitive URL masking
│   │   ├── risk_scorer.py        # Weighted 0-100 scoring engine with family discounting
│   │   ├── rules_config.py       # Configurable brand list, shorteners, and thresholds
│   │   ├── payload_classifier.py # 12-category optical payload classification & password masking
│   │   ├── redirect_inspector.py # SSRF-shielded single-hop redirect inspector
│   │   ├── threat_intelligence.py# Google Safe Browsing v4 client & privacy scrubber
│   │   ├── rate_limiter.py       # Thread-safe in-memory sliding window rate limiter
│   │   ├── pdf_reporter.py       # In-memory ReportLab PDF generator & XML sanitizer
│   │   └── quiz_service.py       # Cyber Safety Academy quiz evaluator & answer verifier
│   ├── database/
│   │   ├── __init__.py           # Package exports for DB helpers
│   │   ├── schema.sql            # SQLite DDL schema for privacy-preserving scan_history
│   │   └── db_manager.py         # Parameterized SQLite queries, bounds, and lifecycle
│   ├── routes/
│   │   ├── main.py               # View routes (/, /scanner, /awareness, /academy, /history, /admin)
│   │   └── api.py                # REST endpoints (/decode-qr, /analyze-url, /scan-history, etc.)
│   ├── static/
│   │   ├── css/                  # SaaS design system (variables.css, main.css)
│   │   ├── js/                   # Vanilla controllers (scanner.js, history.js, academy.js, admin.js)
│   │   └── images/               # Vector branding (logo-shield.svg)
│   └── templates/                # Jinja2 templates (index.html, scan.html, academy.html, etc.)
├── docs/                         # Technical documentation
│   ├── ARCHITECTURE.md           # System architecture, flows, and Mermaid diagrams
│   ├── API.md                    # Complete REST API endpoint reference
│   ├── TESTING.md                # Test execution guide and mocking methodology
│   ├── PROJECT_DEMO.md           # 5-minute demo script, scenarios, and 20+ viva Q&As
│   └── HEURISTICS_SPEC.md        # Heuristic scoring rules and weighting specifications
├── locales/                      # Bilingual awareness dictionaries
│   ├── en.json                   # English awareness content and safety checklist
│   └── ta.json                   # Tamil (தமிழ்) translation catalog
├── quiz_data/                    # Academy bilingual question banks
│   ├── en.json                   # 36 English questions across 6 categories
│   └── ta.json                   # 36 Tamil questions with native explanations
├── tests/                        # Automated test suites (253 tests)
│   ├── unit/                     # Unit test modules (decoder, analyzer, scorer, security)
│   └── integration/              # Flask route, DB lifecycle, and API workflow tests
├── config.py                     # Configuration profiles (Development, Production, Testing)
├── run.py                        # Application entry point and WSGI app exporter
├── requirements.txt              # Pinned Python package dependencies
├── Procfile                      # Process configuration for Gunicorn deployment
├── render.yaml                   # Infrastructure-as-code deployment configuration for Render
├── PROJECT_STATUS.md             # Complete feature status and verification matrix
├── SECURITY.md                   # Security policy, threat models, and disclosure guidelines
├── PRIVACY.md                    # Data minimization and privacy-by-design policy
├── SECURITY_AUDIT.md             # Comprehensive security inventory, findings, and remediations
├── .env.example                  # Environment variable template
└── .gitignore                    # Version control exclusion rules
```

---

## 9. Installation & Local Setup

### Step 1: Clone Repository & Create Virtual Environment
```powershell
# Windows Command Prompt or PowerShell
git clone https://github.com/your-username/qshield.git
cd QShield
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
git clone https://github.com/your-username/qshield.git
cd QShield
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
```powershell
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```
*(Optional)* Open `.env` to configure your `SECRET_KEY`, `ADMIN_API_KEY`, or `GOOGLE_SAFE_BROWSING_API_KEY`.

### Step 4: Run Tests to Verify Integrity
```powershell
pytest -v tests/
```

### Step 5: Start the Development Server
```powershell
python run.py
```
Open your browser to: **`http://127.0.0.1:5000`**

---

## 10. QR Scanning & Inspection Workflow

1. Navigate to `/scanner`.
2. **Upload QR Code:** Drag and drop an image file (PNG, JPG, WebP) or click "Browse Image".
3. **In-Memory Decoding:** The server verifies file size and dimensions, extracts pixels into OpenCV, and decodes the QR string in RAM.
4. **Payload Identification:** QShield classifies the payload (e.g. URL, Wi-Fi, vCard). If a Wi-Fi QR is uploaded, the password is masked (`••••••••`).
5. **Static Heuristic Analysis:** Click "Analyze URL Structure" to evaluate 12 lexical rules offline.
6. **Review Findings:** Examine the 0–100 risk score, category badge (Low, Medium, High, Critical), triggered indicator list, and actionable guidance.
7. **Optional Checks:** Opt-in to run Safe Redirect Tracing or Threat Feed queries with explicit user consent.
8. **Export Audit Report:** Click "Download PDF Security Report" to save a self-contained PDF audit.

---

## 11. Heuristic Risk Scoring Methodology & Limitations

> [!IMPORTANT]
> **Heuristic Assessment Notice:**  
> The QShield risk score is an explainable engineering heuristic, **NOT** a calibrated statistical probability of phishing. A "Low Risk" result indicates that no configured deceptive indicators were detected; it is **NOT** a guarantee that an unflagged link is harmless.

### Scoring Scale & Bands
- **0 – 24 (Low Risk):** Clean static structure; standard HTTPS web formatting.
- **25 – 49 (Medium Risk):** Moderate evasion patterns (e.g., URL shortener, unencrypted HTTP, non-standard port).
- **50 – 74 (High Risk):** Strong deceptive signals (e.g., brand token placed in subdomain, credential keywords paired with urgency tokens).
- **75 – 100 (Critical Risk):** Combined severe indicators (e.g., userinfo `@` credential deception, raw IP address host).
- **`null` (Inconclusive):** Assigned when the input is malformed, an unsupported scheme, or a non-URL payload.

---

## 12. Privacy & Data Minimization Architecture

In accordance with **Privacy-by-Design**:
- **Zero Raw Payload Persistence:** Raw QR payloads, decoded text, and image bytes are discarded immediately after request completion.
- **Sanitized Audit History:** SQLite stores only the root domain hostname (e.g., `example.com`), risk score, indicator count, and timestamp. Query parameters, passwords, and authentication tokens are never saved.
- **Credential Redaction:** Wi-Fi passwords and sensitive query tokens are masked in RAM prior to display.
- **User Control:** Users can review, filter, and permanently delete their scan history records via `DELETE /api/scan-history/<id>`.

---

## 13. REST API Reference Overview

Detailed documentation for all 17 endpoints is available in [`docs/API.md`](docs/API.md).

| Method | Endpoint | Description | Rate Limit |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Base system health probe | None |
| `POST` | `/api/decode-qr` | Decode QR image bytes using OpenCV | 30 / min |
| `POST` | `/api/analyze-url` | Static heuristic URL structural analysis | 60 / min |
| `POST` | `/api/check-reputation` | Google Safe Browsing reputation check (Consent required) | 15 / min |
| `POST` | `/api/inspect-redirects` | SSRF-safe single-hop HTTP redirect inspection | 15 / min |
| `GET` | `/api/scan-history` | Paginated non-sensitive scan metadata list | None |
| `GET` | `/api/scan-history/<id>` | Retrieve single scan metadata record | None |
| `DELETE` | `/api/scan-history/<id>` | Delete scan record permanently | None |
| `GET` | `/api/scan-history/<id>/report`| Download historical PDF security summary | 20 / min |
| `POST` | `/api/scan-report/generate`| Generate live full PDF security report | 20 / min |
| `GET` | `/api/admin/summary` | Aggregated operational telemetry metrics (`X-Admin-Key`) | None |
| `GET` | `/api/admin/health` | Operational health and integrations status (`X-Admin-Key`) | None |
| `GET` | `/api/analytics/summary` | Summary KPI metrics across time ranges (`X-Admin-Key`) | None |
| `GET` | `/api/analytics/risk-distribution` | Risk severity proportions and score bands (`X-Admin-Key`) | None |
| `GET` | `/api/analytics/activity` | Time-bucketed scan timeline (hourly/daily) (`X-Admin-Key`) | None |
| `GET` | `/api/analytics/payload-categories` | Proportions across QR format categories (`X-Admin-Key`) | None |
| `GET` | `/api/analytics/detection-methods` | Breakdown of actually executed detection modules (`X-Admin-Key`) | None |
| `GET` | `/api/analytics/indicators` | Observed threat & structural indicators matrix (`X-Admin-Key`) | None |
| `GET` | `/api/analytics/trends` | Period-over-period trend deltas with zero guards (`X-Admin-Key`) | None |
| `GET` | `/api/analytics/export-pdf` | Download audit-ready analytics PDF report (`X-Admin-Key`) | None |
| `GET` | `/api/quiz/categories` | List Cyber Safety Academy categories (`lang=en` or `ta`) | None |
| `POST` | `/api/quiz/start` | Start category quiz (returns questions without answers) | None |
| `POST` | `/api/quiz/check-answer`| Validate single answer and receive explanation | None |
| `POST` | `/api/quiz/evaluate` | Evaluate full quiz submission and assign tier | None |
| `GET` | `/api/locale/<lang>` | Retrieve localization dictionary (`en` or `ta`) | None |

---

## 14. Threat Intelligence & QR Risk Analytics Dashboard

The platform features an interactive **Threat Intelligence Dashboard & QR Risk Analytics** interface accessible at `/admin` and `/analytics`. Key capabilities include:

- **KPI Overview Cards:** Real-time metrics for total scans, high & critical threat assessments, inconclusive payloads, external feed flags, and average evaluated risk.
- **Period-over-Period Trend Analysis:** Dynamic comparisons against preceding equivalent periods (24h, 7d, 30d) with division-by-zero safeguards and small-dataset disclosures.
- **Continuous Timeline Visualizer:** Pure client-rendered responsive SVG chart plotting hourly and daily activity with dual-tone threat segmentation.
- **Risk Severity Distributions:** Proportional segmented progress meters mapped to QShield's 0–100 risk boundaries.
- **Security Findings Matrix:** Frequency tracking of structural anomalies (raw IPs, Punycode, brand mimicry, unusual ports, shorteners) vs confirmed threat feed detections.
- **Audit-Ready PDF Export:** One-click generation of executive threat intelligence reports via ReportLab.
- **Privacy Enforcement:** Zero raw payloads, query parameters, or personal identifiers are stored or exposed.

For full architecture details, consult [`docs/ANALYTICS_DASHBOARD.md`](docs/ANALYTICS_DASHBOARD.md) and [`docs/ANALYTICS_METHODOLOGY.md`](docs/ANALYTICS_METHODOLOGY.md).

---

## 15. Automated Testing

QShield maintains a 100% passing automated test suite with **299 tests**:

```powershell
# Run the full test suite
pytest -v tests/

# Run camera scanner unit & integration tests
pytest -v tests/unit/test_camera_scanner.py

# Run threat analytics unit and integration tests
pytest -v tests/unit/test_threat_analytics.py tests/integration/test_analytics_routes.py

# Run security regression tests
pytest -v tests/unit/test_security_hardening.py
```

See [`docs/TESTING.md`](docs/TESTING.md) for mocking strategies and test suite architecture.

---

## 16. Production Deployment Instructions

### Deploying to Render / Railway / Linux VPS

1. **Procfile & WSGI:** The repository includes a `Procfile` configured for Gunicorn:
   ```
   web: gunicorn --bind 0.0.0.0:$PORT "run:app"
   ```
2. **Infrastructure as Code:** A `render.yaml` blueprint is included for one-click Render deployment.
3. **Environment Variables for Production:**
   - `FLASK_ENV=production`
   - `FLASK_DEBUG=0`
   - `SECRET_KEY=<cryptographically-random-string>`
   - `ADMIN_API_KEY=<strong-administrative-token>`
   - `RATELIMIT_ENABLED=true`
4. **Persistent Storage Notice:** On cloud platforms with ephemeral filesystems (e.g. Render free tier), the SQLite database resets on service restart unless a persistent disk volume is mounted at the directory specified by `DATABASE_PATH`.

---

## 17. Known Limitations & Future Roadmap

### Known Limitations
1. **Static Analysis Scope:** QShield analyzes syntactic and structural patterns; it does not execute client-side JavaScript inside a dynamic browser sandbox.
2. **Zero-Day Novel Domains:** Newly registered malicious domains with standard HTTPS formatting and clean syntax cannot be flagged by static rules alone until reported to threat feeds.
3. **In-Memory Rate Limiting:** Rate limit state is held in process RAM. Distributed multi-process production deployments require a Redis backend.

### Future Roadmap
- Machine-learning hybrid classification trained on verified phishing datasets (PhishTank / OpenPhish).
- Headless Chromium sandboxing for live DOM snapshotting and visual similarity comparison.
- Centralized Redis backend using Flask-Limiter for multi-worker scaling.
- Vernacular voice navigation and additional Indian regional languages (Hindi, Telugu, Kannada).

---

## 18. Vulnerability Disclosure & Security Policy

For security reporting procedures, threat models, and disclosure conduct, please consult [`SECURITY.md`](SECURITY.md).
