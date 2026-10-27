# QShield Project Demonstration Guide & Viva Preparation

**Project:** QShield — QR Phishing Detection & Awareness System  
**Tagline:** “Decode the QR. Detect the Threat.”  
**Audience:** Academic evaluators, viva examiners, student reviewers, and security demonstrations.

---

## 1. Five-Minute Demonstration Plan

| Time | Phase | What to Demonstrate & Speak |
| :---: | :--- | :--- |
| **0:00 – 0:45** | **Problem & Objective** | Explain *Quishing* (QR Phishing): Attackers place fraudulent QR stickers on physical parking meters, restaurant tables, and phishing emails to bypass traditional email filters. Introduce QShield's mission: **Decode the QR. Detect the Threat.** |
| **0:45 – 1:45** | **Live Camera & QR Decoding** | Navigate to `/scanner`. Demonstrate the **Live Camera Scan** tab. Click "Start Camera" to show explicit permission handling. Point at a sample QR code: show the glowing reticle lock-on, scanning laser effect, instantaneous in-memory decoding (via browser-native `BarcodeDetector` or backend OpenCV canvas fallback), duplicate prevention cooldown, and **strict refusal to auto-navigate**. Switch tabs to demonstrate file upload and manual inspection. |
| **1:45 – 2:45** | **Payload Classification & Heuristics** | Point out the automated handoff: <br/>1. Structural heuristic rules triggered (e.g. brand in subdomain, IP address host, unencrypted HTTP). <br/>2. Explainable 0–100 score and risk tier (Low, Medium, High, Critical). <br/>3. Actionable recommendations and modular detection engine telemetry. |
| **2:45 – 3:30** | **Privacy History & PDF Report** | Show that under Privacy-by-Design, only sanitized domains are recorded in history; query tokens and passwords are never stored. Click "Download PDF Security Report" to showcase the in-memory ReportLab generated audit document. |
| **3:30 – 4:15** | **Awareness & Tamil Academy** | Open `/awareness` to showcase the 6 interactive scam scenarios and scam simulator. Open `/academy` to demonstrate the bilingual Cyber Safety Academy: switch to Tamil (தமிழ்), take a 5-question quiz, view immediate feedback and educational takeaways. |
| **4:15 – 5:00** | **Admin Dashboard & Wrap-Up** | Navigate to `/admin`. Enter `ADMIN_API_KEY` to unlock live system telemetry computed from actual database records. Summarize limitations: heuristic indicator, not a statistical guarantee of safety. |

---

## 2. Controlled Demonstration Scenarios

Use these synthetic, safe test strings during demonstrations:

### Scenario A: Benign Example URL
- **Input String:** `https://en.wikipedia.org/wiki/Computer_security`
- **Expected Outcome:** Low Risk (0/100).
- **Indicators Triggered:** None (Clean static structure).
- **Explanation:** Demonstrates that standard, properly encrypted HTTPS domains with standard structure pass cleanly without false positives.

### Scenario B: Structurally Suspicious URL (Brand Mimicry & Keywords)
- **Input String:** `http://paypal.com.account-update.xyz:8080/login/verify?session=12345`
- **Expected Outcome:** High Risk (~60–75/100).
- **Indicators Triggered:**
  - `URL_BRAND_IN_SUBDOMAIN` (+25 pts)
  - `URL_CREDENTIAL_KEYWORDS_IN_PATH` (+5 pts)
  - `URL_UNENCRYPTED_HTTP` (+15 pts)
  - `URL_NON_STANDARD_PORT` (+15 pts)
- **Explanation:** Demonstrates detection of deceptive subdomain positioning, brand impersonation, and unencrypted transmission.

### Scenario C: Non-URL QR Payload (Wi-Fi Configuration)
- **Input String:** `WIFI:T:WPA;S:CoffeeShop_Guest;P:SuperSecretPass123;;`
- **Expected Outcome:** Payload Category: `Wi-Fi Configuration (WPA)`.
- **Privacy Verification:** Password displayed as `••••••••`; URL analysis appropriately disabled (`Inconclusive`); no automatic Wi-Fi connection attempted.

### Scenario D: Malformed / Dangerous Protocol Scheme
- **Input String:** `javascript:alert(document.cookie)`
- **Expected Outcome:** Rejected with `UNSUPPORTED_SCHEME`.
- **Explanation:** Demonstrates application defense against client-side script execution.

### Scenario E: Corrupt / Non-Image File Upload
- **Input File:** Text file renamed to `sample.png` containing arbitrary text.
- **Expected Outcome:** HTTP 400 with `INVALID_IMAGE` error code.
- **Explanation:** Verifies that file extension is not trusted blindly; real binary headers are validated by Pillow.

### Scenario F: External Threat Intelligence Consent Guard
- **Input String:** `https://example.com/login`
- **Action:** Attempt reputation lookup without checking consent box.
- **Expected Outcome:** Rejected with `CONSENT_REQUIRED`.
- **Explanation:** Demonstrates that user URLs are never sent to third parties without explicit user confirmation.

### Scenario G: Live Camera QR Scanning & Anti-Auto-Open Sandbox
- **Action:** Select "Live Camera Scan" tab. Click "Start Camera". Present physical QR code or monitor screen.
- **Expected Outcome:**
  - Viewfinder locks onto matrix; reticle highlights green (`.detected`) with subtle vibration.
  - Video stream freezes scanning to prevent duplicate triggers (3-second cooldown).
  - Decoded payload displayed safely in preview box.
  - URL is NOT auto-opened. Full risk scoring panel and indicators load in-memory.
  - "Scan Again" button resets reticle and resumes stream.
- **Explanation:** Proves strict security posture: decoding is decoupled from execution or navigation.

---

## 3. Comprehensive Viva Questions & Model Answers

### Q1: What problem does QShield solve?
**Answer:** Traditional web security relies on email scanners and browser URL bars. QR codes (quishing) bypass these because the URL is visually encoded in an optical matrix. Users scan them using mobile cameras without knowing where the code leads. QShield decodes the code safely in-memory, classifies its payload, and evaluates structural deception before the user visits the destination.

### Q2: What is "Quishing"?
**Answer:** Quishing (QR Phishing) is a social engineering attack where malicious actors use QR codes to redirect victims to fraudulent websites, initiate unauthorized financial payments (e.g. fake UPI QR codes), or steal credentials.

### Q3: Why did you choose OpenCV for QR decoding instead of a pure Python decoder?
**Answer:** OpenCV's `cv2.QRCodeDetector` is an industrial-strength, C++ optimized computer vision engine. It provides robust perspective correction, contour analysis, and edge detection, allowing multi-pass decoding on high-resolution, rotated, and low-contrast images.

### Q4: How is Flask utilized in the application architecture?
**Answer:** Flask serves as the lightweight web framework. We use the Application Factory pattern (`create_app`), modular Blueprints (`main_bp` for public views, `api_bp` for REST endpoints), request teardown hooks for SQLite connection management, centralized error handlers, and `@app.after_request` for security headers.

### Q5: Why is SQLite appropriate for this project?
**Answer:** SQLite is serverless, zero-configuration, lightweight, and requires no external database daemons or network latency. Because QShield follows Privacy-by-Design and stores only minimal non-sensitive metadata, SQLite easily handles thousands of records with microsecond queries.

### Q6: How does the URL Analyzer operate without making network calls?
**Answer:** The URL analyzer performs purely static structural inspection. It uses Python's `urllib.parse` and an offline instance of `tldextract` (with public suffix downloads disabled) to evaluate lexical characteristics: IP hostnames, brand tokens in subdomains, userinfo `@` syntax, credential keywords, and port numbers.

### Q7: How is the heuristic risk score calculated?
**Answer:** The risk scoring engine assigns deterministic base weights to triggered indicators (High: 25, Medium: 15, Low: 5, Info: 0). It groups related findings into families (e.g. brand mimicry, credential context), applies a 50% discount to secondary findings in the same family to prevent artificial inflation, and clamps the final score between 0 and 100.

### Q8: Why is the risk score NOT a statistical probability of phishing?
**Answer:** A true probability requires a calibrated mathematical distribution trained on labeled datasets. Structural heuristics are deterministic rule-based indicators of evasion techniques. Presenting a heuristic score as a "90% probability" would be misleading; instead, QShield transparently calls it an explainable structural indicator.

### Q9: What is Payload Classification?
**Answer:** QR codes encode arbitrary text strings. Payload classification uses syntactic pattern matching to determine whether the text represents a URL, a Wi-Fi configuration (`WIFI:`), a vCard contact, an SMS, a phone call, or a financial UPI payment intent.

### Q10: What is Server-Side Request Forgery (SSRF) and how does QShield prevent it?
**Answer:** SSRF occurs when an attacker tricks a backend server into making HTTP requests to internal or private infrastructure (e.g. `127.0.0.1` or `169.254.169.254`). QShield prevents SSRF by:
1. Never fetching URLs during standard scanning.
2. Requiring explicit user consent for redirect tracing.
3. Resolving hostnames and verifying all resolved IPs are public and globally routable.
4. Blocking loopback, RFC1918 private subnets, and cloud metadata IPs at every redirect hop.

### Q11: Why does QShield refuse to automatically navigate to or open scanned URLs?
**Answer:** Automatic navigation defeats the entire purpose of a security scanner. If an application automatically follows a malicious link, the user's browser could be exposed to zero-day browser exploits, drive-by downloads, or malicious redirects before any analysis occurs.

### Q12: How is user privacy protected in QShield?
**Answer:** QShield enforces Privacy-by-Design:
1. Decoded QR payloads and image bytes are kept strictly in RAM and discarded immediately.
2. Wi-Fi passwords and UPI secrets are masked.
3. Scan history stores only domain hostnames (`example.com`), never full URLs, query parameters, or personal tokens.
4. Users can permanently delete their records at any time.

### Q13: What role does Google Safe Browsing play?
**Answer:** Google Safe Browsing is an optional secondary threat feed. It checks whether a URL is a known, cataloged threat. QShield keeps Safe Browsing completely decoupled from local heuristic analysis so that the system remains 100% operational even without API keys or internet access.

### Q14: How does QShield handle image decompression bombs?
**Answer:** A small compressed image (e.g. 500 KB) can expand to gigabytes of uncompressed pixels. QShield limits file size to 5 MB, restricts dimensions to 4096×4096 pixels (16 MP) using Pillow, sets `Image.MAX_IMAGE_PIXELS`, and catches `Image.DecompressionBombError`.

### Q15: How does the sliding window rate limiter work?
**Answer:** The rate limiter maintains a timestamp queue per client IP for each endpoint. When a request arrives, timestamps older than the window (60s) are evicted. If remaining requests exceed the limit, it rejects the request with HTTP 429 and a `Retry-After` header.

### Q16: How is Cross-Site Scripting (XSS) mitigated?
**Answer:** 
1. Jinja2 templates autoescape all HTML variables by default.
2. Frontend JavaScript uses `.textContent` to render untrusted text rather than `.innerHTML`.
3. In-memory ReportLab PDF generator sanitizes strings with `html.escape` and strips control characters.
4. Content-Security-Policy (CSP) prevents frame injection and restricts script execution.

### Q17: Why did you implement bilingual support (Tamil and English)?
**Answer:** Digital financial scams (especially fake UPI QR codes) heavily target rural and semi-urban populations in Tamil Nadu who may not be fluent in English technical jargon. Providing localized Tamil guides and quizzes democratizes cybersecurity education for vernacular users.

### Q18: How are administrative endpoints protected?
**Answer:** Admin endpoints (`/api/admin/summary`, `/api/admin/health`) require an `X-Admin-Key` header matching `ADMIN_API_KEY`. Verification uses constant-time `hmac.compare_digest` to prevent timing attacks. In production (`DEBUG=False`), access is locked down (HTTP 403) if the key is not set.

### Q19: What are the main limitations of QShield?
**Answer:**
1. It analyzes static structural features; it does not execute dynamic JavaScript in a sandbox browser.
2. Newly registered zero-day malicious domains with clean structures may receive a Low risk score.
3. The built-in rate limiter is in-memory and local to a single process.

### Q20: What are your planned future enhancements?
**Answer:**
1. Machine-learning classification trained on verified phishing datasets (e.g. PhishTank, OpenPhish).
2. Headless Chromium sandboxing for DOM snapshot inspection.
3. Distributed Redis backend for multi-worker production deployments.
4. Additional Indian regional languages (Hindi, Telugu, Kannada).

---

## 4. Honest Project Limitations & Future Scope

| Area | Current Implementation Boundary | Proposed Future Enhancement |
| :--- | :--- | :--- |
| **Detection Method** | Deterministic static heuristic lexical rules | Hybrid model combining static rules with a lightweight Random Forest / XGBoost model trained on lexical feature sets. |
| **Content Execution** | Zero execution; URLs are never fetched | Secure cloud-sandboxed Chromium instance that captures screenshots and DOM elements without exposing client devices. |
| **Rate Limiter Storage** | In-memory sliding window deque | Centralized Redis backend using Flask-Limiter for distributed microservices. |
| **Authentication** | Single shared `ADMIN_API_KEY` | Multi-user Role-Based Access Control (RBAC) with bcrypt-hashed credentials and OAuth2 / OpenID Connect. |
| **Internationalization** | English and Tamil (தமிழ்) | Expand to Hindi, Malayalam, Telugu, and Kannada with vernacular voice narration. |
