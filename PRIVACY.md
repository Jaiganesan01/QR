# QShield Privacy & Data Minimization Policy

**Project:** QShield — QR Phishing Detection & Awareness System  
**Tagline:** “Decode the QR. Detect the Threat.”

---

## 1. Privacy-by-Design Core Principles

QShield is built from the ground up on strict data minimization and user privacy principles:
- **No Payload Persistence:** Raw QR payloads, decoded text, binary image buffers, Wi-Fi credentials, and sensitive session tokens are never saved to disk or database tables.
- **Offline First:** QR decoding, payload classification, and URL heuristic analysis execute entirely on the local host with zero outbound network traffic.
- **Explicit Consent for External Calls:** External threat intelligence lookups and redirect inspections are completely disabled until the user explicitly checks a confirmation consent box.
- **User Control:** Users can review, filter, and permanently delete their scan history records at any time.

---

## 2. What Data Is Processed

When you interact with QShield, the following data is processed transiently in application memory:

| Data Element | Processing Stage | Persistence |
| :--- | :--- | :--- |
| **Uploaded QR Image** | Decoded in RAM via OpenCV / Pillow | **Never stored.** Discarded immediately after decoding. |
| **Decoded Text Payload** | Evaluated by Payload Classifier | **Never stored.** Returned to client browser only. |
| **Wi-Fi Passwords** | Classified format (WPA/WEP) | **Masked in memory.** Displayed as bullet dots; never logged or saved. |
| **Payment Recipient & Amounts** | Classified format (UPI) | **Evaluated in memory.** Never logged or saved. |
| **URL Query Parameters & Tokens** | Scanned for sensitive keys (`token`, `auth`, `key`) | **Redacted.** Sensitive keys are replaced with `[REDACTED]`. |

---

## 3. What Data Is Stored in SQLite History

The SQLite database (`instance/qshield.db`) persists only minimal non-sensitive telemetry necessary to populate the scan history table and operational metrics:

1. **Scan ID:** Incremental integer identifier.
2. **Scan Timestamp:** UTC date and time of the scan.
3. **Scan Method:** `upload` or `manual`.
4. **Payload Category:** General structural classification (`URL`, `Wi-Fi Configuration`, `Contact Card (vCard)`, `Plain Text`, etc.).
5. **Target Hostname / Domain:** Sanitized domain name only (e.g., `example.com`). All paths, query parameters, anchors, and userinfo are stripped before persistence.
6. **Heuristic Risk Score:** Integer from 0 to 100 (or `NULL` if non-URL).
7. **Risk Level:** Classification label (`Low`, `Medium`, `High`, `Critical`, or `Inconclusive`).
8. **Observed Indicator Count:** Number of triggered heuristic rules.
9. **Processing Status:** `completed`, `inconclusive`, or `failed`.

> [!IMPORTANT]
> Raw URLs containing authentication tokens, query parameters, email addresses, passwords, or personal credentials are **NEVER** written to the database.

---

## 4. Third-Party Data Transmissions

### Google Safe Browsing API v4 (Optional)
- **When is it queried?** Only when:
  1. An administrator has configured a `GOOGLE_SAFE_BROWSING_API_KEY`.
  2. The payload is a valid HTTP/HTTPS URL with a resolvable public domain.
  3. The user explicitly opts in by checking the external reputation consent box.
- **Privacy Protections:**
  - URLs containing sensitive query parameters (`token`, `secret`, `password`, `session_id`, `api_key`), credential userinfo (`user:pass@host`), or long high-entropy path segments are **automatically skipped** and never transmitted to external providers.
  - If skipped due to privacy protection, QShield notifies the user that the lookup was withheld to protect confidential parameters.

### Safe Redirect Inspector (Optional)
- **When is it queried?** Only when the user explicitly triggers redirect inspection with consent confirmed.
- **Privacy Protections:**
  - Does NOT transmit user cookies, authorization headers, or device fingerprinting tokens.
  - Connects using minimal `HEAD` requests to inspect `Location` headers only.
  - Re-evaluates destination safety at every step, blocking private/local addresses.

---

## 5. User Control & History Management

Users have complete autonomy over their stored scan records:
1. **Interactive Review:** View all past scans at the `/history` dashboard.
2. **Individual Deletion:** Delete specific scan records by clicking the delete button (`DELETE /api/scan-history/<id>`), which permanently removes the row from the SQLite database.
3. **Local Academy Progress:** Cybersecurity Academy quiz progress is stored strictly inside your browser's `localStorage` (`qshield_quiz_progress`). You can reset this at any time by clicking "Reset Learning Progress" on the Academy page.
4. **Administrative Session Key:** Administrative keys entered in the dashboard are stored solely in your browser's temporary `sessionStorage` (`qshield_admin_key`) and automatically cleared when the browser tab is closed.

---

## 6. Logging Policy

Application logs:
- Do NOT record raw QR image bytes or complete QR payload contents.
- Do NOT record administrative authorization keys or third-party API keys.
- Do NOT record sensitive query parameters or user credentials.
- Record only operational error codes, HTTP status codes, and service lifecycle events.
