# QShield REST API Specification

**Project:** QShield — QR Phishing Detection & Awareness System  
**Base URL:** `http://127.0.0.1:5000/api` (or deployed domain)  
**Response Format:** `application/json; charset=utf-8` (PDF endpoints return `application/pdf`)

---

## Table of Endpoints

1. [Health Check](#1-get-health)
2. [Decode QR Code](#2-post-apidecode-qr)
3. [Analyze URL Heuristics](#3-post-apianalyze-url)
4. [External Threat Intelligence Check](#4-post-apicheck-reputation)
5. [Safe Redirect Inspection](#5-post-apiinspect-redirects)
6. [List Scan History](#6-get-apiscan-history)
7. [Get Scan History Detail](#7-get-apiscan-historyid)
8. [Delete Scan History Record](#8-delete-apiscan-historyid)
9. [Download Historical PDF Report](#9-get-apiscan-historyidreport)
10. [Generate Live Scan PDF Report](#10-post-apiscan-reportgenerate)
11. [Get Admin Observability Summary](#11-get-apiadminsummary)
12. [Get Admin Operational Health](#12-get-apiadminhealth)
13. [List Quiz Categories](#13-get-apiquizcategories)
14. [Start Quiz](#14-post-apiquizstart)
15. [Check Single Answer](#15-post-apiquizcheck-answer)
16. [Evaluate Full Quiz Submission](#16-post-apiquizevaluate)
17. [Get Localization Strings](#17-get-apilocalelang)

---

### 1. `GET /health`
* **Description:** Base operational health probe for load balancers and monitoring.
* **Authentication:** None.
* **Response (200 OK):**
  ```json
  {
    "app": "QShield",
    "status": "ok",
    "tagline": "Decode the QR. Detect the Threat."
  }
  ```

---

### 2. `POST /api/decode-qr`
* **Description:** Decodes QR matrix from in-memory image bytes using OpenCV. Enforces 5 MB limit and image dimension bounds (4096×4096 px).
* **Rate Limit:** 30 requests / minute.
* **Request Content-Type:** `multipart/form-data`
* **Parameters:**
  * `qr_file`: (File, required) An image file (`PNG`, `JPEG`, `WEBP`, `BMP`).
* **Example Response (200 OK):**
  ```json
  {
    "success": true,
    "decoded_content": "https://secure-login.bank-portal.com/auth",
    "payload_type": "URL",
    "classification": {
      "payload_type": "url",
      "display_name": "Web Address (URL)",
      "requires_caution": true,
      "classification_confidence": "high"
    },
    "truncated": false,
    "error_code": null,
    "message": "QR code successfully decoded."
  }
  ```
* **Error Responses:**
  * `400 Bad Request`: `EMPTY_FILE`, `NO_FILE_SELECTED`, `UNSUPPORTED_FORMAT`, `INVALID_IMAGE`
  * `413 Payload Too Large`: `FILE_TOO_LARGE`
  * `422 Unprocessable Entity`: `NO_QR_DETECTED` (image valid, but no QR code visible)
* **Privacy:** Image bytes and decoded content exist only in RAM during request execution and are never saved to disk.

---

### 3. `POST /api/analyze-url`
* **Description:** Performs static, structural heuristic inspection on web URLs using 12 offline rules. Zero external network calls.
* **Rate Limit:** 60 requests / minute.
* **Request Content-Type:** `application/json`
* **Parameters:**
  * `url`: (string, required) HTTP or HTTPS web address (max 2048 chars).
  * `scan_type`: (string, optional) `"upload"` or `"manual"` (defaults to `"manual"`).
* **Example Request:**
  ```json
  {
    "url": "https://paypal.com.verify-billing.xyz/account/login",
    "scan_type": "manual"
  }
  ```
* **Example Response (200 OK):**
  ```json
  {
    "valid": true,
    "scan_id": 42,
    "parsed_url": {
      "scheme": "https",
      "hostname": "paypal.com.verify-billing.xyz",
      "registered_domain": "verify-billing.xyz",
      "subdomain": "paypal.com",
      "is_https": true
    },
    "risk_assessment": {
      "score": 55,
      "risk_level": "high",
      "summary": "Multiple structural indicators warrant significant caution.",
      "recommendations": {
        "safe_actions": ["Verify domain directly by navigating to official bookmarks."],
        "risky_actions": ["Do not enter credentials or MFA codes on this domain."]
      }
    },
    "indicators": [
      {
        "id": "URL_BRAND_IN_SUBDOMAIN",
        "title": "Brand Impersonation in Subdomain",
        "severity": "high",
        "weight": 25,
        "evidence": "Brand token 'paypal' present in subdomain of 'verify-billing.xyz'."
      }
    ]
  }
  ```
* **Privacy:** Stores only domain (`verify-billing.xyz`), risk score, and counts in database. Full query parameters and sensitive tokens are never stored.

---

### 4. `POST /api/check-reputation`
* **Description:** Optional reputation check via Google Safe Browsing API v4. Requires explicit user consent.
* **Rate Limit:** 15 requests / minute.
* **Parameters:**
  * `url`: (string, required) Valid HTTP/HTTPS URL.
  * `user_consent`: (boolean, required) Must be `true`.
* **Example Request:**
  ```json
  {
    "url": "https://testsafebrowsing.appspot.com/s/malware.html",
    "user_consent": true
  }
  ```
* **Example Response (200 OK):**
  ```json
  {
    "success": true,
    "reputation_result": {
      "provider": "Google Safe Browsing",
      "status": "checked",
      "reputation": "malicious",
      "threat_categories": ["MALWARE"],
      "summary": "Known threat flagged by Google Safe Browsing: MALWARE."
    }
  }
  ```
* **Privacy:** URLs containing credentials (`user:pass@`), tokens, or session IDs are automatically skipped (`skipped_privacy_sensitive_url`) and never sent to Google.

---

### 5. `POST /api/inspect-redirects`
* **Description:** Traces single-hop HTTP redirects (max 5 hops) with strict SSRF destination protection.
* **Rate Limit:** 15 requests / minute.
* **Parameters:**
  * `url`: (string, required) Valid HTTP/HTTPS URL.
  * `user_consent`: (boolean, required) Must be `true`.
* **Example Response (200 OK):**
  ```json
  {
    "success": true,
    "redirect_result": {
      "status": "completed",
      "redirect_count": 1,
      "hops": [
        {
          "hop_number": 1,
          "destination_host": "tinyurl.com",
          "status_code": 301,
          "is_cross_domain": true
        }
      ],
      "findings": []
    }
  }
  ```
* **Security:** Rejects connection attempts to loopback (`127.0.0.1`), RFC1918 private subnets, or cloud metadata endpoints (`169.254.169.254`).

---

### 6. `GET /api/scan-history`
* **Description:** Retrieves paginated, sanitized scan records in reverse chronological order.
* **Query Parameters:**
  * `page`: (int, optional, default 1)
  * `limit`: (int, optional, default 20, max 100)
  * `search`: (string, optional) Hostname, ID, or status filter.
  * `payload_type`: (string, optional) Filter by payload category.
  * `risk_level`: (string, optional) `low`, `medium`, `high`, `critical`.

---

### 7. `GET /api/scan-history/<id>`
* **Description:** Returns non-sensitive metadata for a single scan record.
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "scan": {
      "id": 1,
      "created_at": "2026-10-27 12:00:00",
      "scan_type": "upload",
      "payload_type": "URL",
      "target_domain": "example.com",
      "risk_score": 10,
      "risk_level": "low",
      "indicator_count": 0,
      "status": "completed"
    }
  }
  ```

---

### 8. `DELETE /api/scan-history/<id>`
* **Description:** Permanently deletes a single scan metadata record from the SQLite database.
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "message": "Scan record #1 successfully deleted."
  }
  ```

---

### 9. `GET /api/scan-history/<id>/report`
* **Description:** Generates and downloads a historical metadata audit PDF report.
* **Response:** Binary PDF stream (`Content-Type: application/pdf`).

---

### 10. `POST /api/scan-report/generate`
* **Description:** Generates an immediate full PDF security report from live scan result JSON.
* **Rate Limit:** 20 requests / minute.
* **Response:** Binary PDF stream (`Content-Type: application/pdf`).

---

### 11. `GET /api/admin/summary`
* **Description:** Returns aggregated operational metrics and scan distribution statistics.
* **Authentication:** Requires `X-Admin-Key` header matching `ADMIN_API_KEY` (or dev fallback).
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "metrics": {
      "total_scans": 150,
      "scans_today": 24,
      "avg_risk_score": 38.5,
      "by_risk_level": { "low": 90, "medium": 35, "high": 20, "critical": 5 },
      "recent_activity": [...]
    }
  }
  ```

---

### 12. `GET /api/admin/health`
* **Description:** Safe operational health report disclosing environment mode, database connectivity, and configured integrations without revealing credentials.

---

### 13. `GET /api/quiz/categories`
* **Description:** Returns all 6 Cyber Safety Academy categories with localized titles and question counts.
* **Query Parameters:** `lang` (`en` or `ta`, default `en`).

---

### 14. `POST /api/quiz/start`
* **Description:** Retrieves questions for a specific category without revealing correct answers.
* **Request:** `{"category_id": "qr_phishing_basics", "lang": "en"}`

---

### 15. `POST /api/quiz/check-answer`
* **Description:** Server-side answer validation. Returns correctness, detailed explanation, and educational takeaway.
* **Request:** `{"question_id": "q1", "selected_option_id": "B", "lang": "en"}`

---

### 16. `POST /api/quiz/evaluate`
* **Description:** Evaluates full category submission, computing final score and assigned performance tier.

---

### 17. `GET /api/locale/<lang>`
* **Description:** Returns complete JSON localization dictionary for `en` or `ta`.
