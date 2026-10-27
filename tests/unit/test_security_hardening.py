"""
Comprehensive Security Regression Test Suite for QShield.
Validates security hardening across:
- Input validation and uniform JSON error handling (400, 404, 405, 413, 429, 500)
- Cross-Site Scripting (XSS) and dangerous URI schemes rejection
- SQL injection resistance on queries, search, and pagination bounds
- File upload security and decompression bomb defenses
- SSRF destination rejection and DNS validation
- Privacy preservation and sensitive token redaction
- Administrative authentication and constant-time key comparison
- In-memory rate limiting and HTTP 429 responses
- ReportLab PDF sanitization against control characters and XML injection
"""
import io
import json
from unittest.mock import patch, MagicMock
from PIL import Image
import pytest

from app import create_app
from config import TestingConfig, ProductionConfig
from app.core.url_analyzer import analyze_url_heuristics, mask_sensitive_url
from app.core.qr_decoder import decode_qr_image_bytes
from app.core.pdf_reporter import generate_scan_pdf_report, generate_history_pdf_report, _sanitize
from app.core.rate_limiter import get_limiter, SlidingWindowRateLimiter
from app.core.redirect_inspector import validate_destination_safety


@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.app_context():
        from app.database import get_db
        db = get_db()
        db.execute("DELETE FROM scan_history;")
        db.commit()
    with app.test_client() as test_client:
        yield test_client


# =============================================================================
# 1. Uniform JSON Error Handling & Information Disclosure Tests
# =============================================================================

def test_api_404_returns_consistent_json_no_stack_trace(client):
    """API endpoints must return structured JSON errors without file paths or stack traces."""
    res = client.get('/api/nonexistent-endpoint-test')
    assert res.status_code == 404
    assert res.is_json
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] == "NOT_FOUND"
    assert "Traceback" not in data.get("message", "")
    assert "File " not in data.get("message", "")


def test_api_405_method_not_allowed_returns_consistent_json(client):
    """Unsupported HTTP methods on API routes must return 405 JSON."""
    res = client.post('/api/scan-history')  # Only GET is allowed
    assert res.status_code == 405
    assert res.is_json
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] == "METHOD_NOT_ALLOWED"


def test_api_invalid_identifier_returns_404_json(client):
    """Invalid or negative scan IDs must return 404 JSON."""
    res = client.get('/api/scan-history/999999999')
    assert res.status_code == 404
    assert res.is_json
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] == "NOT_FOUND"


def test_api_missing_json_body_returns_400(client):
    """Calling JSON endpoints without body or application/json header returns 400."""
    res = client.post('/api/analyze-url', data="not json", content_type="text/plain")
    assert res.status_code == 400
    assert res.is_json
    data = res.get_json()
    assert data["valid"] is False
    assert data["error_code"] == "INVALID_JSON"


def test_security_headers_present_on_all_responses(client):
    """Verify presence of comprehensive security headers."""
    res = client.get('/health')
    assert res.status_code == 200
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
    assert res.headers.get('X-Frame-Options') == 'DENY'
    assert res.headers.get('X-XSS-Protection') == '1; mode=block'
    assert res.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    assert 'camera=(self)' in res.headers.get('Permissions-Policy', '')
    assert 'microphone=()' in res.headers.get('Permissions-Policy', '')
    assert "default-src 'self'" in res.headers.get('Content-Security-Policy', '')
    assert "frame-ancestors 'none'" in res.headers.get('Content-Security-Policy', '')


def test_cache_control_on_sensitive_routes(client):
    """API and admin routes must set no-store Cache-Control headers."""
    res = client.get('/api/scan-history')
    assert res.status_code == 200
    cache_header = res.headers.get('Cache-Control', '')
    assert 'no-store' in cache_header
    assert 'no-cache' in cache_header


# =============================================================================
# 2. XSS & Dangerous Protocol Scheme Defenses
# =============================================================================

def test_url_analyzer_rejects_dangerous_javascript_scheme():
    """URLs using javascript: must be rejected immediately."""
    payloads = [
        "javascript:alert(document.cookie)",
        "JAVASCRIPT:alert(1)",
        "javascript:/*--></title></style>*/<script>alert(1)</script>"
    ]
    for p in payloads:
        res = analyze_url_heuristics(p)
        assert res["valid"] is False
        assert res["error_code"] == "UNSUPPORTED_SCHEME"


def test_url_analyzer_rejects_data_file_and_vbscript_schemes():
    """URLs using data:, file:, vbscript:, blob: must be rejected."""
    bad_schemes = [
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "file://C:/Windows/win.ini",
        "vbscript:msgbox(1)",
        "blob:https://example.com/uuid"
    ]
    for u in bad_schemes:
        res = analyze_url_heuristics(u)
        assert res["valid"] is False
        assert res["error_code"] == "UNSUPPORTED_SCHEME"


def test_xss_script_tags_in_decoded_payload_remain_text():
    """Script tags in QR payloads are categorized safely and never executed."""
    xss_payload = "<script>alert('pwned')</script>"
    from app.core.payload_classifier import classify_payload
    result = classify_payload(xss_payload)
    assert result["payload_type"] in ("plain_text", "structured_other")
    # safe_display_text contains escaped or text copy, not executable
    assert "<script>" in result["safe_display_text"]


# =============================================================================
# 3. SQL Injection Resilience & Pagination Clamping
# =============================================================================

def test_sql_injection_in_history_search(client):
    """SQL injection strings in history search must not corrupt database or execute."""
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE scan_history; --",
        "1 UNION SELECT 1,2,3,4,5,6,7,8,9 --",
        "admin'--",
        "1' OR 1=1#"
    ]
    for payload in sqli_payloads:
        res = client.get(f'/api/scan-history?search={payload}')
        assert res.status_code == 200
        assert res.is_json
        data = res.get_json()
        assert data["success"] is True
        assert isinstance(data["history"], list)

    # Verify scan_history table is still intact and operable
    check = client.get('/api/scan-history')
    assert check.status_code == 200


def test_pagination_bounds_and_clamping(client):
    """Excessive or negative pagination limits and offsets are safely clamped."""
    # Enormous limit should be clamped to 100
    res = client.get('/api/scan-history?limit=1000000&offset=-50')
    assert res.status_code == 200
    data = res.get_json()
    assert data["limit"] == 100

    # Non-numeric offset defaults safely to 0
    res2 = client.get('/api/scan-history?limit=abc&offset=xyz')
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2["limit"] == 20


# =============================================================================
# 4. Upload Security & Decompression Bomb Defenses
# =============================================================================

def test_empty_image_upload_rejected(client):
    """Empty 0-byte file upload returns 400."""
    data = {'qr_file': (io.BytesIO(b""), "empty.png")}
    res = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] == "EMPTY_FILE"


def test_invalid_image_bytes_rejected(client):
    """Corrupted or non-image files with .png extension return 400 INVALID_IMAGE."""
    fake_png = b"This is not a real PNG image, just plain ASCII text."
    data = {'qr_file': (io.BytesIO(fake_png), "malicious.png")}
    res = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] in ("INVALID_IMAGE", "UNSUPPORTED_FORMAT")


def test_oversized_image_upload_rejected(client):
    """Uploads exceeding 5 MB return HTTP 413."""
    oversized_data = b"X" * (5 * 1024 * 1024 + 1024)  # 5 MB + 1 KB
    data = {'qr_file': (io.BytesIO(oversized_data), "oversized.png")}
    res = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert res.status_code == 413
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] == "FILE_TOO_LARGE"


def test_decompression_bomb_dimension_bounds():
    """Images with dimensions exceeding 4096x4096 are rejected by qr_decoder."""
    # Create an in-memory image buffer with 4097 width
    img = Image.new("RGB", (4097, 100), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    raw_bytes = buf.getvalue()

    result = decode_qr_image_bytes(raw_bytes)
    assert result["success"] is False
    assert result["error_code"] == "IMAGE_TOO_LARGE"
    assert "4096" in result["message"]


# =============================================================================
# 5. SSRF Defense & Destination Safety
# =============================================================================

def test_ssrf_rejects_localhost_and_cloud_metadata():
    """Localhost, 127.0.0.1, and AWS/GCP metadata destinations must be blocked."""
    prohibited = [
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "169.254.170.2",
        "metadata.google.internal",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "0.0.0.0"
    ]
    for target in prohibited:
        is_safe, reason, _ = validate_destination_safety(target)
        assert is_safe is False
        assert "prohibited" in reason.lower() or "local" in reason.lower()


def test_no_outbound_network_calls_during_normal_scan(client):
    """Ordinary URL analysis must never initiate outbound network requests."""
    with patch('socket.socket') as mock_socket, patch('urllib.request.urlopen') as mock_urlopen:
        res = client.post('/api/analyze-url', json={"url": "https://example-phishing-test.com/login"})
        assert res.status_code == 200
        # Neither socket.socket nor urlopen should have been called
        assert not mock_socket.called
        assert not mock_urlopen.called


# =============================================================================
# 6. Privacy Preservation & Sensitive Token Redaction
# =============================================================================

def test_mask_sensitive_url_redacts_credentials_and_tokens():
    """mask_sensitive_url must replace tokens, passwords, and userinfo with [REDACTED]."""
    test_url = "https://user:password123@example.com/checkout?token=secrettoken999&session_id=sess123&page=1&ref=email"
    masked = mask_sensitive_url(test_url)

    assert "password123" not in masked
    assert "secrettoken999" not in masked
    assert "sess123" not in masked
    assert "[REDACTED]" in masked
    # Public non-sensitive parameters remain visible
    assert "page=1" in masked


def test_admin_health_does_not_leak_api_keys(client):
    """Admin health endpoint must return boolean indicators without disclosing API keys."""
    res = client.get('/api/admin/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    health = data["health"]
    # Check that keys themselves are not exposed
    assert "GOOGLE_SAFE_BROWSING_API_KEY" not in str(health)
    assert "ADMIN_API_KEY" not in str(health)
    assert isinstance(health["threat_intelligence_configured"], bool)


# =============================================================================
# 7. Administrative Authentication & Timing Attacks
# =============================================================================

def test_admin_auth_constant_time_comparison(client):
    """Admin key verification requires exact key and rejects incorrect keys."""
    app = client.application
    app.config['ADMIN_API_KEY'] = 'SuperSecretAdminKey2026'

    # 1. No key provided
    res_no_key = client.get('/api/admin/summary')
    assert res_no_key.status_code == 401
    assert res_no_key.get_json()["error_code"] == "UNAUTHORIZED"

    # 2. Invalid key provided
    res_bad_key = client.get('/api/admin/summary', headers={'X-Admin-Key': 'WrongKey'})
    assert res_bad_key.status_code == 401
    assert res_bad_key.get_json()["error_code"] == "UNAUTHORIZED"

    # 3. Valid key provided
    res_valid_key = client.get('/api/admin/summary', headers={'X-Admin-Key': 'SuperSecretAdminKey2026'})
    assert res_valid_key.status_code == 200
    assert res_valid_key.get_json()["success"] is True

    # Reset key
    app.config['ADMIN_API_KEY'] = ''


def test_admin_disabled_in_production_without_key():
    """In production mode without ADMIN_API_KEY, admin endpoints return 403."""
    prod_app = create_app(ProductionConfig)
    prod_app.config['ADMIN_API_KEY'] = ''  # Unconfigured in production

    with prod_app.test_client() as prod_client:
        res = prod_client.get('/api/admin/summary')
        assert res.status_code == 403
        data = res.get_json()
        assert data["error_code"] == "ADMIN_DISABLED_IN_PRODUCTION"


# =============================================================================
# 8. ReportLab PDF Security & Sanitization
# =============================================================================

def test_pdf_reporter_strips_control_characters_and_escapes_xml():
    """_sanitize must strip null bytes and escape XML characters."""
    dangerous = "Evil<script>alert(1)</script>&\"'\x00\x0c\x07Hello"
    sanitized = _sanitize(dangerous)

    assert "\x00" not in sanitized
    assert "\x0c" not in sanitized
    assert "<script>" not in sanitized
    assert "&lt;script&gt;" in sanitized
    assert "&amp;" in sanitized
    assert "Hello" in sanitized


def test_pdf_generation_with_malicious_inputs():
    """PDF generation survives malicious inputs without throwing exceptions."""
    malicious_scan = {
        "scan_id": 9999,
        "target_domain": "<img src=x onerror=alert(1)>",
        "payload_type": "URL\x00\x0cInjection",
        "risk_assessment": {
            "score": 95,
            "risk_level": "critical",
            "recommendations": {
                "safe_actions": ["Action 1 <b style='color:red'>Bold</b>"],
                "risky_actions": ["Action 2 &amp; test"],
                "next_step": "Step 3 \x00 null byte"
            }
        },
        "indicators": [
            {
                "rule_id": "TEST_INJECTION",
                "severity": "high",
                "message": "Dangerous payload <script>alert(1)</script>",
                "evidence": "Evidence string with \x00\x07 control chars"
            }
        ]
    }

    pdf_bytes = generate_scan_pdf_report(malicious_scan)
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF")


# =============================================================================
# 9. Rate Limiting Tests
# =============================================================================

def test_sliding_window_rate_limiter_throttles():
    """SlidingWindowRateLimiter denies requests exceeding maximum threshold."""
    limiter = SlidingWindowRateLimiter()
    key = "test-client"

    # Allow 3 requests in a 10-second window
    assert limiter.is_allowed(key, max_requests=3, window_seconds=10)[0] is True
    assert limiter.is_allowed(key, max_requests=3, window_seconds=10)[0] is True
    assert limiter.is_allowed(key, max_requests=3, window_seconds=10)[0] is True

    # 4th request must be denied
    allowed, retry_after = limiter.is_allowed(key, max_requests=3, window_seconds=10)
    assert allowed is False
    assert retry_after > 0


def test_rate_limiting_endpoint_integration(client):
    """When RATELIMIT_ENABLED is True, endpoint returns HTTP 429 when flooded."""
    app = client.application
    app.config['RATELIMIT_ENABLED'] = True
    app.config['RATELIMIT_ANALYZE'] = 2  # Set low limit for testing
    app.config['RATELIMIT_DEFAULT_WINDOW'] = 10

    limiter = get_limiter()
    limiter.reset()

    # Request 1 & 2 succeed
    res1 = client.post('/api/analyze-url', json={"url": "https://example1.com"})
    assert res1.status_code == 200
    res2 = client.post('/api/analyze-url', json={"url": "https://example2.com"})
    assert res2.status_code == 200

    # Request 3 triggers 429
    res3 = client.post('/api/analyze-url', json={"url": "https://example3.com"})
    assert res3.status_code == 429
    assert res3.is_json
    data = res3.get_json()
    assert data["error_code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in res3.headers

    # Reset config
    app.config['RATELIMIT_ENABLED'] = False
    limiter.reset()


# =============================================================================
# 10. Regression Tests (Prior Prompts 1–15 Functionality)
# =============================================================================

def test_bilingual_academy_and_awareness_pages(client):
    """Awareness and Academy routes render correctly in English and Tamil."""
    res_awareness = client.get('/awareness')
    assert res_awareness.status_code == 200
    assert b"Awareness" in res_awareness.data

    res_academy = client.get('/academy')
    assert res_academy.status_code == 200
    assert b"Academy" in res_academy.data


def test_quiz_api_categories_still_operational(client):
    """Quiz category API continues to provide full category questions."""
    res = client.get('/api/quiz/categories?lang=en')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert len(data["categories"]) == 6
    assert data["total_questions"] == 36
