"""
Automated tests for QShield External Threat Intelligence Integration (Prompt 10).
Uses mocked HTTP provider responses to ensure offline determinism, test privacy rules,
consent enforcement, and error normalization.
"""
from io import BytesIO
import json
from unittest.mock import patch, MagicMock
import urllib.error
import pytest

from app import create_app
from config import TestingConfig
from app.core.threat_intelligence import (
    GoogleSafeBrowsingProvider,
    evaluate_threat_intelligence,
    is_sensitive_url
)


@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.app_context():
        from app.database import get_db
        db = get_db()
        db.execute("DELETE FROM scan_history;")
        db.commit()
    with app.test_client() as client:
        yield client


# =============================================================================
# 1. Unit Tests: Privacy and Sensitivity Identification
# =============================================================================

def test_sensitive_url_with_credentials_skipped():
    assert is_sensitive_url("https://user:password123@example.com/dashboard") is True


def test_sensitive_url_with_auth_token_param_skipped():
    assert is_sensitive_url("https://example.com/verify?token=abcd1234efgh5678ijkl9012mnop3456") is True
    assert is_sensitive_url("https://example.com/api?api_key=secretkeyvalue") is True
    assert is_sensitive_url("https://example.com/callback?access_token=ya29.xyz") is True
    assert is_sensitive_url("https://example.com/login?session_id=12345") is True


def test_sensitive_url_with_long_token_in_path_skipped():
    assert is_sensitive_url("https://example.com/reset/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz") is True


def test_clean_public_url_not_sensitive():
    assert is_sensitive_url("https://example.com/about-us") is False
    assert is_sensitive_url("https://chase.com/personal/banking") is False
    assert is_sensitive_url("https://subdomain.google.com/search?q=cybersecurity") is False


# =============================================================================
# 2. Unit Tests: Provider Configuration & Status Normalization
# =============================================================================

def test_provider_missing_api_key_returns_not_configured():
    provider = GoogleSafeBrowsingProvider(api_key="")
    assert provider.is_configured() is False

    res = provider.check_url("https://example.com")
    assert res["status"] == "not_configured"
    assert res["reputation"] == "unknown"
    assert "not configured" in res["summary"].lower()


def test_provider_malicious_response_parsed_correctly():
    mock_body = json.dumps({
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": {"url": "https://malware-sample.com"}
            },
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": {"url": "https://malware-sample.com"}
            }
        ]
    }).encode('utf-8')

    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = mock_body
    mock_resp.__enter__.return_value = mock_resp

    with patch('urllib.request.urlopen', return_value=mock_resp):
        provider = GoogleSafeBrowsingProvider(api_key="mock-api-key-test")
        res = provider.check_url("https://malware-sample.com")

        assert res["status"] == "checked"
        assert res["reputation"] == "malicious"
        assert "MALWARE" in res["threat_categories"]
        assert "SOCIAL_ENGINEERING" in res["threat_categories"]
        assert "Google Safe Browsing" in res["provider"]
        assert res["checked_at"] is not None


def test_provider_clean_response_parsed_correctly():
    mock_body = json.dumps({}).encode('utf-8')
    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = mock_body
    mock_resp.__enter__.return_value = mock_resp

    with patch('urllib.request.urlopen', return_value=mock_resp):
        provider = GoogleSafeBrowsingProvider(api_key="mock-api-key-test")
        res = provider.check_url("https://clean-site.org")

        assert res["status"] == "checked"
        assert res["reputation"] == "no_known_threat_detected"
        assert res["threat_categories"] == []
        assert "No known threat detected" in res["summary"]
        assert "Does not guarantee" in res["summary"]


def test_provider_http_401_403_auth_failure():
    http_error = urllib.error.HTTPError(
        url="https://safebrowsing.googleapis.com",
        code=403,
        msg="Forbidden",
        hdrs={},
        fp=BytesIO(b'{"error": {"message": "API key not valid"}}')
    )

    with patch('urllib.request.urlopen', side_effect=http_error):
        provider = GoogleSafeBrowsingProvider(api_key="invalid-key")
        res = provider.check_url("https://example.com")

        assert res["status"] == "provider_error"
        assert res["reputation"] == "unknown"
        assert "authentication failed" in res["summary"].lower()


def test_provider_http_429_rate_limiting():
    http_error = urllib.error.HTTPError(
        url="https://safebrowsing.googleapis.com",
        code=429,
        msg="Too Many Requests",
        hdrs={},
        fp=BytesIO(b'{"error": {"message": "Resource has been exhausted"}}')
    )

    with patch('urllib.request.urlopen', side_effect=http_error):
        provider = GoogleSafeBrowsingProvider(api_key="valid-key")
        res = provider.check_url("https://example.com")

        assert res["status"] == "rate_limited"
        assert res["reputation"] == "unknown"
        assert "rate limit exceeded" in res["summary"].lower()


def test_provider_http_500_server_error():
    http_error = urllib.error.HTTPError(
        url="https://safebrowsing.googleapis.com",
        code=500,
        msg="Internal Server Error",
        hdrs={},
        fp=BytesIO(b'Internal error')
    )

    with patch('urllib.request.urlopen', side_effect=http_error):
        provider = GoogleSafeBrowsingProvider(api_key="valid-key")
        res = provider.check_url("https://example.com")

        assert res["status"] == "provider_error"
        assert res["reputation"] == "unknown"
        assert "500" in res["summary"]


def test_provider_timeout_handling():
    with patch('urllib.request.urlopen', side_effect=TimeoutError("Request timed out")):
        provider = GoogleSafeBrowsingProvider(api_key="valid-key")
        res = provider.check_url("https://slow-site.com")

        assert res["status"] == "timeout"
        assert res["reputation"] == "unknown"
        assert "timed out" in res["summary"].lower()


# =============================================================================
# 3. Integration Tests: POST /api/check-reputation Endpoint
# =============================================================================

def test_api_check_reputation_missing_consent(client):
    res = client.post('/api/check-reputation', json={
        "url": "https://example.com",
        "user_consent": False
    })
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] == "CONSENT_REQUIRED"
    assert data["reputation_result"]["status"] == "skipped_no_consent"


def test_api_check_reputation_invalid_schemes(client):
    unsupported = [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,<h1>Hello</h1>",
        "ftp://ftp.example.com",
        "not-a-valid-url"
    ]
    for bad_url in unsupported:
        res = client.post('/api/check-reputation', json={
            "url": bad_url,
            "user_consent": True
        })
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert data["reputation_result"]["status"] == "invalid_url"


def test_api_check_reputation_skips_sensitive_query_parameters(client):
    sensitive_url = "https://bank.com/reset?token=secrettoken1234567890abcdef"
    res = client.post('/api/check-reputation', json={
        "url": sensitive_url,
        "user_consent": True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    rep = data["reputation_result"]
    assert rep["status"] == "skipped_sensitive_url"
    assert rep["reputation"] == "unknown"
    assert "privacy protection" in rep["summary"].lower()


def test_api_check_reputation_with_unconfigured_key(client):
    res = client.post('/api/check-reputation', json={
        "url": "https://clean-site.org",
        "user_consent": True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    rep = data["reputation_result"]
    assert rep["status"] == "not_configured"
    assert rep["reputation"] == "unknown"


def test_api_check_reputation_mocked_malicious_hit(client):
    mock_body = json.dumps({
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": {"url": "https://phishing-credential-harvester.com"}
            }
        ]
    }).encode('utf-8')

    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = mock_body
    mock_resp.__enter__.return_value = mock_resp

    with patch('urllib.request.urlopen', return_value=mock_resp):
        with patch.dict('os.environ', {'GOOGLE_SAFE_BROWSING_API_KEY': 'mock-key'}):
            # Also patch current_app config
            with client.application.app_context():
                client.application.config['GOOGLE_SAFE_BROWSING_API_KEY'] = 'mock-key'

            res = client.post('/api/check-reputation', json={
                "url": "https://phishing-credential-harvester.com",
                "user_consent": True
            })
            assert res.status_code == 200
            data = res.get_json()
            assert data["success"] is True
            rep = data["reputation_result"]
            assert rep["status"] == "checked"
            assert rep["reputation"] == "malicious"
            assert "SOCIAL_ENGINEERING" in rep["threat_categories"]


def test_api_check_reputation_never_persists_full_url_in_scan_history(client):
    # Verify DB scan history table only has non-sensitive target_domain
    client.post('/api/analyze-url', json={
        "url": "https://subdomain.login-test.com/path?foo=bar",
        "scan_type": "manual"
    })
    res = client.get('/api/scan-history?limit=1')
    assert res.status_code == 200
    history = res.get_json()["history"]
    assert len(history) == 1
    assert history[0]["target_domain"] == "subdomain.login-test.com"
    assert "/path" not in str(history[0])
    assert "foo=bar" not in str(history[0])


def test_api_analyze_url_checks_performed_indicates_reputation_on_demand(client):
    res = client.post('/api/analyze-url', json={
        "url": "https://example.com"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["checks_performed"]["external_threat_intelligence"] == "available_on_user_request"
