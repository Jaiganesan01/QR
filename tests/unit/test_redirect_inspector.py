"""
Unit & Integration tests for QShield Safe Redirect Inspector (Prompt 12).
Tests SSRF blocks (localhost, RFC1918, link-local, cloud metadata, IPv6),
hop-by-hop resolution, scheme downgrades, loops, max hops, relative location resolution,
sensitive query string filtering, and consent enforcement.
All tests use dependency injection or mocked socket/HTTP responses; NO real network calls.
"""
from unittest.mock import patch, MagicMock
import pytest

from app import create_app
from config import TestingConfig
from app.core.redirect_inspector import (
    SafeRedirectInspector,
    inspect_redirects,
    validate_destination_safety
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
# 1. SSRF & Destination Validation Tests
# =============================================================================

def test_validate_destination_blocks_localhost_and_internal_hostnames():
    bad_hosts = [
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "service.local",
        "instance-data"
    ]
    for host in bad_hosts:
        is_safe, reason, _ = validate_destination_safety(host)
        assert is_safe is False
        assert "prohibited" in reason.lower() or "local" in reason.lower()


def test_validate_destination_blocks_private_ipv4_and_loopback():
    bad_ips = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254", # AWS metadata
        "0.0.0.0"
    ]
    for ip in bad_ips:
        is_safe, reason, _ = validate_destination_safety(ip)
        assert is_safe is False
        assert "prohibited" in reason.lower()


def test_validate_destination_blocks_private_and_loopback_ipv6():
    bad_ipv6 = [
        "::1",
        "fe80::1", # link-local
        "fc00::1", # unique local
        "fd00:ec2::254" # metadata
    ]
    for ip in bad_ipv6:
        is_safe, reason, _ = validate_destination_safety(ip)
        assert is_safe is False
        assert "prohibited" in reason.lower()


def test_validate_destination_blocks_dns_resolving_to_private_ip():
    # Mock socket.getaddrinfo to return a private IP
    mock_addr = [(2, 1, 0, '', ('192.168.1.50', 0))]
    with patch('socket.getaddrinfo', return_value=mock_addr):
        is_safe, reason, ips = validate_destination_safety("internal-portal.example.com")
        assert is_safe is False
        assert "192.168.1.50" in ips
        assert "prohibited" in reason.lower()


def test_validate_destination_blocks_dns_resolving_to_both_public_and_private():
    # If DNS returns a public IP AND a private IP, it must be rejected (dual-homed / rebinding risk)
    mock_addr = [
        (2, 1, 0, '', ('93.184.216.34', 0)), # Public
        (2, 1, 0, '', ('10.0.0.5', 0))        # Private
    ]
    with patch('socket.getaddrinfo', return_value=mock_addr):
        is_safe, reason, _ = validate_destination_safety("mixed-resolution.example.com")
        assert is_safe is False
        assert "prohibited" in reason.lower()


def test_validate_destination_allows_public_ip():
    mock_addr = [(2, 1, 0, '', ('93.184.216.34', 0))]
    with patch('socket.getaddrinfo', return_value=mock_addr):
        is_safe, reason, ips = validate_destination_safety("example.com")
        assert is_safe is True
        assert "93.184.216.34" in ips


# =============================================================================
# 2. Redirect Inspector Logic Tests (Mocked HTTP requests)
# =============================================================================

def test_inspect_valid_url_no_redirect():
    inspector = SafeRedirectInspector()
    # Mock single hop returning 200 OK
    with patch.object(inspector, '_execute_single_hop_request', return_value=(200, {"content-type": "text/html"}, "")):
        with patch('app.core.redirect_inspector.validate_destination_safety', return_value=(True, "", ["93.184.216.34"])):
            res = inspector.inspect("https://example.com/page")
            assert res["status"] == "completed"
            assert res["redirect_count"] == 0
            assert len(res["hops"]) == 1
            assert res["hops"][0]["status_code"] == 200
            assert res["final_destination_display"] == "https://example.com/page"


def test_inspect_single_redirect_to_new_path():
    inspector = SafeRedirectInspector()
    # Hop 1: 301 -> /new-page
    # Hop 2: 200 OK
    side_effects = [
        (301, {"location": "/new-page"}, ""),
        (200, {"content-type": "text/html"}, "")
    ]
    with patch.object(inspector, '_execute_single_hop_request', side_effect=side_effects):
        with patch('app.core.redirect_inspector.validate_destination_safety', return_value=(True, "", ["93.184.216.34"])):
            res = inspector.inspect("https://example.com/old-page")
            assert res["status"] == "completed"
            assert res["redirect_count"] == 1
            assert len(res["hops"]) == 2
            assert res["hops"][0]["status_code"] == 301
            assert res["hops"][1]["status_code"] == 200
            assert res["final_destination_display"] == "https://example.com/new-page"


def test_inspect_cross_domain_redirect():
    inspector = SafeRedirectInspector()
    side_effects = [
        (302, {"location": "https://external-service.com/welcome"}, ""),
        (200, {}, "")
    ]
    with patch.object(inspector, '_execute_single_hop_request', side_effect=side_effects):
        with patch('app.core.redirect_inspector.validate_destination_safety', return_value=(True, "", ["93.184.216.34"])):
            res = inspector.inspect("https://brand.com/login")
            assert res["status"] == "completed"
            assert res["redirect_count"] == 1
            assert any(f["id"] == "cross_domain_redirect" for f in res["findings"])


def test_inspect_https_to_http_downgrade():
    inspector = SafeRedirectInspector()
    side_effects = [
        (302, {"location": "http://insecure-site.org/home"}, ""),
        (200, {}, "")
    ]
    with patch.object(inspector, '_execute_single_hop_request', side_effect=side_effects):
        with patch('app.core.redirect_inspector.validate_destination_safety', return_value=(True, "", ["93.184.216.34"])):
            res = inspector.inspect("https://secure-entry.com/start")
            assert res["status"] == "completed"
            assert any(f["id"] == "https_to_http_downgrade" for f in res["findings"])


def test_inspect_redirect_loop_detection():
    inspector = SafeRedirectInspector()
    side_effects = [
        (302, {"location": "https://example.com/loopB"}, ""),
        (302, {"location": "https://example.com/loopA"}, ""),
        (302, {"location": "https://example.com/loopB"}, "")
    ]
    with patch.object(inspector, '_execute_single_hop_request', side_effect=side_effects):
        with patch('app.core.redirect_inspector.validate_destination_safety', return_value=(True, "", ["93.184.216.34"])):
            res = inspector.inspect("https://example.com/loopA")
            assert any(f["id"] == "redirect_loop" for f in res["findings"])


def test_inspect_exceeding_max_hops():
    inspector = SafeRedirectInspector(max_hops=3)
    # Continually redirects to step1, step2, step3...
    side_effects = [
        (301, {"location": f"https://example.com/step{i}"}, "") for i in range(1, 6)
    ]
    with patch.object(inspector, '_execute_single_hop_request', side_effect=side_effects):
        with patch('app.core.redirect_inspector.validate_destination_safety', return_value=(True, "", ["93.184.216.34"])):
            res = inspector.inspect("https://example.com/step0")
            assert res["status"] == "incomplete"
            assert any(f["id"] == "long_redirect_chain" for f in res["findings"])


def test_inspect_redirect_attempting_ssrf_hop_blocked():
    inspector = SafeRedirectInspector()
    # Hop 1 redirects to internal AWS metadata service
    side_effects = [
        (302, {"location": "http://169.254.169.254/latest/meta-data/"}, "")
    ]
    with patch.object(inspector, '_execute_single_hop_request', side_effect=side_effects):
        # Initial domain safe, but next hop blocked by validate_destination_safety
        def mock_val(host):
            if host == "169.254.169.254":
                return False, "Prohibited metadata address", ["169.254.169.254"]
            return True, "", ["93.184.216.34"]

        with patch('app.core.redirect_inspector.validate_destination_safety', side_effect=mock_val):
            res = inspector.inspect("https://public-redirector.com/link")
            assert res["status"] == "blocked"
            assert any(f["id"] == "inspection_blocked" for f in res["findings"])


def test_inspect_known_url_shortener_detected():
    inspector = SafeRedirectInspector()
    with patch.object(inspector, '_execute_single_hop_request', return_value=(200, {}, "")):
        with patch('app.core.redirect_inspector.validate_destination_safety', return_value=(True, "", ["93.184.216.34"])):
            res = inspector.inspect("https://bit.ly/sample-token")
            assert any(f["id"] == "known_url_shortener" for f in res["findings"])


# =============================================================================
# 3. API Integration & Privacy Tests (POST /api/inspect-redirects)
# =============================================================================

def test_api_inspect_redirects_missing_consent(client):
    res = client.post('/api/inspect-redirects', json={
        "url": "https://example.com",
        "user_consent": False
    })
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] == "CONSENT_REQUIRED"


def test_api_inspect_redirects_invalid_url(client):
    res = client.post('/api/inspect-redirects', json={
        "url": "javascript:alert(1)",
        "user_consent": True
    })
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert data["redirect_result"]["status"] == "invalid_url"


def test_api_inspect_redirects_skips_sensitive_query_tokens(client):
    sensitive_url = "https://example.com/oauth?access_token=ya29.abcdef1234567890"
    res = client.post('/api/inspect-redirects', json={
        "url": sensitive_url,
        "user_consent": True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    res_data = data["redirect_result"]
    assert res_data["status"] == "skipped_sensitive_url"
    assert any("privacy" in f["id"] for f in res_data["findings"])


def test_api_inspect_redirects_success_mocked(client):
    mock_result = {
        "status": "completed",
        "inspection_mode": "safe_single_hop_sandbox",
        "submitted_url_display": "https://bit.ly/test",
        "hops": [
            {
                "hop_number": 1,
                "status_code": 301,
                "source_host": "bit.ly",
                "destination_host": "example.org",
                "destination_display": "https://example.org/",
                "is_cross_domain": True,
                "is_downgrade": False
            },
            {
                "hop_number": 2,
                "status_code": 200,
                "source_host": "example.org",
                "destination_host": "example.org",
                "destination_display": "https://example.org/",
                "is_cross_domain": False,
                "is_downgrade": False
            }
        ],
        "redirect_count": 1,
        "final_destination_display": "https://example.org/",
        "findings": [],
        "summary": "Observed 1 redirect hop concluding at destination host 'example.org'.",
        "limitations": "Strict SSRF limits enforced.",
        "checked_at": "2026-10-27T10:30:00Z"
    }

    with patch('app.core.redirect_inspector.SafeRedirectInspector.inspect', return_value=mock_result):
        res = client.post('/api/inspect-redirects', json={
            "url": "https://bit.ly/test",
            "user_consent": True
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["redirect_result"]["redirect_count"] == 1
        assert data["redirect_result"]["final_destination_display"] == "https://example.org/"
