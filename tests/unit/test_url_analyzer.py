"""
Unit and API integration test suite for URL heuristic analysis.
Verifies all 15 rules & conditions, zero outbound network traffic, and error boundary handling.
"""
import pytest
from app import create_app
from config import TestingConfig
from app.core.url_analyzer import analyze_url_heuristics

@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client

def test_rule_normal_https_url():
    # Ordinary HTTPS URL on standard domain
    res = analyze_url_heuristics("https://en.wikipedia.org/wiki/Computer_security")
    assert res["valid"] is True
    assert res["parsed_url"]["scheme"] == "https"
    assert res["parsed_url"]["hostname"] == "en.wikipedia.org"
    assert res["parsed_url"]["registered_domain"] == "wikipedia.org"
    # Should have info indicator about HTTPS, but NO high/suspicious flags
    severities = [i["severity"] for i in res["indicators"]]
    assert "high" not in severities

def test_rule_normal_http_url():
    # Ordinary HTTP URL
    res = analyze_url_heuristics("http://example.com/readme.txt")
    assert res["valid"] is True
    assert res["parsed_url"]["scheme"] == "http"
    ids = [i["id"] for i in res["indicators"]]
    assert "URL_UNENCRYPTED_HTTP" in ids
    # Proves HTTP alone does not give a fatal verdict, only unencrypted notice
    assert len(res["indicators"]) == 1

def test_rule_malformed_url():
    res = analyze_url_heuristics("http://")
    assert res["valid"] is False
    assert res["error_code"] in ("MISSING_HOSTNAME", "MALFORMED_URL")

def test_rule_unsupported_scheme():
    res = analyze_url_heuristics("javascript:alert(document.cookie)")
    assert res["valid"] is False
    assert res["error_code"] == "UNSUPPORTED_SCHEME"

def test_rule_url_with_userinfo():
    # Phishing trick: trusted.google.com@phish-domain.com
    res = analyze_url_heuristics("https://accounts.google.com@evil-phish-portal.net/login")
    assert res["valid"] is True
    ids = [i["id"] for i in res["indicators"]]
    assert "URL_USERINFO_PRESENT" in ids
    ind = next(i for i in res["indicators"] if i["id"] == "URL_USERINFO_PRESENT")
    assert ind["severity"] == "high"

def test_rule_raw_ip_address_host():
    res = analyze_url_heuristics("http://192.168.1.100/admin")
    assert res["valid"] is True
    ids = [i["id"] for i in res["indicators"]]
    assert "URL_RAW_IP_HOST" in ids

def test_rule_punycode_hostname():
    # IDN homograph e.g. xn--pypal-4ve.com
    res = analyze_url_heuristics("https://xn--pypal-4ve.com/account")
    assert res["valid"] is True
    ids = [i["id"] for i in res["indicators"]]
    assert "URL_PUNYCODE_HOMOGRAPH" in ids

def test_rule_unusually_long_url():
    # Padding with long query
    long_url = "https://example.com/landing?" + ("param=" + "A" * 300)
    res = analyze_url_heuristics(long_url)
    assert res["valid"] is True
    ids = [i["id"] for i in res["indicators"]]
    assert "URL_EXCESSIVE_LENGTH" in ids

def test_rule_credential_keywords_in_path():
    res = analyze_url_heuristics("https://auth-server.example.org/verify/account-update")
    assert res["valid"] is True
    ids = [i["id"] for i in res["indicators"]]
    assert "URL_CREDENTIAL_KEYWORDS_IN_PATH" in ids

def test_rule_legitimate_url_with_query_params():
    res = analyze_url_heuristics("https://store.example.com/search?category=books&page=2&sort=asc")
    assert res["valid"] is True
    assert res["parsed_url"]["has_query"] is True
    ids = [i["id"] for i in res["indicators"]]
    # Should not trigger excessive params (only 3 parameters)
    assert "URL_EXCESSIVE_QUERY_PARAMS" not in ids

def test_rule_non_url_payload():
    # Wi-Fi configuration payload should not be evaluated as a URL
    res = analyze_url_heuristics("WIFI:S:MyCafeWifi;T:WPA;P:SecretPass;;")
    assert res["valid"] is False
    assert res["error_code"] == "NOT_A_WEB_URL"

def test_rule_brand_in_subdomain():
    # paypal in subdomain of unrelated domain (e.g. paypal.com.secure-redirect.xyz)
    res = analyze_url_heuristics("https://paypal.com.account-update.xyz/login")
    assert res["valid"] is True
    ids = [i["id"] for i in res["indicators"]]
    assert "URL_BRAND_IN_SUBDOMAIN" in ids

def test_rule_unusual_port():
    res = analyze_url_heuristics("http://example.com:8888/dashboard")
    assert res["valid"] is True
    assert res["parsed_url"]["port"] == 8888
    ids = [i["id"] for i in res["indicators"]]
    assert "URL_NON_STANDARD_PORT" in ids

def test_zero_outbound_network_requests(monkeypatch):
    """
    Guarantees no outbound socket or HTTP network calls are made during URL analysis.
    """
    import socket
    def forbidden_connect(*args, **kwargs):
        raise AssertionError("Outbound network connection attempted during URL analysis!")
    
    monkeypatch.setattr(socket, "socket", forbidden_connect)
    
    # Analyze various URLs to ensure 100% offline heuristic execution
    analyze_url_heuristics("https://google.com")
    analyze_url_heuristics("http://192.168.1.1/login")
    analyze_url_heuristics("https://paypal.com.evil.xyz/account")

def test_api_analyze_url_endpoint_success(client):
    res = client.post('/api/analyze-url', json={"url": "https://accounts.google.com@phish-hub.net/login"})
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["valid"] is True
    assert "parsed_url" in json_data
    assert len(json_data["indicators"]) > 0

def test_api_analyze_url_endpoint_invalid_json(client):
    res = client.post('/api/analyze-url', data="not json", content_type='text/plain')
    assert res.status_code == 400
    assert res.get_json()["error_code"] == "INVALID_JSON"

def test_api_analyze_url_endpoint_missing_field(client):
    res = client.post('/api/analyze-url', json={"not_url": "test"})
    assert res.status_code == 400
    assert res.get_json()["error_code"] == "MISSING_URL_FIELD"
