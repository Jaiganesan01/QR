"""
Unit and API integration tests for the Explainable Risk Scoring Engine.
Covers:
1. Valid URL with no matching indicators
2. One low-severity indicator
3. One medium-severity indicator
4. One high-severity indicator
5. Multiple independent indicators
6. Duplicate indicators handling
7. Related indicator discount/aggregation
8. Score capping at 100
9. Malformed URL producing inconclusive
10. Non-URL payload producing inconclusive
11. Unsupported scheme
12. HTTP not automatically phishing
13. HTTPS not automatically safe
14. Scoring error handling
15. Relevant recommendations generation
16. Frontend integration via /api/analyze-url
"""
import pytest
from app import create_app
from config import TestingConfig
from app.core.risk_scorer import calculate_risk_score, get_risk_category
from app.core.url_analyzer import analyze_url_heuristics

@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client

def test_risk_category_thresholds():
    assert get_risk_category(0) == "low"
    assert get_risk_category(19) == "low"
    assert get_risk_category(20) == "medium"
    assert get_risk_category(49) == "medium"
    assert get_risk_category(50) == "high"
    assert get_risk_category(79) == "high"
    assert get_risk_category(80) == "critical"
    assert get_risk_category(100) == "critical"

def test_1_valid_url_no_matching_indicators():
    # Clean domain
    analysis = analyze_url_heuristics("https://en.wikipedia.org/wiki/Python")
    res = calculate_risk_score(analysis)
    assert res["score"] == 0
    assert res["risk_level"] == "low"
    assert "No configured suspicious indicators were detected" in res["summary"]
    assert len(res["recommendations"]) > 0

def test_2_one_low_severity_indicator():
    # URL with single credential keyword in path on ordinary https domain
    mock_analysis = {
        "valid": True,
        "indicators": [
            {"id": "URL_CREDENTIAL_KEYWORDS_IN_PATH", "severity": "low", "title": "Cred", "explanation": "Test"}
        ]
    }
    res = calculate_risk_score(mock_analysis)
    assert res["score"] == 5
    assert res["risk_level"] == "low"
    assert res["contributing_indicators"][0]["weight"] == 5

def test_3_one_medium_severity_indicator():
    # Single medium severity (e.g. shortener)
    mock_analysis = {
        "valid": True,
        "indicators": [
            {"id": "URL_SHORTENER_DETECTED", "severity": "medium", "title": "Shortener", "explanation": "Test"}
        ]
    }
    res = calculate_risk_score(mock_analysis)
    assert res["score"] == 15
    assert res["risk_level"] == "low"  # 15 is in 0-19 low band

def test_4_one_high_severity_indicator():
    # Single high severity (e.g. raw IP host)
    mock_analysis = {
        "valid": True,
        "indicators": [
            {"id": "URL_RAW_IP_HOST", "severity": "high", "title": "Raw IP", "explanation": "Test"}
        ]
    }
    res = calculate_risk_score(mock_analysis)
    assert res["score"] == 25
    assert res["risk_level"] == "medium"  # 25 is in 20-49 medium band

def test_5_multiple_independent_indicators():
    # Raw IP (25) + Shortener (15) + Credential (5) = 45 (Medium)
    mock_analysis = {
        "valid": True,
        "indicators": [
            {"id": "URL_RAW_IP_HOST", "severity": "high", "title": "Raw IP"},
            {"id": "URL_SHORTENER_DETECTED", "severity": "medium", "title": "Shortener"},
            {"id": "URL_CREDENTIAL_KEYWORDS_IN_PATH", "severity": "low", "title": "Cred"}
        ]
    }
    res = calculate_risk_score(mock_analysis)
    assert res["score"] == 45
    assert res["risk_level"] == "medium"

def test_6_duplicate_indicators_handling():
    # Same indicator included twice should NOT double count
    mock_analysis = {
        "valid": True,
        "indicators": [
            {"id": "URL_RAW_IP_HOST", "severity": "high", "title": "Raw IP"},
            {"id": "URL_RAW_IP_HOST", "severity": "high", "title": "Raw IP"}
        ]
    }
    res = calculate_risk_score(mock_analysis)
    assert res["score"] == 25
    assert len(res["contributing_indicators"]) == 1

def test_7_related_indicators_aggregation():
    # Brand in subdomain (high = 25) + Brand typosquat (medium = 15)
    # Since both belong to brand_mimicry group, secondary receives 50% discount (15 -> 8)
    mock_analysis = {
        "valid": True,
        "indicators": [
            {"id": "URL_BRAND_IN_SUBDOMAIN", "severity": "high", "title": "Brand in Subdomain"},
            {"id": "URL_BRAND_TYPOSQUAT_SUSPICION", "severity": "medium", "title": "Brand Typosquat"}
        ]
    }
    res = calculate_risk_score(mock_analysis)
    # 25 + 8 = 33
    assert res["score"] == 33
    assert res["score_breakdown"]["deduplication_adjustments"] > 0

def test_8_score_capping_at_100():
    # 5 high indicators = 125 -> capped at 100
    mock_analysis = {
        "valid": True,
        "indicators": [
            {"id": f"IND_HIGH_{i}", "severity": "high", "title": f"High {i}"} for i in range(5)
        ]
    }
    res = calculate_risk_score(mock_analysis)
    assert res["score"] == 100
    assert res["risk_level"] == "critical"

def test_9_malformed_url_inconclusive():
    analysis = analyze_url_heuristics("http://")
    res = calculate_risk_score(analysis)
    assert res["score"] is None
    assert res["risk_level"] == "inconclusive"

def test_10_non_url_payload_inconclusive():
    analysis = analyze_url_heuristics("WIFI:S:HomeNet;T:WPA;P:secret;;")
    res = calculate_risk_score(analysis)
    assert res["score"] is None
    assert res["risk_level"] == "inconclusive"

def test_11_unsupported_scheme():
    analysis = analyze_url_heuristics("javascript:alert(1)")
    res = calculate_risk_score(analysis)
    assert res["score"] is None
    assert res["risk_level"] == "inconclusive"

def test_12_http_not_automatically_phishing():
    # Plain HTTP on ordinary benign domain
    analysis = analyze_url_heuristics("http://example.com/info")
    res = calculate_risk_score(analysis)
    # HTTP is medium (15 points), which stays in Low (0-19)
    assert res["score"] == 15
    assert res["risk_level"] == "low"
    assert "Critical" not in res["summary"]

def test_13_https_not_automatically_safe():
    # HTTPS URL with multiple high/medium risk spoofing tricks:
    # Userinfo syntax (25) + Brand in Subdomain (25) + Credential keyword in path (5) = 55 (High)
    analysis = analyze_url_heuristics("https://user@paypal.com.verify-billing.xyz/login")
    res = calculate_risk_score(analysis)
    assert res["score"] >= 50
    assert res["risk_level"] in ("high", "critical")

def test_14_scoring_error_produces_inconclusive():
    res = calculate_risk_score(None)
    assert res["score"] is None
    assert res["risk_level"] == "inconclusive"

def test_15_recommendations_match_findings():
    analysis = analyze_url_heuristics("https://accounts.google.com@phish-hub.net/login")
    res = calculate_risk_score(analysis)
    assert any("@" in r for r in res["recommendations"])

def test_16_frontend_api_returns_risk_assessment(client):
    res = client.post('/api/analyze-url', json={"url": "https://paypal.com.evil-billing.xyz/login"})
    assert res.status_code == 200
    json_data = res.get_json()
    assert "risk_assessment" in json_data
    risk = json_data["risk_assessment"]
    assert risk["score"] is not None
    assert risk["risk_level"] in ("low", "medium", "high", "critical")
    assert len(risk["contributing_indicators"]) > 0
    assert len(risk["recommendations"]) > 0
    assert "limitations" in risk
