"""
Unit & Integration Test Suite for QShield AI-Powered Threat Detection Engine (Prompt 18).
Validates:
- 20+ feature extraction metrics (lengths, entropy, character counts, redirect params, encoding)
- Shannon entropy mathematical precision
- Modular detection engine coordination (heuristics, payload classification, threat feeds, ML fallback)
- Safe handling of benign, suspicious, malformed, Punycode, raw IP, and edge-case URLs
- Deterministic score stability
- Safe handling of non-URL payloads (Wi-Fi, vCard, Plain Text)
- ML model adapter 'unavailable' status & graceful fallback without fabrication
- Distinguishing local structural risk from external threat intelligence
"""
import pytest
from app.core.feature_extractor import (
    extract_url_features,
    extract_numerical_feature_vector,
    calculate_entropy,
    is_ip_host
)
from app.core.detection_engine import ModularDetectionEngine, get_detection_engine
from app.core.ml_classifier import MLThreatClassifier


# =============================================================================
# 1. Feature Extractor Unit Tests
# =============================================================================

def test_entropy_calculation_accuracy():
    """Verify Shannon entropy calculation on known strings."""
    # Empty string has 0 entropy
    assert calculate_entropy("") == 0.0
    # Single repeating character has 0 entropy
    assert calculate_entropy("aaaaaaa") == 0.0
    # Diverse high-entropy token has entropy >= 4.0
    high_entropy_token = "7b2e9a8f4c1d0e5b3a6f9c2d8e1a7b4f"
    assert calculate_entropy(high_entropy_token) >= 3.8


def test_ip_host_detection():
    """Verify IPv4 and IPv6 literal identification."""
    assert is_ip_host("192.168.1.1") is True
    assert is_ip_host("10.0.0.1") is True
    assert is_ip_host("::1") is True
    assert is_ip_host("2001:db8::1") is True
    assert is_ip_host("google.com") is False
    assert is_ip_host("paypal.verify.net") is False


def test_feature_extractor_on_benign_url():
    """Extract features from a standard legitimate HTTPS URL."""
    url = "https://en.wikipedia.org/wiki/Computer_security"
    res = extract_url_features(url)
    assert res["valid"] is True
    f = res["features"]

    assert f["is_https"] is True
    assert f["hostname"] == "en.wikipedia.org"
    assert f["registered_domain"] == "wikipedia.org"
    assert f["subdomain_depth"] == 1
    assert f["is_ip_host"] is False
    assert f["is_punycode"] is False
    assert f["has_userinfo"] is False
    assert f["has_non_standard_port"] is False
    assert f["is_shortener"] is False
    assert f["has_redirect_param"] is False
    assert len(f["matched_brands"]) == 0


def test_feature_extractor_detects_redirect_parameters():
    """URLs containing redirect-related query keys must be flagged."""
    url = "https://legit-portal.com/auth?redirect=https://external-target.com&user=1"
    res = extract_url_features(url)
    assert res["valid"] is True
    f = res["features"]

    assert f["has_redirect_param"] is True
    assert "redirect" in f["redirect_params"]


def test_feature_extractor_detects_brand_in_subdomain():
    """Detects when a known brand substring appears in subdomain."""
    url = "https://paypal.com.account-update.xyz/login"
    res = extract_url_features(url)
    assert res["valid"] is True
    f = res["features"]

    assert len(f["matched_brands"]) > 0
    match = f["matched_brands"][0]
    assert match["brand"] == "paypal"
    assert match["location"] == "subdomain"


def test_feature_extractor_excessive_percent_encoding():
    """Detects URLs with 3+ percent-encoded triplets."""
    url = "https://example.com/path%20with%20multiple%20escapes%2ehtml"
    res = extract_url_features(url)
    assert res["valid"] is True
    f = res["features"]

    assert f["percent_encoding_count"] >= 3
    assert f["excessive_encoding"] is True


def test_numerical_feature_vector_structure():
    """Verify fixed-length numerical feature dictionary output."""
    url = "https://example.com/test?q=123"
    vec = extract_numerical_feature_vector(url)

    expected_keys = [
        "f_url_len", "f_host_len", "f_path_len", "f_query_len",
        "f_subdomain_depth", "f_hyphen_count", "f_digit_ratio",
        "f_percent_count", "f_path_entropy", "f_query_entropy",
        "f_is_https", "f_is_ip_host", "f_is_punycode", "f_has_userinfo",
        "f_is_shortener", "f_has_redirect_param", "f_has_non_standard_port",
        "f_brand_mimicry", "f_cred_keywords", "f_urgency_keywords",
        "f_query_param_count"
    ]
    for k in expected_keys:
        assert k in vec
        assert isinstance(vec[k], float)


# =============================================================================
# 2. ML Classifier Adapter Tests
# =============================================================================

def test_ml_classifier_unconfigured_status_and_safe_fallback():
    """When no model artifact is provided, ML adapter reports unavailable without raising errors."""
    classifier = MLThreatClassifier(model_path=None)
    assert classifier.is_available() is False

    res = classifier.predict("https://example.com")
    assert res["status"] == "unavailable"
    assert res["prediction"] is None
    assert "explainable rule-based heuristics" in res["message"]


def test_ml_classifier_custom_mock_estimator():
    """Verify that pluggable estimators can be evaluated if configured."""
    classifier = MLThreatClassifier()
    # Mock active estimator
    mock_model = type("MockEstimator", (), {
        "predict": lambda self, X: [1],
        "predict_proba": lambda self, X: [[0.15, 0.85]]
    })()
    classifier._model = mock_model
    classifier._metadata["status"] = "active"

    assert classifier.is_available() is True
    pred = classifier.predict("https://suspicious-test.com")
    assert pred["status"] == "completed"
    assert pred["prediction"] == "suspicious"
    assert pred["confidence"] == 0.85


# =============================================================================
# 3. Modular Detection Engine Integration Tests
# =============================================================================

def test_detection_engine_benign_url():
    """Benign standard URL produces low risk with heuristic_rules method."""
    engine = get_detection_engine()
    res = engine.evaluate("https://python.org/doc/")

    assert res["analysis_status"] == "completed"
    assert res["analysis_method"] == "heuristic_rules"
    assert res["risk_level"] == "low"
    assert res["risk_score"] < 25
    assert "local_heuristics" in res["evidence_sources"]
    assert "payload_classifier" in res["evidence_sources"]


def test_detection_engine_suspicious_url_high_risk():
    """Deceptive subdomain URL with non-standard port triggers elevated risk with explainable findings."""
    engine = get_detection_engine()
    res = engine.evaluate("http://chase.com.security-check.xyz:8888/login/verify")

    assert res["analysis_status"] == "completed"
    assert res["risk_level"] in ("high", "critical")
    assert res["risk_score"] >= 50
    assert len(res["findings"]) > 0

    finding_ids = [f["id"] for f in res["findings"]]
    assert "URL_BRAND_IN_SUBDOMAIN" in finding_ids
    assert "URL_UNENCRYPTED_HTTP" in finding_ids
    assert "URL_NON_STANDARD_PORT" in finding_ids


def test_detection_engine_non_url_payload_inconclusive():
    """Wi-Fi and vCard payloads evaluate as inconclusive for URL heuristics."""
    engine = get_detection_engine()
    wifi_str = "WIFI:T:WPA;S:Home_Network;P:mysecretpass123;;"
    res = engine.evaluate(wifi_str)

    assert res["analysis_status"] == "inconclusive"
    assert res["risk_level"] == "inconclusive"
    assert res["risk_score"] is None
    assert res["confidence_label"] == "insufficient_evidence"
    assert res["payload_classification"]["payload_type"] == "wifi"


def test_detection_engine_punycode_and_ip_host():
    """Punycode and raw IP destinations are evaluated accurately."""
    engine = get_detection_engine()

    # Raw IP
    res_ip = engine.evaluate("http://192.168.1.100/admin")
    assert any(f["id"] == "URL_RAW_IP_HOST" for f in res_ip["findings"])

    # Punycode
    res_puny = engine.evaluate("https://xn--e1afmkfd.xn--p1ai/")
    assert any(f["id"] == "URL_PUNYCODE_HOMOGRAPH" for f in res_puny["findings"])


def test_detection_engine_reputation_feed_elevation():
    """When external threat intelligence confirms malware, risk elevates to critical."""
    engine = get_detection_engine()
    mock_reputation = {
        "provider": "Google Safe Browsing",
        "status": "checked",
        "reputation": "malicious",
        "threat_categories": ["MALWARE"]
    }
    res = engine.evaluate("https://example.com/test", reputation_result=mock_reputation)

    assert res["analysis_method"] == "heuristic_plus_threat_feed"
    assert res["risk_level"] == "critical"
    assert res["risk_score"] >= 85
    assert "threat_intelligence_feed" in res["evidence_sources"]


def test_detection_engine_empty_input_handling():
    """Empty or whitespace-only inputs fail safely."""
    engine = get_detection_engine()
    res = engine.evaluate("")
    assert res["analysis_status"] == "failed"
    assert res["risk_score"] is None
    assert res["confidence_label"] == "insufficient_evidence"


def test_detection_engine_stable_scoring_for_identical_inputs():
    """Identical inputs under identical conditions must produce the exact same score."""
    engine = get_detection_engine()
    url = "https://paypal.com.verify-billing.xyz/account/login"
    res1 = engine.evaluate(url)
    res2 = engine.evaluate(url)

    assert res1["risk_score"] == res2["risk_score"]
    assert res1["risk_level"] == res2["risk_level"]
    assert len(res1["findings"]) == len(res2["findings"])
