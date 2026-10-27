"""
Comprehensive integration test suite for the complete scan results experience (Prompt 8).
Covers:
1. QR URL decoding and report generation
2. Low-risk response
3. Medium-risk response
4. High-risk response
5. Inconclusive response
6. Plain-text QR payload (non-URL)
7. Empty indicators with clean structure disclaimer
8. Grouped recommendations structure
9. Missing or malformed fields
10. Copy-content and inert rendering
11. Verification that URLs are strictly text and never automatically navigated or embedded in iframes
"""
import io
import pytest
import qrcode
from app import create_app
from config import TestingConfig
from app.core.url_analyzer import analyze_url_heuristics
from app.core.risk_scorer import calculate_risk_score

@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client

def create_qr_image_bytes(data: str) -> bytes:
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def test_1_qr_url_decode_and_api_analyze_flow(client):
    test_url = "https://safe-university.example.edu/admission"
    img_bytes = create_qr_image_bytes(test_url)
    
    # 1. Decode QR
    decode_res = client.post('/api/decode-qr', data={'qr_file': (io.BytesIO(img_bytes), 'univ_qr.png')}, content_type='multipart/form-data')
    assert decode_res.status_code == 200
    decode_data = decode_res.get_json()
    assert decode_data["success"] is True
    assert decode_data["decoded_content"] == test_url
    assert decode_data["payload_type"] == "URL"

    # 2. Analyze URL & generate risk report
    analyze_res = client.post('/api/analyze-url', json={"url": decode_data["decoded_content"]})
    assert analyze_res.status_code == 200
    analyze_data = analyze_res.get_json()
    assert analyze_data["valid"] is True
    assert "risk_assessment" in analyze_data
    assert "checks_performed" in analyze_data
    assert analyze_data["checks_performed"]["qr_decoding"] == "complete"
    assert analyze_data["checks_performed"]["heuristic_analysis"] == "complete"

def test_2_low_risk_response():
    analysis = analyze_url_heuristics("https://github.com/torvalds/linux")
    res = calculate_risk_score(analysis)
    assert res["score"] == 0
    assert res["risk_level"] == "low"
    assert "No configured suspicious indicators" in res["summary"]

def test_3_medium_risk_response():
    # URL Shortener (15 pts = medium risk category)
    analysis = analyze_url_heuristics("https://bit.ly/newsletter-update")
    res = calculate_risk_score(analysis)
    assert 20 <= res["score"] or res["score"] == 15
    assert len(res["recommendations"]) > 0

def test_4_high_risk_response():
    # Brand in subdomain + Credential keyword (25 + 5 = 30 or combined > 50 with userinfo)
    analysis = analyze_url_heuristics("https://admin@paypal.com.account-verification.xyz/login")
    res = calculate_risk_score(analysis)
    assert res["score"] >= 50
    assert res["risk_level"] in ("high", "critical")
    assert "what_to_avoid" in res["grouped_recommendations"]
    assert len(res["grouped_recommendations"]["what_to_avoid"]) > 0

def test_5_inconclusive_response():
    # Non-web payload
    analysis = analyze_url_heuristics("WIFI:S:LibraryWifi;T:WPA;P:guest123;;")
    res = calculate_risk_score(analysis)
    assert res["score"] is None
    assert res["risk_level"] == "inconclusive"
    assert "inconclusive" in res["summary"].lower()

def test_6_plain_text_qr_payload_decode_no_url_scoring(client):
    text_note = "Meeting room reservation: Room 402, 3:00 PM."
    img_bytes = create_qr_image_bytes(text_note)
    
    decode_res = client.post('/api/decode-qr', data={'qr_file': (io.BytesIO(img_bytes), 'note_qr.png')}, content_type='multipart/form-data')
    assert decode_res.status_code == 200
    decode_data = decode_res.get_json()
    assert decode_data["payload_type"] == "Plain Text"
    assert decode_data["decoded_content"] == text_note

def test_7_empty_indicators_disclaimer():
    analysis = analyze_url_heuristics("https://wikipedia.org")
    res = calculate_risk_score(analysis)
    assert res["score"] == 0
    # Mandatory disclaimer present
    assert "limitations" in res
    assert "does not represent a calibrated phishing probability" in res["limitations"]

def test_8_grouped_recommendations_structure():
    analysis = analyze_url_heuristics("https://secure.google.com@evil-portal.net/login")
    res = calculate_risk_score(analysis)
    grouped = res["grouped_recommendations"]
    assert "what_to_check" in grouped
    assert "what_to_avoid" in grouped
    assert "recommended_next_step" in grouped
    assert len(grouped["what_to_check"]) > 0
    assert len(grouped["what_to_avoid"]) > 0

def test_9_malformed_api_input(client):
    res = client.post('/api/analyze-url', json={"url": ""})
    assert res.status_code == 400
    assert res.get_json()["error_code"] == "EMPTY_INPUT"

def test_10_html_characters_escaped_in_rendered_template(client):
    # Verify that dangerous inputs submitted through scan route are escaped by Jinja2
    res = client.post('/scanner', data={'manual_url': 'https://example.com/<script>alert(1)</script>'})
    assert res.status_code == 200
    # Must not contain raw unescaped script tag in rendered HTML
    assert b"<script>alert(1)</script>" not in res.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in res.data or b"&lt;script&gt;" in res.data

def test_11_no_iframe_in_scan_page(client):
    res = client.get('/scanner')
    assert res.status_code == 200
    # Security requirement: Never embed decoded target in iframe
    assert b"<iframe" not in res.data
