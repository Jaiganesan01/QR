"""
Unit tests for QShield QR Payload Classifier & Inspector (Prompt 11).
Tests recognition, structured parsing, password masking, malformed inputs,
and security boundaries across all supported payload formats.
"""
import pytest
from app.core.payload_classifier import classify_payload


def test_classify_valid_http_url():
    res = classify_payload("http://example.com/login")
    assert res["payload_type"] == "url"
    assert res["display_name"] == "Web Address (URL)"
    assert res["fields"]["is_https"] is False
    assert res["fields"]["hostname"] == "example.com"
    assert "unencrypted HTTP" in res["warnings"][0]


def test_classify_valid_https_url():
    res = classify_payload("https://secure.chase.com/auth")
    assert res["payload_type"] == "url"
    assert res["fields"]["is_https"] is True
    assert res["fields"]["hostname"] == "secure.chase.com"


def test_classify_plain_text():
    res = classify_payload("Welcome to the cybersecurity seminar in Hall B.")
    assert res["payload_type"] == "plain_text"
    assert res["fields"]["contains_embedded_url"] is False
    assert res["fields"]["character_count"] > 0


def test_classify_plain_text_with_embedded_url():
    res = classify_payload("Please verify your account details at https://secure-bank.example.com immediately.")
    assert res["payload_type"] == "plain_text"
    assert res["fields"]["contains_embedded_url"] is True
    assert res["requires_caution"] is True
    assert any("embedded web link" in w for w in res["warnings"])


def test_classify_valid_wifi_standard_wpa():
    wifi_str = "WIFI:T:WPA;S:HomeNetwork_5G;P:SuperSecretPass123;;;"
    res = classify_payload(wifi_str)
    assert res["payload_type"] == "wifi"
    assert res["fields"]["ssid"] == "HomeNetwork_5G"
    assert res["fields"]["security_type"] == "WPA"
    assert res["fields"]["password_present"] is True
    # Password must be masked! Never exposed in output
    assert res["fields"]["masked_password"] == "••••••••"
    assert "SuperSecretPass123" not in str(res)


def test_classify_wifi_escaped_delimiters():
    wifi_str = r"WIFI:T:WPA;S:Office\;Guest\;Net;P:P\@ss\;word;;"
    res = classify_payload(wifi_str)
    assert res["payload_type"] == "wifi"
    assert res["fields"]["ssid"] == "Office;Guest;Net"
    assert res["fields"]["password_present"] is True
    assert res["fields"]["masked_password"] == "••••••••"


def test_classify_wifi_malformed_no_ssid():
    wifi_str = "WIFI:T:WEP;P:12345;;"
    res = classify_payload(wifi_str)
    assert res["payload_type"] == "wifi"
    assert res["fields"]["ssid"] is None
    assert any("Could not locate Wi-Fi network name" in w for w in res["warnings"])


def test_classify_valid_vcard():
    vcard_payload = (
        "BEGIN:VCARD\n"
        "VERSION:3.0\n"
        "FN:Jane Doe\n"
        "ORG:Acme Cyber Security\n"
        "TEL:+1-555-0199\n"
        "EMAIL:jane.doe@example.org\n"
        "URL:https://acme.example.org\n"
        "END:VCARD"
    )
    res = classify_payload(vcard_payload)
    assert res["payload_type"] == "vcard"
    assert res["fields"]["name"] == "Jane Doe"
    assert res["fields"]["organization"] == "Acme Cyber Security"
    assert res["fields"]["phone"] == "+1-555-0199"
    assert res["fields"]["email"] == "jane.doe@example.org"
    assert res["fields"]["website"] == "https://acme.example.org"
    assert res["requires_caution"] is True  # Contains website URL


def test_classify_malformed_vcard():
    vcard_payload = "BEGIN:VCARD\nVERSION:3.0\nNOTE:Missing FN or N\nEND:VCARD"
    res = classify_payload(vcard_payload)
    assert res["payload_type"] == "vcard"
    assert res["fields"]["name"] is None


def test_classify_mailto_payload():
    res = classify_payload("mailto:support@qshield.example.com?subject=Inquiry&body=Hello%20Team")
    assert res["payload_type"] == "email"
    assert res["fields"]["recipient"] == "support@qshield.example.com"
    assert res["fields"]["subject"] == "Inquiry"
    assert res["fields"]["body_snippet"] == "Hello Team"


def test_classify_tel_payload():
    res = classify_payload("tel:+18005550199")
    assert res["payload_type"] == "phone"
    assert res["fields"]["phone_number"] == "+18005550199"
    assert any("Verify phone number" in w for w in res["warnings"])


def test_classify_sms_payload():
    res = classify_payload("smsto:+18005550199:Your security code is 123456")
    assert res["payload_type"] == "sms"
    assert res["fields"]["recipient_number"] == "+18005550199"
    assert "123456" in res["fields"]["message_body"]


def test_classify_sms_with_smishing_url():
    res = classify_payload("sms:+15551234?body=Package%20delayed%20https://track-post.com/info")
    assert res["payload_type"] == "sms"
    assert res["requires_caution"] is True
    assert any("smishing" in w.lower() for w in res["warnings"])


def test_classify_valid_geo_coordinates():
    res = classify_payload("geo:37.7749,-122.4194")
    assert res["payload_type"] == "geo"
    assert res["fields"]["latitude"] == 37.7749
    assert res["fields"]["longitude"] == -122.4194
    assert res["fields"]["valid_coordinates"] is True


def test_classify_out_of_range_geo_coordinates():
    res = classify_payload("geo:999.000,450.000")
    assert res["payload_type"] == "geo"
    assert res["fields"]["valid_coordinates"] is False
    assert any("out of valid range" in w for w in res["warnings"])


def test_classify_calendar_event():
    cal = (
        "BEGIN:VCALENDAR\n"
        "BEGIN:VEVENT\n"
        "SUMMARY:Security Briefing\n"
        "LOCATION:Room 101\n"
        "DTSTART:20261101T090000Z\n"
        "DTEND:20261101T100000Z\n"
        "END:VEVENT\n"
        "END:VCALENDAR"
    )
    res = classify_payload(cal)
    assert res["payload_type"] == "calendar"
    assert res["fields"]["summary"] == "Security Briefing"
    assert res["fields"]["location"] == "Room 101"
    assert res["fields"]["start_time"] == "20261101T090000Z"


def test_classify_upi_payment_payload():
    upi_str = "upi://pay?pa=merchant@okaxis&pn=CyberCafe&am=150.00&cu=INR&tn=Coffee%20and%20Snacks"
    res = classify_payload(upi_str)
    assert res["payload_type"] == "payment"
    assert res["fields"]["payee_vpa"] == "merchant@okaxis"
    assert res["fields"]["payee_name"] == "CyberCafe"
    assert res["fields"]["amount"] == "150.00"
    assert res["fields"]["currency"] == "INR"
    assert res["fields"]["note"] == "Coffee and Snacks"
    assert res["requires_caution"] is True
    assert any("Payment Request Caution" in w for w in res["warnings"])


def test_classify_upi_malformed():
    res = classify_payload("upi://pay?pn=Unknown")
    assert res["payload_type"] == "payment"
    assert res["fields"]["payee_vpa"] is None
    assert any("Missing Payee" in w for w in res["warnings"])


def test_classify_unsupported_uri_scheme():
    res = classify_payload("javascript:alert(document.cookie)")
    assert res["payload_type"] == "structured_other"
    assert res["fields"]["scheme"] == "javascript"
    assert res["requires_caution"] is True


def test_classify_very_long_payload_truncation():
    long_text = "A" * 3000
    res = classify_payload(long_text)
    assert res["payload_type"] == "plain_text"
    assert res["truncated"] is True
    assert len(res["safe_display_text"]) == 2000


def test_classify_html_script_plain_text():
    raw = "<script>alert('xss')</script><b>Bold Text</b>"
    res = classify_payload(raw)
    assert res["payload_type"] == "plain_text"
    # Content must be preserved as inert plain text, not executed
    assert "<script>" in res["safe_display_text"]


def test_classify_empty_input():
    res = classify_payload("")
    assert res["payload_type"] == "unknown"
    assert res["classification_confidence"] == "low"
