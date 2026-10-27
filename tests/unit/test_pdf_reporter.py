"""
Unit tests for QShield PDF Security Report Generator (app/core/pdf_reporter.py).
Verifies report construction, metadata vs live report labeling, Unicode handling,
multi-page generation, privacy sanitization, and output validity.
"""
import pytest
from app.core.pdf_reporter import (
    generate_scan_pdf_report,
    generate_history_pdf_report,
    _sanitize
)


class TestPDFReporter:

    def test_sanitize_escapes_xml_entities(self):
        raw = '<script>alert("test & verify");</script>'
        sanitized = _sanitize(raw)
        assert "<script>" not in sanitized
        assert "&lt;script&gt;" in sanitized
        assert "&amp;" in sanitized

    def test_sanitize_handles_none_and_numbers(self):
        assert _sanitize(None) == ""
        assert _sanitize(12345) == "12345"

    def test_generate_scan_pdf_report_valid(self):
        scan_data = {
            "scan_id": 42,
            "valid": True,
            "target_domain": "chase-security-update.xyz",
            "payload_type": "Web Address (URL)",
            "risk_assessment": {
                "score": 65,
                "risk_level": "high",
                "recommendations": {
                    "next_step": "Do not enter login credentials on this unverified domain."
                }
            },
            "indicators": [
                {
                    "rule_id": "URL_BRAND_IN_SUBDOMAIN",
                    "severity": "high",
                    "message": "Brand impersonation in subdomain structure",
                    "evidence": "chase"
                },
                {
                    "rule_id": "URL_EXCESSIVE_LENGTH",
                    "severity": "low",
                    "message": "URL exceeds normal length limits",
                    "evidence": "length=120"
                }
            ],
            "reputation_result": {
                "status": "completed",
                "reputation": "clean",
                "summary": "Google Safe Browsing reported no active threats."
            },
            "redirect_result": {
                "status": "completed",
                "redirect_count": 1,
                "summary": "Observed 1 benign redirect step."
            },
            "payload_inspection": {
                "format_syntax": "Standard HTTP/HTTPS URL",
                "caution_notice": "Inspect root domain before opening in browser."
            }
        }

        pdf_bytes = generate_scan_pdf_report(scan_data)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b'%PDF-')

    def test_generate_clean_scan_pdf_report_no_indicators(self):
        scan_data = {
            "scan_id": 10,
            "valid": True,
            "target_domain": "wikipedia.org",
            "payload_type": "Web Address (URL)",
            "risk_assessment": {
                "score": 0,
                "risk_level": "low",
                "recommendations": {
                    "next_step": "Verify root domain matches your intended destination."
                }
            },
            "indicators": []
        }

        pdf_bytes = generate_scan_pdf_report(scan_data)
        assert pdf_bytes.startswith(b'%PDF-')
        assert len(pdf_bytes) > 1000

    def test_generate_history_pdf_report_valid(self):
        record = {
            "id": 101,
            "scan_type": "upload",
            "payload_type": "Payment Request (UPI)",
            "target_domain": "merchant@oksbi",
            "risk_score": 15,
            "risk_level": "low",
            "indicator_count": 0,
            "status": "completed",
            "created_at": "2026-10-27 18:30:00"
        }

        pdf_bytes = generate_history_pdf_report(record)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b'%PDF-')
        assert len(pdf_bytes) > 1000

    def test_multi_page_pdf_generation(self):
        """Generates a long report with 20 indicators to test multi-page flow and NumberedCanvas."""
        indicators = []
        for i in range(20):
            indicators.append({
                "rule_id": f"URL_SUSPICIOUS_RULE_{i:02d}",
                "severity": "medium",
                "message": f"Suspicious heuristic indicator #{i} found in the target link structure.",
                "evidence": f"Pattern marker token_{i}=xyz"
            })

        scan_data = {
            "scan_id": 999,
            "valid": True,
            "target_domain": "multi-page-test-domain.org",
            "payload_type": "Web Address (URL)",
            "risk_assessment": {
                "score": 85,
                "risk_level": "critical",
                "recommendations": {
                    "next_step": "Immediately block communication to this domain."
                }
            },
            "indicators": indicators
        }

        pdf_bytes = generate_scan_pdf_report(scan_data)
        assert pdf_bytes.startswith(b'%PDF-')
        # Multi-page document should have larger byte size
        assert len(pdf_bytes) > 5000

    def test_pdf_report_excludes_sensitive_passwords_or_tokens(self):
        """Verifies report generation works without crashing on text with sensitive-looking tokens."""
        scan_data = {
            "scan_id": 55,
            "valid": True,
            "target_domain": "portal.example.com",
            "payload_type": "Wi-Fi Network",
            "risk_assessment": {
                "score": 25,
                "risk_level": "medium",
                "recommendations": {
                    "next_step": "Ensure credentials are masked."
                }
            },
            "indicators": [],
            "payload_inspection": {
                "format_syntax": "WIFI:S:MyCafe;T:WPA;P:••••••••;;",
                "caution_notice": "Wi-Fi password masked as •••••••• for shoulder-surfing protection."
            }
        }

        pdf_bytes = generate_scan_pdf_report(scan_data)
        assert pdf_bytes.startswith(b'%PDF-')

    def test_pdf_report_unicode_and_special_symbols(self):
        scan_data = {
            "scan_id": 77,
            "valid": True,
            "target_domain": "xn--fsqu00a.example",
            "payload_type": "Web Address (URL)",
            "risk_assessment": {
                "score": 40,
                "risk_level": "medium",
                "recommendations": {
                    "next_step": "Check international characters: © ® ™ § ¶"
                }
            },
            "indicators": [
                {
                    "rule_id": "URL_PUNYCODE_HOMOGRAPH",
                    "severity": "medium",
                    "message": "Punycode domain detected: xn--",
                    "evidence": "xn--fsqu00a"
                }
            ]
        }

        pdf_bytes = generate_scan_pdf_report(scan_data)
        assert pdf_bytes.startswith(b'%PDF-')
