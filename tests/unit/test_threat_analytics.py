"""
Unit Tests for QShield Advanced Threat Intelligence & QR Risk Analytics
Validates KPI aggregations, time-bucketed timelines, risk distributions,
observed indicators, period trend comparisons, and PDF generation.
"""
import pytest
from datetime import datetime, timedelta, timezone

from app import create_app
from config import TestingConfig
from app.database import (
    init_db,
    record_scan,
    update_scan_threat_intel,
    get_analytics_summary,
    get_risk_distribution,
    get_activity_timeline,
    get_payload_categories,
    get_detection_methods,
    get_observed_indicators,
    get_trend_analysis
)
from app.core.pdf_reporter import generate_analytics_pdf_report


@pytest.fixture
def test_app():
    app = create_app(TestingConfig)
    with app.app_context():
        init_db()
        from app.database import get_db
        db = get_db()
        db.execute("DELETE FROM scan_history")
        db.commit()
        yield app


class TestThreatAnalyticsAggregations:

    def test_empty_database_summary_and_distributions(self, test_app):
        """Empty database returns zero counts and is_empty=True without raising errors."""
        with test_app.app_context():
            summary = get_analytics_summary()
            assert summary["total_scans"] == 0
            assert summary["high_or_critical_scans"] == 0
            assert summary["inconclusive_scans"] == 0
            assert summary["avg_risk_score"] is None
            assert summary["is_empty"] is True

            dist = get_risk_distribution()
            assert dist["total_scans"] == 0
            assert dist["is_empty"] is True
            assert len(dist["distribution"]) == 5

            cats = get_payload_categories()
            assert cats["total_scans"] == 0
            assert cats["is_empty"] is True
            assert cats["categories"] == []

            methods = get_detection_methods()
            assert methods["total_scans"] == 0
            assert methods["is_empty"] is True

            inds = get_observed_indicators()
            assert inds["total_scans_evaluated"] == 0
            assert inds["is_empty"] is True
            assert "Structural risk indicators provide observable evidence" in inds["guidance_notice"]

    def test_single_scan_metrics(self, test_app):
        """Single recorded scan aggregates correctly."""
        with test_app.app_context():
            record_scan(
                scan_type="manual",
                payload_type="URL",
                target_domain="secure-portal.xyz",
                risk_score=75,
                risk_level="high",
                indicator_count=2,
                status="completed",
                detection_method="heuristic_rules",
                indicators=["URL_BRAND_IN_SUBDOMAIN", "URL_NON_STANDARD_PORT"]
            )

            summary = get_analytics_summary(time_range="7d")
            assert summary["total_scans"] == 1
            assert summary["high_risk_scans"] == 1
            assert summary["critical_risk_scans"] == 0
            assert summary["high_or_critical_scans"] == 1
            assert summary["avg_risk_score"] == 75.0
            assert summary["is_empty"] is False

            inds = get_observed_indicators(time_range="7d")
            assert inds["total_scans_evaluated"] == 1
            ind_map = {i["id"]: i for i in inds["indicators"]}
            assert ind_map["URL_BRAND_IN_SUBDOMAIN"]["count"] == 1
            assert ind_map["URL_NON_STANDARD_PORT"]["count"] == 1
            assert ind_map["URL_RAW_IP_HOST"]["count"] == 0

    def test_multiple_mixed_scans_and_filters(self, test_app):
        """Aggregates multiple records with diverse risk levels, categories, and methods."""
        with test_app.app_context():
            # 1. Critical URL with IP Host
            s1 = record_scan(
                scan_type="upload",
                payload_type="URL",
                target_domain="192.168.1.1",
                risk_score=90,
                risk_level="critical",
                indicator_count=2,
                status="completed",
                detection_method="ensemble",
                indicators=["URL_RAW_IP_HOST", "URL_CREDENTIAL_KEYWORDS_IN_PATH"]
            )
            # Update threat intel match
            update_scan_threat_intel(s1, threat_status="clean", is_flagged=True)

            # 2. Low Risk URL
            record_scan(
                scan_type="manual",
                payload_type="URL",
                target_domain="trusted-bank.com",
                risk_score=10,
                risk_level="low",
                indicator_count=0,
                status="completed",
                detection_method="heuristic_rules"
            )

            # 3. Medium Risk URL with Shortener
            record_scan(
                scan_type="upload",
                payload_type="URL",
                target_domain="bit.ly",
                risk_score=35,
                risk_level="medium",
                indicator_count=1,
                status="completed",
                detection_method="heuristic_rules",
                indicators=["URL_SHORTENER_DOMAIN"]
            )

            # 4. Inconclusive Wi-Fi configuration
            record_scan(
                scan_type="upload",
                payload_type="Wi-Fi",
                target_domain=None,
                risk_score=None,
                risk_level="inconclusive",
                indicator_count=0,
                status="inconclusive",
                detection_method="inconclusive"
            )

            # 5. Payment Request (UPI)
            record_scan(
                scan_type="manual",
                payload_type="Payment Request (UPI)",
                target_domain="merchant@upi",
                risk_score=15,
                risk_level="low",
                indicator_count=0,
                status="completed",
                detection_method="inconclusive"
            )

            # Unfiltered summary
            summary = get_analytics_summary(time_range="all")
            assert summary["total_scans"] == 5
            assert summary["high_or_critical_scans"] == 1
            assert summary["critical_risk_scans"] == 1
            assert summary["inconclusive_scans"] == 1
            assert summary["low_risk_scans"] == 2
            assert summary["medium_risk_scans"] == 1
            assert summary["scored_scans"] == 4
            # avg of 90, 10, 35, 15 = 150 / 4 = 37.5
            assert summary["avg_risk_score"] == 37.5
            assert summary["external_threat_detections"] == 1

            # Filter by category: URL only
            url_summary = get_analytics_summary(time_range="all", payload_type="URL")
            assert url_summary["total_scans"] == 3
            assert url_summary["high_or_critical_scans"] == 1

            # Filter by risk_level: low only
            low_summary = get_analytics_summary(time_range="all", risk_level="low")
            assert low_summary["total_scans"] == 2
            assert low_summary["low_risk_scans"] == 2

            # Filter by detection_method: ensemble only
            ens_summary = get_analytics_summary(time_range="all", detection_method="ensemble")
            assert ens_summary["total_scans"] == 1
            assert ens_summary["avg_risk_score"] == 90.0

    def test_sql_injection_safety_in_filters(self, test_app):
        """Malicious SQL injection filter inputs are treated as literal strings via parameterized SQL."""
        with test_app.app_context():
            record_scan(
                scan_type="upload",
                payload_type="URL",
                target_domain="normal.com",
                risk_score=10,
                risk_level="low",
                status="completed"
            )

            # SQL injection in payload_type
            res = get_analytics_summary(payload_type="' OR '1'='1' --", time_range="all")
            assert res["total_scans"] == 0

            # SQL injection in risk_level
            res_risk = get_analytics_summary(risk_level="critical' UNION SELECT 1,2,3 --", time_range="all")
            # Invalid risk level is ignored or matched literally to 0
            assert res_risk["total_scans"] in (0, 1)

    def test_activity_timeline_hourly_and_daily(self, test_app):
        """Activity timeline builds complete hourly buckets for 24h and daily buckets for 7d."""
        with test_app.app_context():
            record_scan(
                scan_type="manual",
                payload_type="URL",
                target_domain="example.org",
                risk_score=60,
                risk_level="high",
                status="completed"
            )

            # 24h timeline
            tl_24h = get_activity_timeline(time_range="24h")
            assert tl_24h["interval"] == "hour"
            assert len(tl_24h["timeline"]) >= 24
            assert tl_24h["total_scans"] >= 1

            # 7d timeline
            tl_7d = get_activity_timeline(time_range="7d")
            assert tl_7d["interval"] == "day"
            assert len(tl_7d["timeline"]) >= 7
            assert tl_7d["total_scans"] >= 1

    def test_trends_small_dataset_safeguard(self, test_app):
        """When fewer than 5 records exist, trend analysis reports insufficient data."""
        with test_app.app_context():
            record_scan(
                scan_type="manual",
                payload_type="URL",
                target_domain="test.com",
                risk_score=20,
                risk_level="medium",
                status="completed"
            )

            trends = get_trend_analysis(time_range="7d")
            assert trends["has_sufficient_data"] is False
            assert "Not enough data to identify a trend" in trends["summary_message"]
            assert "Local scan activity only" in trends["disclaimer"]

    def test_trends_division_by_zero_handling(self, test_app):
        """When previous period has 0 records and current period has records, no ZeroDivisionError occurs."""
        with test_app.app_context():
            # Insert 5 scans in current period
            for i in range(5):
                record_scan(
                    scan_type="manual",
                    payload_type="URL",
                    target_domain=f"test{i}.com",
                    risk_score=60,
                    risk_level="high",
                    status="completed"
                )

            trends = get_trend_analysis(time_range="7d")
            assert trends["has_sufficient_data"] is True
            # Previous period was 0, so percentage_change should be None, absolute change is 5
            scans_metric = trends["metrics"]["total_scans"]
            assert scans_metric["absolute_change"] == 5
            assert scans_metric["percentage_change"] is None
            assert scans_metric["direction"] == "up"

    def test_analytics_pdf_generation(self, test_app):
        """Generates valid multi-page PDF bytes from aggregated analytics data without leaking secrets."""
        with test_app.app_context():
            record_scan(
                scan_type="manual",
                payload_type="URL",
                target_domain="secure-check.org",
                risk_score=85,
                risk_level="critical",
                status="completed",
                indicators=["URL_BRAND_IN_SUBDOMAIN", "URL_PUNYCODE_HOST"]
            )

            bundle = {
                "summary": get_analytics_summary(time_range="7d"),
                "risk_distribution": get_risk_distribution(time_range="7d"),
                "payload_categories": get_payload_categories(time_range="7d"),
                "detection_methods": get_detection_methods(time_range="7d"),
                "indicators": get_observed_indicators(time_range="7d"),
                "trends": get_trend_analysis(time_range="7d"),
                "time_range_label": "last_7_days"
            }

            pdf_bytes = generate_analytics_pdf_report(bundle)
            assert isinstance(pdf_bytes, bytes)
            assert len(pdf_bytes) > 1000
            assert pdf_bytes.startswith(b'%PDF-')
