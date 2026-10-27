"""
Unit tests for Scan History database manager enhancements and admin aggregations.
Verifies parameterized SQL filtering, pagination, search, metrics, and SQL injection safety.
"""
import pytest
from app import create_app
from config import TestingConfig
from app.database import (
    init_db,
    record_scan,
    get_scan_history,
    get_scan_history_count,
    get_admin_metrics,
    get_scan_by_id,
    delete_scan
)


@pytest.fixture
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        init_db()
        from app.database import get_db
        db = get_db()
        db.execute("DELETE FROM scan_history")
        db.commit()
        yield app


class TestHistoryDB:

    def test_empty_database_metrics(self, app):
        with app.app_context():
            metrics = get_admin_metrics()
            assert metrics["total_scans"] == 0
            assert metrics["scans_today"] == 0
            assert metrics["scans_with_scores"] == 0
            assert metrics["avg_risk_score"] is None
            assert metrics["by_payload_type"] == {}
            assert metrics["by_risk_level"] == {}
            assert metrics["recent_activity"] == []

    def test_record_and_filter_history(self, app):
        with app.app_context():
            id1 = record_scan(
                scan_type="upload",
                payload_type="Web Address (URL)",
                target_domain="bank-update.xyz",
                risk_score=75,
                risk_level="high",
                indicator_count=2,
                status="completed"
            )
            id2 = record_scan(
                scan_type="manual",
                payload_type="Payment Request (UPI)",
                target_domain="merchant@oksbi",
                risk_score=10,
                risk_level="low",
                indicator_count=0,
                status="completed"
            )
            id3 = record_scan(
                scan_type="upload",
                payload_type="Plain Text",
                target_domain=None,
                risk_score=None,
                risk_level=None,
                indicator_count=0,
                status="inconclusive"
            )

            # Test unfiltered count
            assert get_scan_history_count() == 3

            # Filter by category
            upi_scans = get_scan_history(payload_type="Payment Request (UPI)")
            assert len(upi_scans) == 1
            assert upi_scans[0]["id"] == id2

            # Filter by risk_level
            high_scans = get_scan_history(risk_level="high")
            assert len(high_scans) == 1
            assert high_scans[0]["id"] == id1

            # Filter by status
            inconclusive_scans = get_scan_history(status="inconclusive")
            assert len(inconclusive_scans) == 1
            assert inconclusive_scans[0]["id"] == id3

    def test_pagination_and_bounds(self, app):
        with app.app_context():
            # Insert 5 records
            for i in range(5):
                record_scan(
                    scan_type="manual",
                    payload_type="Web Address (URL)",
                    target_domain=f"domain-{i}.com",
                    risk_score=i * 10,
                    risk_level="low" if i < 2 else "medium",
                    indicator_count=i,
                    status="completed"
                )

            assert get_scan_history_count() == 5

            # Page 1 with limit 2
            p1 = get_scan_history(limit=2, offset=0)
            assert len(p1) == 2

            # Page 2 with limit 2
            p2 = get_scan_history(limit=2, offset=2)
            assert len(p2) == 2
            assert p1[0]["id"] != p2[0]["id"]

            # Page 3 with limit 2 (only 1 remaining)
            p3 = get_scan_history(limit=2, offset=4)
            assert len(p3) == 1

    def test_search_by_id_and_keyword(self, app):
        with app.app_context():
            id1 = record_scan(
                scan_type="upload",
                payload_type="Wi-Fi Network",
                target_domain="airport_wifi",
                risk_score=20,
                risk_level="medium",
                indicator_count=1,
                status="completed"
            )
            id2 = record_scan(
                scan_type="manual",
                payload_type="Web Address (URL)",
                target_domain="login.corp.org",
                risk_score=5,
                risk_level="low",
                indicator_count=0,
                status="completed"
            )

            # Search by specific ID
            res_id = get_scan_history(search=str(id1))
            assert len(res_id) == 1
            assert res_id[0]["id"] == id1

            # Search by keyword in domain or payload
            res_kw = get_scan_history(search="Wi-Fi")
            assert len(res_kw) == 1
            assert res_kw[0]["payload_type"] == "Wi-Fi Network"

    def test_sql_injection_safety(self, app):
        with app.app_context():
            record_scan(
                scan_type="upload",
                payload_type="Web Address (URL)",
                target_domain="legit.org",
                risk_score=0,
                risk_level="low",
                indicator_count=0,
                status="completed"
            )

            # Malicious payloads attempting boolean bypass or UNION injection
            malicious_searches = [
                "' OR '1'='1",
                "1; DROP TABLE scan_history; --",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9 --"
            ]

            for evil in malicious_searches:
                # Should not crash, and should not return unauthorized records
                result = get_scan_history(search=evil)
                assert isinstance(result, list)
                assert len(result) == 0

                count = get_scan_history_count(search=evil)
                assert count == 0

            # Verify table still exists and data is intact
            assert get_scan_history_count() == 1

    def test_admin_metrics_aggregations(self, app):
        with app.app_context():
            record_scan("upload", "Web Address (URL)", "site1.org", risk_score=20, risk_level="medium", indicator_count=1, status="completed")
            record_scan("upload", "Web Address (URL)", "site2.org", risk_score=80, risk_level="critical", indicator_count=3, status="completed")
            record_scan("manual", "Wi-Fi Network", None, risk_score=None, risk_level=None, indicator_count=0, status="inconclusive")

            metrics = get_admin_metrics()
            assert metrics["total_scans"] == 3
            assert metrics["scans_today"] == 3
            assert metrics["scans_with_scores"] == 2
            assert metrics["avg_risk_score"] == 50.0  # (20 + 80) / 2
            assert metrics["by_payload_type"]["Web Address (URL)"] == 2
            assert metrics["by_payload_type"]["Wi-Fi Network"] == 1
            assert metrics["by_risk_level"]["medium"] == 1
            assert metrics["by_risk_level"]["critical"] == 1
            assert metrics["by_risk_level"]["inconclusive"] == 1
            assert len(metrics["recent_activity"]) == 3
