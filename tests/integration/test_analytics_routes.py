"""
Integration Tests for QShield Analytics API Routes
Validates JSON schemas, query parameter filtering, admin authorization enforcement,
and prevention of sensitive payload leakage.
"""
import pytest
from app import create_app
from config import TestingConfig, ProductionConfig
from app.database import init_db, record_scan


@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.app_context():
        init_db()
        from app.database import get_db
        db = get_db()
        db.execute("DELETE FROM scan_history")
        db.commit()
    with app.test_client() as client:
        yield client


class TestAnalyticsRoutes:

    def test_analytics_endpoints_empty_database(self, client):
        """All analytics endpoints return success=True and valid schemas on an empty database."""
        endpoints = [
            ('/api/analytics/summary', 'summary'),
            ('/api/analytics/risk-distribution', 'risk_distribution'),
            ('/api/analytics/activity', 'activity'),
            ('/api/analytics/payload-categories', 'payload_categories'),
            ('/api/analytics/detection-methods', 'detection_methods'),
            ('/api/analytics/indicators', 'indicators'),
            ('/api/analytics/trends', 'trends'),
        ]
        for url, key in endpoints:
            res = client.get(url)
            assert res.status_code == 200, f"Failed on {url}"
            data = res.get_json()
            assert data["success"] is True
            assert key in data

    def test_analytics_summary_with_data(self, client):
        """Summary endpoint returns accurate statistics after inserting records."""
        # Insert a high-risk URL scan
        res_post = client.post('/api/analyze-url', json={
            "url": "http://paypal.com.account-update.xyz:8888/login?token=secret123",
            "scan_type": "manual"
        })
        assert res_post.status_code == 200

        res = client.get('/api/analytics/summary?time_range=7d')
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        s = data["summary"]
        assert s["total_scans"] >= 1
        assert s["high_or_critical_scans"] >= 1
        assert s["avg_risk_score"] is not None
        assert s["is_empty"] is False

    def test_risk_distribution_endpoint(self, client):
        """Risk distribution returns counts matching defined score bands."""
        res = client.get('/api/analytics/risk-distribution?time_range=all')
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        rd = data["risk_distribution"]
        assert "distribution" in rd
        levels = [item["id"] for item in rd["distribution"]]
        assert set(levels) == {"low", "medium", "high", "critical", "inconclusive"}

    def test_activity_timeline_endpoint(self, client):
        """Activity timeline supports both 24h hourly and 7d daily intervals."""
        res_24h = client.get('/api/analytics/activity?time_range=24h')
        assert res_24h.status_code == 200
        d_24h = res_24h.get_json()["activity"]
        assert d_24h["interval"] == "hour"
        assert len(d_24h["timeline"]) >= 24

        res_7d = client.get('/api/analytics/activity?time_range=7d')
        assert res_7d.status_code == 200
        d_7d = res_7d.get_json()["activity"]
        assert d_7d["interval"] == "day"
        assert len(d_7d["timeline"]) >= 7

    def test_observed_indicators_endpoint(self, client):
        """Indicators endpoint returns structured indicators without leaking raw URLs."""
        res = client.get('/api/analytics/indicators?time_range=all')
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        ind_data = data["indicators"]
        assert "indicators" in ind_data
        assert "guidance_notice" in ind_data

        # Verify no sensitive URL leak in indicator metadata
        raw_text = res.get_data(as_text=True)
        assert "token=secret123" not in raw_text

    def test_trends_endpoint(self, client):
        """Trends endpoint computes deltas and handles time ranges."""
        res = client.get('/api/analytics/trends?time_range=7d')
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        t = data["trends"]
        assert "metrics" in t
        assert "has_sufficient_data" in t
        assert "disclaimer" in t

    def test_pdf_export_endpoint(self, client):
        """PDF export returns binary PDF with attachment headers."""
        res = client.get('/api/analytics/export-pdf?time_range=7d')
        assert res.status_code == 200
        assert res.headers.get('Content-Type') == 'application/pdf'
        assert 'attachment' in res.headers.get('Content-Disposition', '')
        assert res.data.startswith(b'%PDF-')

    def test_admin_auth_protection_in_production(self):
        """In production environment without ADMIN_API_KEY, analytics endpoints return 403."""
        prod_app = create_app(ProductionConfig)
        with prod_app.test_client() as p_client:
            res = p_client.get('/api/analytics/summary')
            assert res.status_code == 403
            data = res.get_json()
            assert data["error_code"] == "ADMIN_DISABLED_IN_PRODUCTION"

    def test_admin_auth_with_key_in_production(self):
        """In production with ADMIN_API_KEY set, requires valid X-Admin-Key header."""
        prod_app = create_app(ProductionConfig)
        prod_app.config['ADMIN_API_KEY'] = 'test-secret-key-12345'

        with prod_app.test_client() as p_client:
            # 1. No key -> 401
            res_no_key = p_client.get('/api/analytics/summary')
            assert res_no_key.status_code == 401

            # 2. Wrong key -> 401
            res_wrong = p_client.get('/api/analytics/summary', headers={'X-Admin-Key': 'bad-key'})
            assert res_wrong.status_code == 401

            # 3. Valid key -> 200
            res_ok = p_client.get('/api/analytics/summary', headers={'X-Admin-Key': 'test-secret-key-12345'})
            assert res_ok.status_code == 200
            assert res_ok.get_json()["success"] is True
