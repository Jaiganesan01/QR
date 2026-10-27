"""
Integration tests for QShield Scan History, PDF Security Reports, and Admin Dashboard.
"""
import pytest
from app import create_app
from config import TestingConfig
from app.database import init_db, record_scan


@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.app_context():
        init_db()
    with app.test_client() as client:
        yield client


class TestScanHistoryPagesAndEndpoints:

    def test_history_page_loads(self, client):
        response = client.get('/history')
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Scan History" in html
        assert "filterCategory" in html
        assert "filterRisk" in html
        assert "historyTable" in html or "historyTbody" in html

    def test_api_scan_history_pagination_and_filtering(self, client):
        # Create records
        client.post('/api/analyze-url', json={"url": "https://low-risk-site.org"})
        client.post('/api/analyze-url', json={"url": "https://chase.com.security-verify.xyz/login"})

        # Get history with page & limit
        res = client.get('/api/scan-history?page=1&limit=10')
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["total"] >= 2
        assert len(data["history"]) >= 2
        assert "page" in data
        assert "limit" in data

        # Filter by risk level
        res_high = client.get('/api/scan-history?risk_level=high')
        assert res_high.status_code == 200
        data_high = res_high.get_json()
        for item in data_high["history"]:
            assert item["risk_level"] == "high"

    def test_api_scan_detail_and_delete(self, client):
        res = client.post('/api/analyze-url', json={"url": "https://test-detail.org"})
        scan_id = res.get_json().get("scan_id")
        assert scan_id is not None

        # Fetch detail
        detail_res = client.get(f'/api/scan-history/{scan_id}')
        assert detail_res.status_code == 200
        detail = detail_res.get_json()["scan"]
        assert detail["id"] == scan_id
        # Verify no raw payload or query string leaked
        assert "raw_payload" not in detail

        # Delete
        del_res = client.delete(f'/api/scan-history/{scan_id}')
        assert del_res.status_code == 200
        assert del_res.get_json()["success"] is True

        # Ensure deleted
        get_again = client.get(f'/api/scan-history/{scan_id}')
        assert get_again.status_code == 404

    def test_api_scan_detail_not_found(self, client):
        res = client.get('/api/scan-history/999999')
        assert res.status_code == 404
        assert res.get_json()["success"] is False


class TestPDFReportEndpoints:

    def test_download_historical_pdf_report_valid(self, client):
        res = client.post('/api/analyze-url', json={"url": "https://example-report-test.org"})
        scan_id = res.get_json().get("scan_id")
        assert scan_id is not None

        # Request PDF report
        pdf_res = client.get(f'/api/scan-history/{scan_id}/report')
        assert pdf_res.status_code == 200
        assert pdf_res.mimetype == "application/pdf"
        assert "attachment;" in pdf_res.headers.get("Content-Disposition", "")
        assert pdf_res.data.startswith(b'%PDF-')
        assert len(pdf_res.data) > 1000

    def test_download_historical_pdf_report_not_found(self, client):
        pdf_res = client.get('/api/scan-history/999999/report')
        assert pdf_res.status_code == 404
        assert pdf_res.get_json()["success"] is False

    def test_generate_live_scan_pdf_report(self, client):
        payload = {
            "scan_id": 12,
            "valid": True,
            "target_domain": "chase-alert.xyz",
            "payload_type": "Web Address (URL)",
            "risk_assessment": {
                "score": 75,
                "risk_level": "high",
                "recommendations": {
                    "next_step": "Do not enter passwords."
                }
            },
            "indicators": [
                {
                    "rule_id": "URL_BRAND_IN_SUBDOMAIN",
                    "severity": "high",
                    "message": "Brand impersonation observed.",
                    "evidence": "chase"
                }
            ]
        }

        res = client.post('/api/scan-report/generate', json=payload)
        assert res.status_code == 200
        assert res.mimetype == "application/pdf"
        assert res.data.startswith(b'%PDF-')
        assert len(res.data) > 1000

    def test_generate_live_scan_pdf_invalid_payload(self, client):
        res = client.post('/api/scan-report/generate', data="not json", content_type="text/plain")
        assert res.status_code == 400


class TestAdminDashboardAndEndpoints:

    def test_admin_page_loads(self, client):
        response = client.get('/admin')
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "QShield Admin Dashboard" in html
        assert "metricTotalScans" in html
        assert "recentActivityTbody" in html

    def test_api_admin_summary(self, client):
        res = client.get('/api/admin/summary')
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "metrics" in data
        metrics = data["metrics"]
        assert "total_scans" in metrics
        assert "scans_today" in metrics
        assert "by_payload_type" in metrics
        assert "by_risk_level" in metrics

    def test_api_admin_health(self, client):
        res = client.get('/api/admin/health')
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        health = data["health"]
        assert health["database_connected"] is True
        assert health["application_status"] == "healthy"
        # Secrets should never be leaked
        assert "GOOGLE_SAFE_BROWSING_API_KEY" not in str(health)
        assert "SECRET_KEY" not in str(health)

    def test_admin_auth_enforcement_with_configured_key(self):
        """When ADMIN_API_KEY is configured in the app, verify unauthorized access is blocked."""
        class KeyConfig(TestingConfig):
            ADMIN_API_KEY = "super-secret-admin-token-12345"

        app = create_app(KeyConfig)
        with app.app_context():
            init_db()
        client = app.test_client()

        # Without key -> 401
        unauth_res = client.get('/api/admin/summary')
        assert unauth_res.status_code == 401
        assert unauth_res.get_json()["error_code"] == "UNAUTHORIZED"

        # With wrong key -> 401
        wrong_res = client.get('/api/admin/summary', headers={"X-Admin-Key": "wrong-key"})
        assert wrong_res.status_code == 401

        # With correct key -> 200
        auth_res = client.get('/api/admin/summary', headers={"X-Admin-Key": "super-secret-admin-token-12345"})
        assert auth_res.status_code == 200
        assert auth_res.get_json()["success"] is True

        # Query param auth also supported
        param_res = client.get('/api/admin/summary?api_key=super-secret-admin-token-12345')
        assert param_res.status_code == 200
