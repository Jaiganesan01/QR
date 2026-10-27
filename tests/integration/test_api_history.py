"""
Integration tests for QShield API scan history endpoints and privacy compliance.
"""
import pytest
from app import create_app
from config import TestingConfig

@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.app_context():
        from app.database import get_db
        db = get_db()
        db.execute("DELETE FROM scan_history;")
        db.commit()
    with app.test_client() as client:
        yield client

def test_api_analyze_url_creates_scan_record_and_returns_id(client):
    """
    Submitting a URL to /api/analyze-url should persist sanitized metadata and return scan_id.
    """
    res = client.post(
        '/api/analyze-url',
        json={"url": "https://secure-login.chase.com.auth-update.xyz/verify?token=secret123", "scan_type": "manual"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["valid"] is True
    assert "scan_id" in data
    scan_id = data["scan_id"]

    # Now verify via /api/scan-history/<id>
    history_res = client.get(f'/api/scan-history/{scan_id}')
    assert history_res.status_code == 200
    history_data = history_res.get_json()
    assert history_data["success"] is True
    scan = history_data["scan"]

    # Verify PRIVACY: domain only, no path, no sensitive token, no query string
    assert scan["target_domain"] == "secure-login.chase.com.auth-update.xyz"
    assert "secret123" not in str(scan)
    assert "token=" not in str(scan)
    assert scan["scan_type"] == "manual"
    assert scan["payload_type"] == "URL"
    assert scan["risk_level"].lower() in ("low", "medium", "high", "inconclusive")

def test_api_scan_history_list(client):
    # Perform two analyses
    client.post('/api/analyze-url', json={"url": "https://example1.com"})
    client.post('/api/analyze-url', json={"url": "https://example2.com"})

    res = client.get('/api/scan-history?limit=10')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["count"] >= 2
    assert isinstance(data["history"], list)
    for record in data["history"]:
        assert "target_domain" in record
        assert "risk_score" in record
        assert "risk_level" in record
        assert "created_at" in record

def test_api_scan_history_detail_not_found(client):
    res = client.get('/api/scan-history/99999')
    assert res.status_code == 404
    data = res.get_json()
    assert data["success"] is False
    assert data["error_code"] == "NOT_FOUND"

def test_api_scan_history_delete_flow(client):
    res = client.post('/api/analyze-url', json={"url": "https://to-be-deleted.com"})
    assert res.status_code == 200
    scan_id = res.get_json()["scan_id"]

    # Delete record
    del_res = client.delete(f'/api/scan-history/{scan_id}')
    assert del_res.status_code == 200
    assert del_res.get_json()["success"] is True

    # Check detail returns 404 now
    detail_res = client.get(f'/api/scan-history/{scan_id}')
    assert detail_res.status_code == 404

def test_api_scan_history_delete_not_found(client):
    res = client.delete('/api/scan-history/999999')
    assert res.status_code == 404
    assert res.get_json()["error_code"] == "NOT_FOUND"
