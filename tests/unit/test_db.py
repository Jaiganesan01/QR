"""
Unit tests for QShield SQLite database manager and data privacy safeguards.
"""
import pytest
from app import create_app
from config import TestingConfig
from app.database import (
    get_db,
    init_db,
    record_scan,
    get_scan_history,
    get_scan_by_id,
    delete_scan
)

@pytest.fixture
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db = get_db()
        db.execute("DELETE FROM scan_history;")
        db.commit()
    return app

def test_db_initialization_creates_scan_history_table(app):
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history';")
        row = cursor.fetchone()
        assert row is not None
        assert row["name"] == "scan_history"

def test_record_scan_privacy_preservation(app):
    """
    Ensure record_scan only persists non-sensitive metadata and strips query strings / passwords from domains.
    """
    with app.app_context():
        scan_id = record_scan(
            scan_type="upload",
            payload_type="URL",
            target_domain="https://victim-user:secretpwd@subdomain.secure-login.com:8443/login?token=sensitive_token#header",
            risk_score=78,
            risk_level="High Risk",
            indicator_count=3,
            status="completed"
        )
        assert scan_id is not None
        assert scan_id > 0

        record = get_scan_by_id(scan_id)
        assert record is not None
        # Domain must only be the hostname, NEVER containing passwords, credentials, paths, or query tokens
        assert record["target_domain"] == "subdomain.secure-login.com"
        assert "secretpwd" not in record["target_domain"]
        assert "sensitive_token" not in record["target_domain"]
        assert record["risk_score"] == 78
        assert record["risk_level"] == "High Risk"
        assert record["indicator_count"] == 3
        assert record["status"] == "completed"

def test_get_scan_history_ordering_and_pagination(app):
    with app.app_context():
        id1 = record_scan("manual", "URL", "example1.com", 10, "Low Risk", 0, "completed")
        id2 = record_scan("upload", "URL", "example2.com", 85, "High Risk", 3, "completed")
        id3 = record_scan("manual", "URL", "example3.com", 45, "Medium Risk", 1, "completed")

        history = get_scan_history(limit=2, offset=0)
        assert len(history) == 2
        # Reverse chronological ordering (highest ID / newest first)
        assert history[0]["id"] == id3
        assert history[1]["id"] == id2

        offset_history = get_scan_history(limit=2, offset=2)
        assert len(offset_history) == 1
        assert offset_history[0]["id"] == id1

def test_get_scan_by_id_not_found(app):
    with app.app_context():
        record = get_scan_by_id(999999)
        assert record is None

def test_delete_scan(app):
    with app.app_context():
        scan_id = record_scan("manual", "URL", "delete-test.org", 20, "Low Risk", 0, "completed")
        assert get_scan_by_id(scan_id) is not None

        # Successful deletion
        assert delete_scan(scan_id) is True
        # Verify it no longer exists
        assert get_scan_by_id(scan_id) is None

        # Deleting non-existent scan returns False
        assert delete_scan(scan_id) is False

def test_record_scan_handles_non_url_and_null_scores(app):
    with app.app_context():
        scan_id = record_scan(
            scan_type="upload",
            payload_type="Plain Text",
            target_domain=None,
            risk_score=None,
            risk_level="Inconclusive",
            indicator_count=0,
            status="completed"
        )
        record = get_scan_by_id(scan_id)
        assert record["payload_type"] == "Plain Text"
        assert record["target_domain"] is None
        assert record["risk_score"] is None
        assert record["risk_level"] == "Inconclusive"
