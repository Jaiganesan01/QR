"""
Integration tests for QShield Awareness Centre routes and endpoints.
"""
import pytest
from app import create_app
from config import TestingConfig

@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client

def test_awareness_page_render(client):
    response = client.get('/awareness')
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Think Before You Scan." in html
    assert "guideSearchInput" in html
    assert "guidesSection" in html
    assert "scenariosSection" in html
    assert "checklistSection" in html
    assert "btnLangEn" in html
    assert "btnLangTa" in html

def test_locale_api_en(client):
    response = client.get('/api/locale/en')
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["lang"] == "en"
    assert "guides" in data["data"]
    assert "scenarios" in data["data"]
    assert "checklist_items" in data["data"]
    assert len(data["data"]["guides"]) == 8

def test_locale_api_ta(client):
    response = client.get('/api/locale/ta')
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert data["lang"] == "ta"
    assert "சிந்தியுங்கள்" in data["data"]["hero_heading"]
    assert len(data["data"]["guides"]) == 8
    assert len(data["data"]["scenarios"]) == 6

def test_locale_api_invalid_language(client):
    response = client.get('/api/locale/fr')
    assert response.status_code == 404
    data = response.get_json()
    assert data["success"] is False
    assert data["error_code"] == "UNSUPPORTED_LANGUAGE"
