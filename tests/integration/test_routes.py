"""
Integration tests for frontend routes, homepage sections, and static asset serving
"""
import pytest
from app import create_app
from config import TestingConfig

@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client

def test_homepage_loads(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'QShield' in response.data
    assert b'Scan Smart' in response.data
    assert b'Discover what hides behind a QR code' in response.data

def test_homepage_sections_exist(client):
    response = client.get('/')
    assert response.status_code == 200
    # Hero Privacy Note
    assert b'Your safety starts with understanding what you scan.' in response.data
    # Trust & Transparency Bar
    assert b'Explainable Risk Analysis' in response.data
    assert b'Payload Inspection' in response.data
    assert b'Security Awareness' in response.data
    # How it works steps
    assert b'1. Upload or Scan' in response.data
    assert b'2. Analyze the Content' in response.data
    assert b'3. Understand the Result' in response.data
    # Planned capability tags
    assert b'Planned feature' in response.data
    # Demo preview banner
    assert b'Illustrative demo \xe2\x80\x94 not a live security scan' in response.data or b'Illustrative demo' in response.data
    # Awareness section
    assert b'Think Before You Scan' in response.data
    assert b'Preview the decoded destination' in response.data
    # Privacy & Responsible Security
    assert b'Responsible Security &amp; Privacy' in response.data or b'Responsible Security' in response.data
    assert b'HTTPS alone does not prove' in response.data

def test_all_pages_status(client):
    for route in ['/', '/scanner', '/how-it-works', '/awareness', '/about', '/privacy', '/health']:
        response = client.get(route)
        assert response.status_code == 200

def test_security_headers(client):
    response = client.get('/')
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'

def test_static_assets(client):
    for asset in [
        '/static/css/variables.css',
        '/static/css/main.css',
        '/static/js/main.js',
        '/static/js/scanner.js',
        '/static/images/logo-shield.svg'
    ]:
        res = client.get(asset)
        assert res.status_code == 200
