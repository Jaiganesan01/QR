"""
Integration tests for the scanner page, upload handling, and manual URL preparation
"""
import io
import pytest
from app import create_app
from config import TestingConfig

@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client

def test_scanner_page_get(client):
    res = client.get('/scanner')
    assert res.status_code == 200
    assert b'Inspect a QR Code' in res.data
    assert b'Already have a URL?' in res.data
    assert b'Decode QR Code' in res.data
    assert b'Use Camera' in res.data

def test_manual_url_valid_submission(client):
    res = client.post('/scanner', data={'manual_url': 'https://secure-banking.example.com'}, follow_redirects=True)
    assert res.status_code == 200
    assert b'URL analysis complete' in res.data
    assert b'https://secure-banking.example.com' in res.data

def test_manual_url_unsafe_scheme_rejected(client):
    res = client.post('/scanner', data={'manual_url': 'javascript:alert(1)'}, follow_redirects=True)
    assert res.status_code == 200
    assert b'Unsupported or unsafe protocol' in res.data

def test_file_upload_valid_image_staged(client):
    import qrcode
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data("https://example.com/test-qr")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    
    res = client.post('/scanner', data={'qr_file': (io.BytesIO(buf.getvalue()), 'test_qr.png')}, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b'QR code successfully decoded' in res.data
    assert b'https://example.com/test-qr' in res.data

def test_file_upload_unsupported_format_rejected(client):
    fake_exe = (io.BytesIO(b'MZ\x90\x00\x03\x00\x00\x00'), 'malicious.exe')
    res = client.post('/scanner', data={'qr_file': fake_exe}, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b'Unsupported format' in res.data
