"""
Comprehensive test suite for OpenCV QR code decoding and /api/decode-qr endpoint.
Generates synthetic in-memory QR fixtures for testing (plain text, URLs, HTML text, etc.).
"""
import io
import pytest
import qrcode
from app import create_app
from config import TestingConfig
from app.core.qr_decoder import decode_qr_image_bytes, classify_payload_preliminary

@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client

def create_qr_image_bytes(data: str, format: str = "PNG") -> bytes:
    """Helper to generate real QR code image bytes in memory."""
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format=format)
    return buf.getvalue()

def test_classify_payload_preliminary():
    assert classify_payload_preliminary("https://example.com") == "URL"
    assert classify_payload_preliminary("http://example.com/login") == "URL"
    assert classify_payload_preliminary("WIFI:S:MyNetwork;T:WPA;P:secret;;") == "Wi-Fi Configuration"
    assert classify_payload_preliminary("upi://pay?pa=test@upi&pn=Vendor") == "Payment Intent (UPI)"
    assert classify_payload_preliminary("BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nEND:VCARD") == "Contact Card (vCard)"
    assert classify_payload_preliminary("Just a random plain text note") == "Plain Text"

def test_decode_valid_plain_text():
    text = "Hello QShield Security Tester"
    img_bytes = create_qr_image_bytes(text)
    res = decode_qr_image_bytes(img_bytes)
    assert res["success"] is True
    assert res["decoded_content"] == text
    assert res["payload_type"] == "Plain Text"
    assert res["truncated"] is False

def test_decode_valid_http_url():
    url = "https://example.org/path?auth=demo"
    img_bytes = create_qr_image_bytes(url)
    res = decode_qr_image_bytes(img_bytes)
    assert res["success"] is True
    assert res["decoded_content"] == url
    assert res["payload_type"] == "URL"

def test_decode_image_with_no_qr():
    # Plain 100x100 white PNG image without any QR code
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (100, 100), color="white").save(buf, format="PNG")
    res = decode_qr_image_bytes(buf.getvalue())
    assert res["success"] is False
    assert res["error_code"] == "NO_QR_DETECTED"
    assert "Unable to decode" in res["message"]

def test_decode_corrupted_image_bytes():
    corrupted_bytes = b"NOT_AN_IMAGE_DATA_123456789"
    res = decode_qr_image_bytes(corrupted_bytes)
    assert res["success"] is False
    assert res["error_code"] == "INVALID_IMAGE"

def test_api_decode_qr_success_plain_text(client):
    img_bytes = create_qr_image_bytes("Sample Secret Text 42")
    data = {'qr_file': (io.BytesIO(img_bytes), 'test_plain.png')}
    response = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["decoded_content"] == "Sample Secret Text 42"
    assert json_data["payload_type"] == "Plain Text"

def test_api_decode_qr_success_url(client):
    target_url = "https://safe-portal.example.edu/verify"
    img_bytes = create_qr_image_bytes(target_url)
    data = {'qr_file': (io.BytesIO(img_bytes), 'test_url.png')}
    response = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["decoded_content"] == target_url
    assert json_data["payload_type"] == "URL"

def test_api_decode_qr_html_payload_treated_as_text(client):
    # Tests that payloads containing HTML/script tags are returned as pure string text
    html_text = "<script>alert('xss')</script><b>Dangerous</b>"
    img_bytes = create_qr_image_bytes(html_text)
    data = {'qr_file': (io.BytesIO(img_bytes), 'xss_qr.png')}
    response = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["success"] is True
    assert json_data["decoded_content"] == html_text

def test_api_decode_qr_missing_file(client):
    response = client.post('/api/decode-qr', data={}, content_type='multipart/form-data')
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["success"] is False
    assert json_data["error_code"] == "MISSING_FILE"

def test_api_decode_qr_empty_file(client):
    data = {'qr_file': (io.BytesIO(b''), 'empty.png')}
    response = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["success"] is False
    assert json_data["error_code"] in ("NO_FILE_SELECTED", "EMPTY_FILE")

def test_api_decode_qr_exceeds_5mb(client):
    # 5MB + 1KB buffer
    big_data = b'A' * (5 * 1024 * 1024 + 1024)
    data = {'qr_file': (io.BytesIO(big_data), 'oversized.png')}
    response = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert response.status_code == 413
    json_data = response.get_json()
    assert json_data["success"] is False
    assert json_data["error_code"] == "FILE_TOO_LARGE"

def test_api_decode_qr_unsupported_file_type(client):
    data = {'qr_file': (io.BytesIO(b'%PDF-1.4 header text not image'), 'doc.pdf')}
    response = client.post('/api/decode-qr', data=data, content_type='multipart/form-data')
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data["success"] is False
    assert json_data["error_code"] in ("UNSUPPORTED_FORMAT", "INVALID_IMAGE")
