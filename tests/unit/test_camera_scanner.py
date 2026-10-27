"""
Unit and integration tests for Prompt 20: Live Camera QR Scanner & Intelligent Scanning Experience.
Validates client-side BarcodeDetector fast-path, base64 frame fallback, scan_type='camera' handling,
viewfinder UI elements, and strict security guarantees (no automatic execution/navigation).
"""
import base64
import io
import pytest
import qrcode
from PIL import Image

from app import create_app
from config import TestingConfig


@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client


def make_qr_base64(data: str, format: str = "PNG", prefix: bool = False) -> str:
    """Helper to generate a base64 encoded QR image for camera frame simulation."""
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format=format)
    encoded = base64.b64encode(buf.getvalue()).decode('utf-8')
    if prefix:
        return f"data:image/{format.lower()};base64,{encoded}"
    return encoded


def test_decode_qr_camera_base64_frame(client):
    """Test /api/decode-qr accepts a base64 camera frame and decodes correctly."""
    target_payload = "https://safe-portal.example.org/account"
    b64_frame = make_qr_base64(target_payload)

    resp = client.post(
        '/api/decode-qr',
        json={'frame': b64_frame, 'scan_type': 'camera'}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['decoded_content'] == target_payload
    assert data['payload_type'] == 'URL'


def test_decode_qr_camera_data_url_prefix(client):
    """Test /api/decode-qr handles data:image/...;base64, prefixes smoothly."""
    target_payload = "WIFI:S:GuestNetwork;T:WPA;P:SuperSecretPass;;"
    b64_frame = make_qr_base64(target_payload, format="JPEG", prefix=True)

    resp = client.post(
        '/api/decode-qr',
        json={'frame': b64_frame, 'scan_type': 'camera'}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert "WIFI:S:GuestNetwork" in data['decoded_content']
    assert 'Wi-Fi' in data['payload_type']
    assert 'classification' in data
    assert data['classification']['fields']['ssid'] == 'GuestNetwork'
    # Sensitive password should be masked
    assert data['classification']['fields']['password_present'] is True
    assert data['classification']['fields']['masked_password'] == '••••••••'


def test_decode_qr_camera_no_qr_detected(client):
    """Test camera frame with blank/no QR code returns 422 with NO_QR_DETECTED."""
    blank = Image.new("RGB", (200, 200), color="white")
    buf = io.BytesIO()
    blank.save(buf, format="PNG")
    b64_blank = base64.b64encode(buf.getvalue()).decode('utf-8')

    resp = client.post(
        '/api/decode-qr',
        json={'frame': b64_blank, 'scan_type': 'camera'}
    )
    assert resp.status_code == 422
    data = resp.get_json()
    assert data['success'] is False
    assert data['error_code'] == 'NO_QR_DETECTED'


def test_decode_qr_camera_invalid_base64(client):
    """Test malformed base64 frame string returns 400 INVALID_BASE64."""
    resp = client.post(
        '/api/decode-qr',
        json={'frame': '!!!not_valid_base64@@@', 'scan_type': 'camera'}
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
    assert data['error_code'] == 'INVALID_BASE64'


def test_decode_qr_camera_missing_frame_data(client):
    """Test JSON request without frame or content returns 400 MISSING_FRAME_DATA."""
    resp = client.post(
        '/api/decode-qr',
        json={'scan_type': 'camera'}
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
    assert data['error_code'] == 'MISSING_FRAME_DATA'


def test_decode_qr_barcode_detector_fastpath_url(client):
    """Test client-side BarcodeDetector pre-decoded URL payload returns structured classification."""
    resp = client.post(
        '/api/decode-qr',
        json={'content': 'https://bank-secure-verification.xyz/login', 'scan_type': 'camera'}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['decoded_content'] == 'https://bank-secure-verification.xyz/login'
    assert data['payload_type'] == 'URL'
    assert 'classification' in data


def test_decode_qr_barcode_detector_fastpath_wifi(client):
    """Test client-side BarcodeDetector non-URL payload returns masked fields and scan_id."""
    resp = client.post(
        '/api/decode-qr',
        json={'content': 'WIFI:S:AirportFreeWiFi;T:nopass;;', 'scan_type': 'camera'}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'Wi-Fi' in data['payload_type']
    assert data['classification']['fields']['ssid'] == 'AirportFreeWiFi'
    assert data['scan_id'] is not None


def test_analyze_url_camera_scan_type(client):
    """Test /api/analyze-url accepts scan_type='camera' and runs detection engine safely."""
    resp = client.post(
        '/api/analyze-url',
        json={
            'url': 'https://suspicious-account-update.net/verify',
            'scan_type': 'camera'
        }
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['valid'] is True
    assert 'risk_assessment' in data
    assert 'score' in data['risk_assessment']
    assert 'risk_level' in data['risk_assessment']
    assert 'detection_engine' in data
    assert 'indicators' in data
    # Confirm scan was recorded
    assert data.get('scan_id') is not None


def test_scanner_html_contains_camera_components(client):
    """Test that /scanner renders all Live Camera UI components and controls."""
    resp = client.get('/scanner')
    assert resp.status_code == 200
    html = resp.data.decode('utf-8')

    # Viewport, tabs, and controls
    assert 'id="tabCamera"' in html
    assert 'Live Camera Scan' in html
    assert 'id="panelCamera"' in html
    assert 'id="cameraVideo"' in html
    assert 'id="cameraReticle"' in html
    assert 'id="cameraStatusBadge"' in html
    assert 'id="btnStartCamera"' in html
    assert 'id="btnStopCamera"' in html
    assert 'id="btnCameraScanAgain"' in html
    assert 'id="cameraDeviceSelect"' in html
    assert 'id="btnSwitchCamera"' in html

    # Privacy notice
    assert 'Privacy Protection:' in html
    assert 'Camera scanning runs strictly within your browser' in html
    assert 'Scanned URLs are never opened automatically' in html


def test_camera_scan_does_not_execute_or_auto_navigate(client):
    """Security verification: camera decoding is strictly passive and in-memory."""
    # Ensure analyzing a dangerous/malicious URL via camera workflow never throws SSRF exceptions
    # or executes shell commands
    resp = client.post(
        '/api/analyze-url',
        json={
            'url': 'http://169.254.169.254/latest/meta-data/',
            'scan_type': 'camera'
        }
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['valid'] is True
    assert data['risk_assessment']['risk_level'].lower() in ('high', 'medium', 'high risk', 'medium risk')
    # Cloud metadata risk indicator flagged
    indicator_ids = [ind.get('id') for ind in data.get('indicators', [])]
    assert any('METADATA' in (iid or '').upper() or 'IP' in (iid or '').upper() for iid in indicator_ids)


def test_decode_qr_barcode_detector_fastpath_upi(client):
    """Test client-side BarcodeDetector UPI payment payload classification."""
    resp = client.post(
        '/api/decode-qr',
        json={'content': 'upi://pay?pa=merchant@upi&pn=Store&am=150.00&cu=INR', 'scan_type': 'camera'}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'Payment' in data['payload_type'] or 'UPI' in data['payload_type']
    assert data['classification']['fields']['payee_vpa'] == 'merchant@upi'


def test_decode_qr_barcode_detector_fastpath_vcard(client):
    """Test client-side BarcodeDetector vCard payload classification."""
    vcard_raw = "BEGIN:VCARD\nVERSION:3.0\nFN:Alice Smith\nTEL:+1234567890\nEND:VCARD"
    resp = client.post(
        '/api/decode-qr',
        json={'content': vcard_raw, 'scan_type': 'camera'}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert 'Contact' in data['payload_type'] or 'vCard' in data['payload_type']
    assert data['classification']['fields']['name'] == 'Alice Smith'


def test_camera_scanner_localization_keys_exist():
    """Verify both en.json and ta.json have camera_scanner localization sections."""
    import json
    with open('locales/en.json', 'r', encoding='utf-8') as f:
        en = json.load(f)
    with open('locales/ta.json', 'r', encoding='utf-8') as f:
        ta = json.load(f)

    assert 'camera_scanner' in en
    assert 'camera_scanner' in ta
    assert en['camera_scanner']['tab_camera'] == 'Live Camera Scan'
    assert en['camera_scanner']['btn_start_camera'] == 'Start Camera'
    assert en['camera_scanner']['btn_stop_camera'] == 'Stop Camera'
    assert ta['camera_scanner']['tab_camera'] is not None
    assert ta['camera_scanner']['btn_start_camera'] is not None
