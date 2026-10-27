# QShield — Live Camera QR Scanner & Intelligent Scanning Experience

**Project:** QShield — QR Phishing Detection & Awareness System  
**Tagline:** Decode the QR. Detect the Threat.  
**Version:** 2.0 (Prompt 20 Milestone)

---

## 1. Overview & Core Philosophy

The **QShield Live Camera QR Scanner** transforms QR inspection into an interactive, real-time security experience while upholding strict application security and privacy guarantees.

Unlike conventional mobile camera apps that immediately open decoded web links or prompt single-click navigation, QShield implements an **Inert Security Sandbox**:

> **Critical Security Rule:**  
> QShield **NEVER** automatically opens, fetches, executes, or navigates to any scanned QR destination. It safely decodes the matrix in memory, classifies the payload, presents human-readable extracted details, evaluates structural risk indicators, and provides actionable recommendations—empowering the user to make an informed decision before visiting any link.

---

## 2. Three Unified Scanning Modalities

The QShield Scanner workspace (`/scanner`) features three dedicated inspection modes accessible via responsive, keyboard-accessible tabs:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        QShield Scanner Workspace                       │
├───────────────────┬──────────────────────┬─────────────────────────────┤
│ 1. Live Camera    │ 2. Upload QR Image   │ 3. Analyze URL Manually     │
│    (Native/Canvas)│    (File Drag & Drop)│    (Static Heuristics)      │
└───────────────────┴──────────────────────┴─────────────────────────────┘
```

1. **Live Camera Scan (`#tabCamera`):**  
   Point any device camera (rear/environment preferred on mobile) at a physical QR code. Features an animated viewfinder reticle, laser scanning indicator, device switcher, and pause-on-detection controls.
2. **Upload QR Image (`#tabUpload`):**  
   Drag-and-drop or browse local PNG, JPG, JPEG, and WebP files up to 5 MB. Processes image files directly via OpenCV in memory without disk persistence.
3. **Analyze URL Manually (`#tabManual`):**  
   Paste or type an existing HTTP/HTTPS web address to run static structural heuristics, modular intelligence telemetry, and threat feed reputation lookups directly.

---

## 3. Camera Access & Permission Model

### 3.1 Explicit User Initiation
Camera streaming is **never started automatically** on page load or tab click. Video hardware is activated solely after explicit user consent (clicking **Start Camera** or the **Use Camera** button).

### 3.2 Secure Context Requirement
In compliance with W3C Media Capture specifications:
- Camera access requires a secure origin (`HTTPS`) or local development host (`localhost` / `127.0.0.1`).
- If an insecure HTTP context is detected, the UI gracefully disables the camera button and alerts the user to use the file upload or manual URL analysis tab.

### 3.3 Hardware Constraints & Device Selection
- **Facing Mode:** Prefers `{ video: { facingMode: { ideal: "environment" } } }` for mobile devices.
- **Resolution:** Requests ideal `{ width: 1280, height: 720 }` for sharp barcode edge resolution.
- **Multi-Camera Support:** When multiple video input devices are detected (e.g., front, rear, external webcam), QShield populates a device dropdown (`#cameraDeviceSelect`) and enables the **Switch Camera** button.

### 3.4 Hardware Lifecycle & Stream Cleanup
To protect user privacy and prevent battery drain or camera indicator locks:
- Clicking **Stop Camera** calls `stream.getTracks().forEach(t => t.stop())` and clears `video.srcObject`.
- Switching away from the Camera tab immediately stops all tracks.
- Window events (`visibilitychange` when tab is backgrounded, `pagehide`, and `beforeunload`) automatically release hardware camera streams.

---

## 4. Dual QR Detection Pipeline

QShield uses a resilient two-tier detection strategy balancing sub-millisecond client performance with universal cross-browser compatibility:

```
                       [ Camera Video Stream ]
                                  │
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
       [ BarcodeDetector API ]          [ Unsupported / Legacy ]
         Supported in Browser?                  Firefox / Safari < 17
                  │                               │
         ┌────────┴────────┐                      ▼
       YES                 NO           [ Canvas Frame Capture ]
         │                  │             (Every ~650ms, 640px max)
         ▼                  │                     │
[ Zero-latency Client Dec ] │                     ▼
[ ~120ms Throttled Loop   ] │            [ POST /api/decode-qr ]
         │                  │             (OpenCV In-Memory)
         │                  └──────────┐          │
         ▼                             ▼          ▼
   [ QR Detected ] ──────────────► [ Intelligent Routing ]
                                   (Freeze Loop & Classify)
```

### Strategy 1: Client-Side Native `BarcodeDetector` (Preferred)
- Available in modern Chromium (Chrome, Edge, Opera, Samsung Internet) and Android WebView.
- Uses hardware-accelerated computer vision natively in the browser.
- Operates at ~8 FPS (120ms interval) with **zero network payload** and zero server latency.

### Strategy 2: Offscreen Canvas Backend Fallback (Universal)
- Operates automatically in Firefox and legacy browsers where `window.BarcodeDetector` is unavailable.
- Grabs video frames onto a hidden `<canvas>`, downscales to max 640px for rapid transfer, and sends JPEG base64 payloads to `POST /api/decode-qr`.
- Processed by OpenCV `QRCodeDetector` entirely in memory.

---

## 5. Intelligent Scanning Experience & Routing

Once a QR code is detected:

1. **Instant Freeze & Cooldown:**  
   The live detection loop is paused to prevent duplicate rapid-fire alerts. The reticle transitions to green (`.detected`), haptic vibration triggers on mobile devices, and the **Scan Again** button appears.
2. **Duplicate Protection:**  
   A 3000ms cooldown window prevents the same payload from firing repeatedly if the user holds the camera steady over the same code.
3. **Payload Classification:**
   - **Web Address (URL):** Automatically routed to `performUrlAnalysis(targetUrl, 'camera')`. Computes risk scores (0–100), extracts structural features (entropy, punycode, subdomains), displays explainable threat indicators, and offers one-click PDF Security Report downloads.
   - **Wi-Fi Network:** Extracts network SSID, encryption type (WPA/WPA2/WEP/Open), and hidden network status. Masks sensitive pre-shared passwords (`••••••••`) to prevent shoulder surfing.
   - **Payment Intent (UPI):** Parses payee virtual payment address (VPA), merchant name, and transaction reference. Displays clear financial fraud cautions.
   - **Contact Card (vCard):** Safely extracts contact details without modifying the device address book.
   - **Plain Text:** Renders safe text preview without executing script or markup.

---

## 6. Error Handling & Graceful Degradation

| Failure Mode | User-Facing Guidance | System Recovery Action |
|---|---|---|
| **Permission Denied** (`NotAllowedError`) | "Camera permission was denied. Please allow permissions in your address bar or upload an image." | Visual error badge; upload dropzone highlighted. |
| **No Camera Found** (`NotFoundError`) | "No camera device detected on this system. You can upload a QR image or enter a URL manually." | Hides video preview; activates image dropzone. |
| **Camera Busy** (`NotReadableError`) | "Camera is currently in use by another application. Please close the other program." | Provides retry button. |
| **Insecure Context** (Plain HTTP) | "Camera access requires HTTPS or localhost. Please upload an image." | Directs user to file upload mode. |
| **Blurry / Dark Framing** | Reticle instruction: "Point camera at a QR code to decode" | Viewfinder laser animation guides user alignment. |

---

## 7. Bilingual Localization (English & Tamil)

All camera scanner UI elements, error strings, reticle instructions, and status pills are localized across English and Tamil (`locales/en.json` and `locales/ta.json`):

- **English:** "Live Camera Scan", "Start Camera", "Stop Camera", "Scan Again", "Position the QR code inside the frame"
- **Tamil:** "நேரலை கேமரா ஸ்கேன்", "கேமராவைத் தொடங்கு", "கேமராவை நிறுத்து", "மீண்டும் ஸ்கேன் செய்", "QR குறியீட்டை சட்டத்திற்குள் வைக்கவும்"

---

## 8. Verification & Test Suite

The live camera scanner is verified by a dedicated test suite in `tests/unit/test_camera_scanner.py`:
- `test_decode_qr_camera_base64_frame`: Decodes base64 frame payloads.
- `test_decode_qr_camera_data_url_prefix`: Verifies data URI strip handling.
- `test_decode_qr_camera_no_qr_detected`: Returns 422 `NO_QR_DETECTED`.
- `test_decode_qr_camera_invalid_base64`: Returns 400 `INVALID_BASE64`.
- `test_decode_qr_camera_missing_frame_data`: Returns 400 `MISSING_FRAME_DATA`.
- `test_decode_qr_barcode_detector_fastpath_url`: Pre-decoded URL payload classification.
- `test_decode_qr_barcode_detector_fastpath_wifi`: Wi-Fi credential masking verification.
- `test_decode_qr_barcode_detector_fastpath_upi`: UPI financial payment parsing.
- `test_decode_qr_barcode_detector_fastpath_vcard`: vCard contact parsing.
- `test_analyze_url_camera_scan_type`: Verifies `scan_type='camera'` recording.
- `test_scanner_html_contains_camera_components`: Verifies all DOM IDs and controls.
- `test_camera_scan_does_not_execute_or_auto_navigate`: Strict security and SSRF safeguards.
- `test_camera_scanner_localization_keys_exist`: Confirms complete en/ta dictionary synchronization.
