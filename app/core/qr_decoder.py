"""
QR Code Image Decoding Module for QShield.
Decodes QR codes from raw in-memory image bytes using OpenCV (cv2.QRCodeDetector).
Does not execute, follow, or fetch decoded content.
"""
import io
import re
from typing import Dict, Any, Optional
import cv2
import numpy as np
from PIL import Image

# Maximum allowed decoded string length to prevent memory abuse / denial of service
MAX_DECODED_LENGTH = 4096

# Image dimension and decompression bomb bounds
MAX_IMAGE_WIDTH = 4096
MAX_IMAGE_HEIGHT = 4096
MAX_IMAGE_PIXELS = 16_000_000
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

def classify_payload_preliminary(text: str) -> str:
    """
    Performs preliminary format identification of decoded text.
    NOTE: This is NOT a security verdict; it only categorizes schema format.
    """
    stripped = text.strip()
    lower = stripped.lower()
    
    if lower.startswith(('http://', 'https://')):
        return "URL"
    elif lower.startswith('wifi:'):
        return "Wi-Fi Configuration"
    elif lower.startswith('upi://') or 'pay?' in lower:
        return "Payment Intent (UPI)"
    elif lower.startswith(('begin:vcard', 'mecard:')):
        return "Contact Card (vCard)"
    elif lower.startswith('tel:'):
        return "Telephone Number"
    elif lower.startswith('mailto:'):
        return "Email Address"
    elif lower.startswith('smsto:') or lower.startswith('sms:'):
        return "SMS Message"
    elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', stripped):
        # Likely a domain/URL missing protocol
        return "URL (No Scheme)"
    else:
        return "Plain Text"

def decode_qr_image_bytes(image_bytes: bytes) -> Dict[str, Any]:
    """
    Safely validates image bytes in memory and extracts QR code content using OpenCV.
    
    Returns structured dictionary:
    {
        "success": bool,
        "decoded_content": Optional[str],
        "payload_type": Optional[str],
        "truncated": bool,
        "error_code": Optional[str],
        "message": str
    }
    """
    if not image_bytes or len(image_bytes) == 0:
        return {
            "success": False,
            "decoded_content": None,
            "payload_type": None,
            "truncated": False,
            "error_code": "EMPTY_INPUT",
            "message": "No image data was provided. Please upload a valid image file."
        }

    # 1. Content validation using Pillow (verifies real image headers/format, not just extension)
    try:
        with Image.open(io.BytesIO(image_bytes)) as pil_img:
            img_format = (pil_img.format or "").upper()
            if img_format not in ("PNG", "JPEG", "JPG", "WEBP", "BMP"):
                return {
                    "success": False,
                    "decoded_content": None,
                    "payload_type": None,
                    "truncated": False,
                    "error_code": "UNSUPPORTED_FORMAT",
                    "message": f"Unsupported image format ({img_format or 'Unknown'}). Supported: PNG, JPG, JPEG, WebP."
                }

            # Check dimensions to prevent decompression bombs and memory exhaustion
            width, height = pil_img.size
            if width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT or (width * height) > MAX_IMAGE_PIXELS:
                return {
                    "success": False,
                    "decoded_content": None,
                    "payload_type": None,
                    "truncated": False,
                    "error_code": "IMAGE_TOO_LARGE",
                    "message": f"Image dimensions ({width}x{height}) exceed maximum allowed dimensions of {MAX_IMAGE_WIDTH}x{MAX_IMAGE_HEIGHT}."
                }

            # Verify file integrity
            pil_img.verify()
    except Image.DecompressionBombError:
        return {
            "success": False,
            "decoded_content": None,
            "payload_type": None,
            "truncated": False,
            "error_code": "DECOMPRESSION_BOMB_DETECTED",
            "message": "Image dimensions trigger decompression bomb defense. Upload rejected."
        }
    except Exception:
        return {
            "success": False,
            "decoded_content": None,
            "payload_type": None,
            "truncated": False,
            "error_code": "INVALID_IMAGE",
            "message": "The uploaded file is corrupted or not a valid image file."
        }

    # 2. Decode bytes into OpenCV image matrix using in-memory byte buffer
    try:
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is None:
            return {
                "success": False,
                "decoded_content": None,
                "payload_type": None,
                "truncated": False,
                "error_code": "IMAGE_DECODE_FAILED",
                "message": "Could not parse image structure into pixels. Ensure the file is not damaged."
            }
    except Exception:
        return {
            "success": False,
            "decoded_content": None,
            "payload_type": None,
            "truncated": False,
            "error_code": "IMAGE_DECODE_FAILED",
            "message": "An error occurred while reading the image pixels."
        }

    # 3. Detect and decode QR code using cv2.QRCodeDetector()
    try:
        detector = cv2.QRCodeDetector()
        
        # Primary pass on standard image
        decoded_text, points, _ = detector.detectAndDecode(img)
        
        # If not detected, try enhanced grayscale pass (improves contrast for low-contrast/dark mode QRs)
        if not decoded_text:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            decoded_text, points, _ = detector.detectAndDecode(gray)

        # If still not detected, try adaptive thresholding
        if not decoded_text:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            thresh = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 0
            )
            decoded_text, points, _ = detector.detectAndDecode(thresh)

        if not decoded_text:
            return {
                "success": False,
                "decoded_content": None,
                "payload_type": None,
                "truncated": False,
                "error_code": "NO_QR_DETECTED",
                "message": "Unable to decode this QR code. Try a clearer, well-lit image with the entire QR code visible."
            }

        # Check maximum length boundary
        truncated = False
        final_content = decoded_text
        if len(decoded_text) > MAX_DECODED_LENGTH:
            final_content = decoded_text[:MAX_DECODED_LENGTH]
            truncated = True

        payload_type = classify_payload_preliminary(final_content)

        # Extended classification via payload_classifier module
        from app.core.payload_classifier import classify_payload
        classification_result = classify_payload(final_content)

        return {
            "success": True,
            "decoded_content": final_content,
            "payload_type": payload_type,
            "classification": classification_result,
            "truncated": truncated,
            "error_code": None,
            "message": "QR code successfully decoded." if not truncated else "QR code decoded (content truncated to maximum safe display length)."
        }

    except Exception:
        return {
            "success": False,
            "decoded_content": None,
            "payload_type": None,
            "truncated": False,
            "error_code": "DETECTION_ERROR",
            "message": "An unexpected error occurred during QR code decoding."
        }
