"""
QR Payload Classifier & Intelligent Payload Inspector.
Identifies QR content structure (URL, Wi-Fi, vCard, Email, Phone, SMS, Geo, Calendar, Payment/UPI, Plain Text)
and returns safe, human-readable extracted fields with masked credentials and clear caution advisories.
Strictly offline, parser-driven, and safe against arbitrary code execution.
"""
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote

# Maximum characters displayed for plain text to prevent DoS / UI degradation
MAX_DISPLAY_TEXT_LENGTH = 2000

# URL detection pattern inside plain text
EMBEDDED_URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)


def classify_payload(decoded_text: str) -> Dict[str, Any]:
    """
    Classifies decoded QR content into a structured, safe-to-render inspection representation.
    
    Returns:
    {
        "payload_type": str,               # url, wifi, vcard, email, phone, sms, geo, calendar, payment, plain_text, structured_other, unknown
        "display_name": str,               # Human-readable title
        "summary": str,                    # Brief explanation
        "fields": Dict[str, Any],          # Safe extracted properties (passwords masked!)
        "warnings": List[str],             # Security / verification notices
        "requires_caution": bool,          # True if payload warrants extra scrutiny
        "classification_confidence": str,  # high, medium, low
        "limitations": str,                # Parser scope and boundaries
        "truncated": bool,                 # Whether text was truncated for display
        "safe_display_text": str           # Truncated & safe-for-text-rendering copy
    }
    """
    if not isinstance(decoded_text, str):
        return _build_unknown_response("", "Payload input is not a string.")

    cleaned = decoded_text.strip()
    if not cleaned:
        return _build_unknown_response("", "Payload is empty.")

    # Truncation for safe text display
    truncated = len(cleaned) > MAX_DISPLAY_TEXT_LENGTH
    safe_display = cleaned[:MAX_DISPLAY_TEXT_LENGTH]

    lower = cleaned.lower()

    # 1. Wi-Fi Network Configuration (WIFI:...)
    if lower.startswith("wifi:"):
        return _parse_wifi_payload(cleaned, safe_display, truncated)

    # 2. Contact Card / vCard (BEGIN:VCARD ... END:VCARD or MECARD:...)
    if "begin:vcard" in lower or lower.startswith("mecard:"):
        return _parse_vcard_payload(cleaned, safe_display, truncated)

    # 3. Calendar Event (BEGIN:VEVENT ...)
    if "begin:vevent" in lower or "begin:vcalendar" in lower:
        return _parse_calendar_payload(cleaned, safe_display, truncated)

    # 4. Payment Payload (UPI: upi://pay...)
    if lower.startswith("upi://pay"):
        return _parse_upi_payment_payload(cleaned, safe_display, truncated)

    # 5. Telephone Number (tel:...)
    if lower.startswith("tel:"):
        return _parse_phone_payload(cleaned, safe_display, truncated)

    # 6. Email Address or Composition (mailto:...)
    if lower.startswith("mailto:"):
        return _parse_email_payload(cleaned, safe_display, truncated)

    # 7. SMS Composition (sms: or smsto:...)
    if lower.startswith("sms:") or lower.startswith("smsto:"):
        return _parse_sms_payload(cleaned, safe_display, truncated)

    # 8. Geographic Location (geo:...)
    if lower.startswith("geo:"):
        return _parse_geo_payload(cleaned, safe_display, truncated)

    # 9. HTTP / HTTPS Website URL
    if lower.startswith("http://") or lower.startswith("https://"):
        return _parse_url_payload(cleaned, safe_display, truncated)

    # 10. Check for unsupported URI scheme (e.g., javascript:, data:, file:, intent:, itms:)
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):', cleaned)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme not in ('http', 'https', 'wifi', 'tel', 'mailto', 'sms', 'smsto', 'geo', 'upi'):
            return {
                "payload_type": "structured_other",
                "display_name": f"Custom URI Scheme ({scheme}:)",
                "summary": f"Decoded content uses the '{scheme}:' URI scheme which is not a standard web URL.",
                "fields": {
                    "scheme": scheme,
                    "target": cleaned[:200]
                },
                "warnings": [
                    f"Unsupported protocol scheme '{scheme}'.",
                    "Do not open or execute unexpected URI schemes as they may trigger local application actions."
                ],
                "requires_caution": True,
                "classification_confidence": "medium",
                "limitations": "Non-standard URI schemes are not executed or deeply parsed by QShield.",
                "truncated": truncated,
                "safe_display_text": safe_display
            }

    # 11. Plain Text (or text with embedded URLs)
    return _parse_plain_text_payload(cleaned, safe_display, truncated)


def _build_unknown_response(raw_text: str, reason: str) -> Dict[str, Any]:
    return {
        "payload_type": "unknown",
        "display_name": "Unknown / Inconclusive Format",
        "summary": "QShield could not confidently identify this QR content structure.",
        "fields": {},
        "warnings": [reason],
        "requires_caution": True,
        "classification_confidence": "low",
        "limitations": "Unrecognized format is treated strictly as inert raw text.",
        "truncated": len(raw_text) > MAX_DISPLAY_TEXT_LENGTH,
        "safe_display_text": raw_text[:MAX_DISPLAY_TEXT_LENGTH]
    }


# =============================================================================
# Format Parsers
# =============================================================================

def _parse_url_payload(url_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    try:
        parsed = urlparse(url_str)
        is_https = (parsed.scheme or '').lower() == 'https'
        hostname = (parsed.hostname or '').lower()
    except Exception:
        hostname = ""
        is_https = False

    warnings = []
    if not is_https:
        warnings.append("Link uses unencrypted HTTP protocol.")
    if parsed.username or parsed.password:
        warnings.append("Embedded credentials detected in URL.")

    return {
        "payload_type": "url",
        "display_name": "Web Address (URL)",
        "summary": "Decoded content is a standard web destination (HTTP/HTTPS URL).",
        "fields": {
            "protocol": (parsed.scheme or '').lower(),
            "hostname": hostname,
            "path": parsed.path or '/',
            "has_query": bool(parsed.query),
            "is_https": is_https
        },
        "warnings": warnings,
        "requires_caution": not is_https,
        "classification_confidence": "high",
        "limitations": "Classification confirms URL format; safety assessment is provided by heuristic analysis.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }


def _parse_wifi_payload(wifi_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    """
    Parses standard WIFI:T:WPA;S:MySSID;P:MyPassword;H:false;;
    Never reveals raw password in output or safe_display_text! Masks as bullet characters.
    """
    content = wifi_str[5:] # remove 'WIFI:'
    # Split by semicolon while respecting escaped semicolons
    raw_tokens = re.split(r'(?<!\\);', content)

    fields: Dict[str, Any] = {
        "ssid": None,
        "security_type": "None / Open",
        "password_present": False,
        "masked_password": None,
        "hidden": False
    }

    warnings = []

    for token in raw_tokens:
        token = token.strip()
        if not token:
            continue
        if token.startswith("S:") or token.startswith("s:"):
            fields["ssid"] = token[2:].replace(r'\;', ';').replace(r'\:', ':')
        elif token.startswith("T:") or token.startswith("t:"):
            sec = token[2:].upper()
            fields["security_type"] = sec if sec else "None / Open"
        elif token.startswith("P:") or token.startswith("p:"):
            raw_pwd = token[2:]
            if raw_pwd:
                fields["password_present"] = True
                fields["masked_password"] = "••••••••"
        elif token.startswith("H:") or token.startswith("h:"):
            fields["hidden"] = token[2:].lower() in ("true", "1")

    # Mask any password in safe_display_text to prevent leakage in UI
    masked_display = re.sub(r'([;:]P:)([^;]+)', r'\1••••••••', safe_display, flags=re.IGNORECASE)

    if not fields["ssid"]:
        warnings.append("Could not locate Wi-Fi network name (SSID). Malformed Wi-Fi structure.")

    if fields["password_present"]:
        warnings.append("This QR code contains pre-configured Wi-Fi authentication credentials. Do not share with untrusted parties.")

    return {
        "payload_type": "wifi",
        "display_name": "Wi-Fi Network Configuration",
        "summary": f"Configures connection to Wi-Fi network '{fields.get('ssid') or 'Unnamed'}'.",
        "fields": fields,
        "warnings": warnings,
        "requires_caution": fields["password_present"] or fields["security_type"] in ("NONE", "NOPASS", "None / Open"),
        "classification_confidence": "high" if fields["ssid"] else "medium",
        "limitations": "Parses standard Wi-Fi QR schema. Does not connect to or test the network.",
        "truncated": truncated,
        "safe_display_text": masked_display
    }


def _parse_vcard_payload(vcard_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    """
    Extracts common contact card information safely without executing markup.
    """
    fields: Dict[str, Any] = {
        "name": None,
        "organization": None,
        "phone": None,
        "email": None,
        "website": None
    }

    warnings = [
        "Review contact details before importing. Contact cards may contain unverified phone numbers or URLs."
    ]

    lines = re.split(r'[\r\n]+', vcard_str)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        line_upper = line.upper()

        if line_upper.startswith("FN:") or line_upper.startswith("FN;"):
            fields["name"] = line.split(":", 1)[1].strip()
        elif line_upper.startswith("N:") and not fields["name"]:
            parts = line.split(":", 1)[1].split(";")
            fields["name"] = " ".join([p.strip() for p in reversed(parts) if p.strip()])
        elif line_upper.startswith("ORG:") or line_upper.startswith("ORG;"):
            fields["organization"] = line.split(":", 1)[1].strip()
        elif (line_upper.startswith("TEL:") or line_upper.startswith("TEL;")) and not fields["phone"]:
            fields["phone"] = line.split(":", 1)[1].strip()
        elif (line_upper.startswith("EMAIL:") or line_upper.startswith("EMAIL;")) and not fields["email"]:
            fields["email"] = line.split(":", 1)[1].strip()
        elif (line_upper.startswith("URL:") or line_upper.startswith("URL;")) and not fields["website"]:
            fields["website"] = line.split(":", 1)[1].strip()

    # Also handle MECARD: format
    if not fields["name"] and vcard_str.upper().startswith("MECARD:"):
        mecard_body = vcard_str[7:]
        tokens = mecard_body.split(";")
        for t in tokens:
            t_upper = t.upper()
            if t_upper.startswith("N:"):
                fields["name"] = t[2:].strip()
            elif t_upper.startswith("TEL:"):
                fields["phone"] = t[4:].strip()
            elif t_upper.startswith("EMAIL:"):
                fields["email"] = t[6:].strip()
            elif t_upper.startswith("URL:"):
                fields["website"] = t[4:].strip()

    if fields.get("website"):
        warnings.append("Contact includes a web address. Inspect website link carefully before opening.")

    return {
        "payload_type": "vcard",
        "display_name": "Contact Card (vCard)",
        "summary": f"Contact profile for '{fields.get('name') or 'Unnamed Contact'}'.",
        "fields": fields,
        "warnings": warnings,
        "requires_caution": bool(fields.get("website")),
        "classification_confidence": "high" if fields.get("name") else "medium",
        "limitations": "Standard vCard fields extracted as untrusted text. Contacts are not automatically created.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }


def _parse_calendar_payload(cal_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    fields: Dict[str, Any] = {
        "summary": None,
        "location": None,
        "start_time": None,
        "end_time": None,
        "description": None
    }

    warnings = [
        "Events are displayed for inspection only and are not automatically added to your calendar."
    ]

    lines = re.split(r'[\r\n]+', cal_str)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        line_upper = line.upper()

        if line_upper.startswith("SUMMARY:"):
            fields["summary"] = line[8:].strip()
        elif line_upper.startswith("LOCATION:"):
            fields["location"] = line[9:].strip()
        elif line_upper.startswith("DTSTART:") or line_upper.startswith("DTSTART;"):
            fields["start_time"] = line.split(":", 1)[1].strip()
        elif line_upper.startswith("DTEND:") or line_upper.startswith("DTEND;"):
            fields["end_time"] = line.split(":", 1)[1].strip()
        elif line_upper.startswith("DESCRIPTION:"):
            fields["description"] = line[12:].strip()[:300]

    return {
        "payload_type": "calendar",
        "display_name": "Calendar Event (iCalendar)",
        "summary": f"Event: '{fields.get('summary') or 'Unnamed Event'}'.",
        "fields": fields,
        "warnings": warnings,
        "requires_caution": False,
        "classification_confidence": "high" if fields.get("summary") else "medium",
        "limitations": "Recurrence rules and time zone adjustments are not evaluated.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }


def _parse_upi_payment_payload(upi_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    """
    Parses UPI payment payload upi://pay?pa=...&pn=...&am=...&cu=INR
    Never initiates a payment or confirms merchant identity.
    """
    fields: Dict[str, Any] = {
        "payee_vpa": None,
        "payee_name": None,
        "amount": None,
        "currency": "INR",
        "note": None
    }

    warnings = [
        "Payment Request Caution: Anyone can generate a payment QR code. Always verify the recipient identity and amount in your official banking or UPI app before approving any payment."
    ]

    try:
        parsed = urlparse(upi_str)
        params = parse_qs(parsed.query)

        fields["payee_vpa"] = params.get("pa", [None])[0]
        fields["payee_name"] = params.get("pn", [None])[0]
        fields["amount"] = params.get("am", [None])[0]
        fields["currency"] = params.get("cu", ["INR"])[0]
        fields["note"] = params.get("tn", [None])[0]
    except Exception:
        warnings.append("Could not parse all payment parameters.")

    if not fields["payee_vpa"]:
        warnings.append("Missing Payee Virtual Payment Address (VPA). Malformed payment request.")

    return {
        "payload_type": "payment",
        "display_name": "Payment Request (UPI)",
        "summary": f"Payment intent addressed to {fields.get('payee_vpa') or 'unspecified payee'}.",
        "fields": fields,
        "warnings": warnings,
        "requires_caution": True,
        "classification_confidence": "high" if fields.get("payee_vpa") else "medium",
        "limitations": "QShield displays payment intent details as unverified text. Recipient identity is not validated.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }


def _parse_phone_payload(tel_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    phone_number = tel_str[4:].strip()
    return {
        "payload_type": "phone",
        "display_name": "Telephone Number",
        "summary": f"Telephone dialing link for '{phone_number}'.",
        "fields": {
            "phone_number": phone_number
        },
        "warnings": [
            "QShield will not initiate calls. Verify phone number authenticity before calling."
        ],
        "requires_caution": False,
        "classification_confidence": "high",
        "limitations": "Carrier routing and telephone number ownership are not verified.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }


def _parse_email_payload(mailto_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    recipient = ""
    subject = None
    body = None

    try:
        parsed = urlparse(mailto_str)
        recipient = parsed.path
        params = parse_qs(parsed.query)
        subject = params.get("subject", [None])[0]
        body = params.get("body", [None])[0]
    except Exception:
        recipient = mailto_str[7:]

    return {
        "payload_type": "email",
        "display_name": "Email Composition Link",
        "summary": f"Email composition link addressed to '{recipient}'.",
        "fields": {
            "recipient": recipient,
            "subject": subject,
            "body_snippet": body[:100] if body else None
        },
        "warnings": [
            "Verify recipient address carefully before sending emails or private correspondence."
        ],
        "requires_caution": False,
        "classification_confidence": "high",
        "limitations": "Email addresses are displayed as text; no messages are composed or sent.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }


def _parse_sms_payload(sms_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    number = ""
    body = None

    try:
        if sms_str.lower().startswith("sms:"):
            parsed = urlparse(sms_str)
            number = parsed.path
            params = parse_qs(parsed.query)
            body = params.get("body", [None])[0]
        elif sms_str.lower().startswith("smsto:"):
            parts = sms_str[6:].split(":", 1)
            number = parts[0]
            if len(parts) > 1:
                body = parts[1]
    except Exception:
        number = sms_str

    warnings = [
        "Messages are not automatically sent. Inspect recipient and message text before sending."
    ]

    # Check for embedded URLs in SMS body
    if body and EMBEDDED_URL_PATTERN.search(body):
        warnings.append("SMS body contains an embedded web URL. Be cautious of potential smishing (SMS phishing).")

    return {
        "payload_type": "sms",
        "display_name": "SMS Message Composition",
        "summary": f"SMS message prepared for recipient '{number}'.",
        "fields": {
            "recipient_number": number,
            "message_body": body[:200] if body else None
        },
        "warnings": warnings,
        "requires_caution": bool(body and EMBEDDED_URL_PATTERN.search(body)),
        "classification_confidence": "high",
        "limitations": "No SMS is dispatched. Embedded links are not executed.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }


def _parse_geo_payload(geo_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    coords = geo_str[4:].split("?")[0].split(",")
    latitude = None
    longitude = None
    is_valid = False
    warnings = []

    try:
        if len(coords) >= 2:
            lat = float(coords[0].strip())
            lon = float(coords[1].strip())
            if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
                latitude = lat
                longitude = lon
                is_valid = True
            else:
                warnings.append("Geographic coordinates are out of valid range (-90..90 lat, -180..180 lon).")
    except Exception:
        warnings.append("Malformed geographic coordinates string.")

    return {
        "payload_type": "geo",
        "display_name": "Geographic Coordinates",
        "summary": f"Location: {latitude}, {longitude}" if is_valid else "Geographic coordinates payload",
        "fields": {
            "latitude": latitude,
            "longitude": longitude,
            "valid_coordinates": is_valid
        },
        "warnings": warnings,
        "requires_caution": not is_valid,
        "classification_confidence": "high" if is_valid else "low",
        "limitations": "Coordinates are shown as text; maps are not automatically loaded.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }


def _parse_plain_text_payload(text_str: str, safe_display: str, truncated: bool) -> Dict[str, Any]:
    warnings = []
    has_embedded_url = bool(EMBEDDED_URL_PATTERN.search(text_str))
    if has_embedded_url:
        warnings.append("Plain text contains what appears to be an embedded web link. Do not copy or visit unverified links.")

    return {
        "payload_type": "plain_text",
        "display_name": "Plain Text Content",
        "summary": "Decoded content contains unformatted plain text.",
        "fields": {
            "character_count": len(text_str),
            "contains_embedded_url": has_embedded_url
        },
        "warnings": warnings,
        "requires_caution": has_embedded_url,
        "classification_confidence": "high",
        "limitations": "Plain text is safely escaped; HTML tags or scripts are rendered strictly as text.",
        "truncated": truncated,
        "safe_display_text": safe_display
    }
