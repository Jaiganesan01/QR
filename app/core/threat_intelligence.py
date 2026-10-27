"""
Threat Intelligence Provider Architecture and Safe Browsing Client.
Provides an extensible adapter interface for external threat reputation lookups,
strict privacy scrubbing, deterministic normalized responses, and safe timeout handling.
"""
from abc import ABC, abstractmethod
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# Sensitive query parameter keys that trigger privacy skip
SENSITIVE_PARAM_NAMES = {
    'token', 'access_token', 'id_token', 'refresh_token', 'auth', 'key', 'apikey', 'api_key',
    'secret', 'password', 'pass', 'pwd', 'session', 'sessionid', 'session_id', 'sid',
    'bearer', 'jwt', 'code', 'otp', 'pin', 'ssn', 'cvv', 'card', 'account', 'credit'
}

# Regex to detect token-like strings in path or query (long hexadecimal, base64-like strings)
TOKEN_LIKE_PATTERN = re.compile(r'(?:[?&][^=]+=)?([A-Za-z0-9-_]{32,})')

PROVIDER_LIMITATIONS_NOTICE = (
    "Reputation feeds reflect previously observed or reported threats. "
    "A clean status indicates that no matching malicious signature is currently listed, "
    "but cannot establish that a newly created or targeted destination is safe."
)


def is_sensitive_url(url_str: str) -> bool:
    """
    Check if a URL contains credentials or likely sensitive tokens/parameters in path or query.
    Returns True if URL contains private data that must not be sent to external providers.
    """
    if not isinstance(url_str, str):
        return True

    try:
        parsed = urlparse(url_str)
    except Exception:
        return True

    # 1. Check for embedded userinfo (credentials)
    if parsed.username or parsed.password or '@' in (parsed.netloc or ''):
        return True

    # 2. Check query parameters for sensitive names
    if parsed.query:
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        for key in query_dict:
            clean_key = key.lower().strip()
            if clean_key in SENSITIVE_PARAM_NAMES:
                return True
            for part in clean_key.split('_'):
                if part in SENSITIVE_PARAM_NAMES:
                    return True

    # 3. Check for high-entropy / JWT / token-like string segments in path
    if parsed.path:
        segments = parsed.path.strip('/').split('/')
        for seg in segments:
            # Segment looks like a JWT or large session ID / UUID / token
            if len(seg) >= 32 and re.match(r'^[A-Za-z0-9_\-\.]+$', seg):
                return True

    return False


class ThreatIntelligenceProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the threat intelligence provider."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if required API credentials and settings are configured."""
        pass

    @abstractmethod
    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation with provider.
        Returns a normalized result dictionary.
        """
        pass


class GoogleSafeBrowsingProvider(ThreatIntelligenceProvider):
    """
    Google Safe Browsing API v4 implementation.
    Endpoint: https://safebrowsing.googleapis.com/v4/threatMatches:find
    """

    API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key: Optional[str] = None, timeout_seconds: float = 4.0):
        self._api_key = (api_key or "").strip()
        self.timeout_seconds = timeout_seconds

    @property
    def provider_name(self) -> str:
        return "Google Safe Browsing"

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def check_url(self, url: str) -> Dict[str, Any]:
        if not self.is_configured():
            return {
                "provider": self.provider_name,
                "status": "not_configured",
                "reputation": "unknown",
                "threat_categories": [],
                "summary": "External threat intelligence provider is not configured. Server-side API key is required.",
                "checked_at": None,
                "limitations": PROVIDER_LIMITATIONS_NOTICE
            }

        endpoint = f"{self.API_ENDPOINT}?key={self._api_key}"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "QShield-QR-Phishing-Detection/1.0"
        }
        payload = {
            "client": {
                "clientId": "qshield-qr-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            req_data = json.dumps(payload).encode('utf-8')
            request = urllib.request.Request(endpoint, data=req_data, headers=headers, method="POST")

            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status_code = response.getcode()
                resp_bytes = response.read(65536)  # Bound response to 64KB max
                resp_data = json.loads(resp_bytes.decode('utf-8'))

                now_utc = datetime.now(timezone.utc).isoformat()
                matches = resp_data.get("matches", [])

                if matches:
                    categories = sorted(list({m.get("threatType", "UNKNOWN") for m in matches}))
                    category_labels = ", ".join(categories)
                    return {
                        "provider": self.provider_name,
                        "status": "checked",
                        "reputation": "malicious",
                        "threat_categories": categories,
                        "summary": f"Known threat flagged by Google Safe Browsing: {category_labels}.",
                        "checked_at": now_utc,
                        "limitations": PROVIDER_LIMITATIONS_NOTICE
                    }
                else:
                    return {
                        "provider": self.provider_name,
                        "status": "checked",
                        "reputation": "no_known_threat_detected",
                        "threat_categories": [],
                        "summary": "No known threat detected by this provider. (Does not guarantee the URL is safe).",
                        "checked_at": now_utc,
                        "limitations": PROVIDER_LIMITATIONS_NOTICE
                    }

        except urllib.error.HTTPError as http_err:
            code = http_err.code
            logger.warning("Threat intelligence HTTP error code %s from provider", code)
            now_utc = datetime.now(timezone.utc).isoformat()

            if code in (401, 403):
                return {
                    "provider": self.provider_name,
                    "status": "provider_error",
                    "reputation": "unknown",
                    "threat_categories": [],
                    "summary": "Threat intelligence authentication failed. Provider API credentials may be invalid or restricted.",
                    "checked_at": now_utc,
                    "limitations": PROVIDER_LIMITATIONS_NOTICE
                }
            elif code == 429:
                return {
                    "provider": self.provider_name,
                    "status": "rate_limited",
                    "reputation": "unknown",
                    "threat_categories": [],
                    "summary": "Threat intelligence lookup rate limit exceeded. Please try again later.",
                    "checked_at": now_utc,
                    "limitations": PROVIDER_LIMITATIONS_NOTICE
                }
            else:
                return {
                    "provider": self.provider_name,
                    "status": "provider_error",
                    "reputation": "unknown",
                    "threat_categories": [],
                    "summary": f"External reputation service returned HTTP status {code}.",
                    "checked_at": now_utc,
                    "limitations": PROVIDER_LIMITATIONS_NOTICE
                }

        except (urllib.error.URLError, TimeoutError) as net_err:
            is_timeout = isinstance(net_err, TimeoutError) or "timed out" in str(net_err).lower()
            status_val = "timeout" if is_timeout else "provider_error"
            summary_val = (
                "Threat intelligence lookup timed out. Reputation data could not be retrieved."
                if is_timeout
                else "Unable to reach threat intelligence provider network."
            )
            return {
                "provider": self.provider_name,
                "status": status_val,
                "reputation": "unknown",
                "threat_categories": [],
                "summary": summary_val,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "limitations": PROVIDER_LIMITATIONS_NOTICE
            }

        except Exception as ex:
            logger.error("Unexpected threat intelligence error: %s", type(ex).__name__)
            return {
                "provider": self.provider_name,
                "status": "provider_error",
                "reputation": "unknown",
                "threat_categories": [],
                "summary": "An unexpected error occurred while processing threat reputation data.",
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "limitations": PROVIDER_LIMITATIONS_NOTICE
            }


def evaluate_threat_intelligence(
    url: str,
    user_consent: bool,
    provider: Optional[ThreatIntelligenceProvider] = None,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main evaluation pipeline for external threat reputation.
    Enforces user consent, scheme validation, URL structure, and privacy checks.
    """
    # 1. Check user consent
    if not user_consent:
        return {
            "provider": "Threat Intelligence",
            "status": "skipped_no_consent",
            "reputation": "unknown",
            "threat_categories": [],
            "summary": "External threat reputation lookup requires explicit user consent.",
            "checked_at": None,
            "limitations": PROVIDER_LIMITATIONS_NOTICE
        }

    # 2. Check URL validity and scheme
    if not isinstance(url, str) or not url.strip():
        return {
            "provider": "Threat Intelligence",
            "status": "invalid_url",
            "reputation": "unknown",
            "threat_categories": [],
            "summary": "A valid HTTP or HTTPS URL is required for threat intelligence lookup.",
            "checked_at": None,
            "limitations": PROVIDER_LIMITATIONS_NOTICE
        }

    cleaned = url.strip()
    try:
        parsed = urlparse(cleaned)
        scheme = (parsed.scheme or '').lower()
        if scheme not in ('http', 'https') or not parsed.hostname:
            return {
                "provider": "Threat Intelligence",
                "status": "invalid_url",
                "reputation": "unknown",
                "threat_categories": [],
                "summary": f"Scheme '{scheme}' is unsupported. Only HTTP and HTTPS URLs can be checked.",
                "checked_at": None,
                "limitations": PROVIDER_LIMITATIONS_NOTICE
            }
    except Exception:
        return {
            "provider": "Threat Intelligence",
            "status": "invalid_url",
            "reputation": "unknown",
            "threat_categories": [],
            "summary": "Malformed URL format.",
            "checked_at": None,
            "limitations": PROVIDER_LIMITATIONS_NOTICE
        }

    # 3. Privacy-by-design check
    if is_sensitive_url(cleaned):
        return {
            "provider": "Threat Intelligence",
            "status": "skipped_sensitive_url",
            "reputation": "unknown",
            "threat_categories": [],
            "summary": "Lookup skipped for privacy protection: URL appears to contain credentials, tokens, or private session parameters.",
            "checked_at": None,
            "limitations": PROVIDER_LIMITATIONS_NOTICE
        }

    # 4. Resolve provider
    if provider is None:
        provider = GoogleSafeBrowsingProvider(api_key=api_key)

    return provider.check_url(cleaned)
