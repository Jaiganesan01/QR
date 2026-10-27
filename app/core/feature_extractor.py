"""
Advanced URL Feature Extraction Module for QShield.
Performs deterministic, purely offline lexical and structural feature extraction.
Zero outbound network requests; zero DNS lookups; zero dynamic code execution.
"""
import ipaddress
import math
import re
import urllib.parse
from collections import Counter
from typing import Any, Dict, List, Optional
import tldextract

from app.core.rules_config import (
    TARGET_BRANDS,
    KNOWN_URL_SHORTENERS,
    CREDENTIAL_KEYWORDS,
    URGENCY_KEYWORDS,
    STANDARD_WEB_PORTS,
    MAX_URL_LENGTH_STANDARD,
    MAX_SUBDOMAIN_DEPTH,
    MAX_QUERY_PARAMS_COUNT,
    MAX_ALLOWED_ANALYSIS_URL_LENGTH,
)

# Initialize offline tldextract extractor (offline mode, no network lookups)
_extract = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None)

# Known query parameter names frequently utilized for open redirects
REDIRECT_PARAM_NAMES = {
    'url', 'redirect', 'redirect_url', 'redirect_uri', 'redirect_to',
    'dest', 'destination', 'next', 'target', 'link', 'out', 'view',
    'forward', 'goto', 'r', 'u', 'q'
}


def calculate_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy H(X) = -sum(P(x) * log2(P(x))) for a string.
    High entropy (H >= 4.2) indicates high randomness (e.g. encrypted/obfuscated strings).
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def is_ip_host(hostname: str) -> bool:
    """Checks whether the hostname is an IPv4 or IPv6 address literal."""
    if not hostname:
        return False
    clean = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def extract_url_features(raw_url: str) -> Dict[str, Any]:
    """
    Safely extracts 20+ structural and lexical features from a URL string.
    Returns a comprehensive structured dictionary.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        return {"valid": False, "error_code": "EMPTY_INPUT", "features": None}

    cleaned = raw_url.strip()
    if len(cleaned) > MAX_ALLOWED_ANALYSIS_URL_LENGTH:
        return {"valid": False, "error_code": "URL_TOO_LONG", "features": None}

    # Normalize protocol prefix for parsing
    url_to_parse = cleaned
    has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_to_parse))
    if not has_scheme:
        url_to_parse = 'http://' + url_to_parse

    try:
        parsed = urllib.parse.urlsplit(url_to_parse)
    except Exception:
        return {"valid": False, "error_code": "MALFORMED_URL", "features": None}

    scheme = (parsed.scheme or '').lower()
    hostname = (parsed.hostname or '').lower()

    if not hostname:
        return {"valid": False, "error_code": "MISSING_HOSTNAME", "features": None}

    # Extract public suffix / registered domain safely
    extracted = _extract(hostname)
    reg_domain = extracted.registered_domain.lower() if extracted.registered_domain else hostname
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ''
    suffix = extracted.suffix.lower() if extracted.suffix else ''
    path = parsed.path or '/'
    query = parsed.query or ''
    port = parsed.port

    # Subdomain depth
    subdomain_parts = [s for s in subdomain.split('.') if s] if subdomain else []
    subdomain_depth = len(subdomain_parts)

    # Character counts & ratios
    url_len = len(cleaned)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    digit_count_host = sum(c.isdigit() for c in hostname)
    digit_ratio_host = round(digit_count_host / max(1, host_len), 3)

    hyphen_count_host = hostname.count('-')
    consecutive_dots = '..' in cleaned
    special_char_count = sum(not c.isalnum() for c in cleaned)

    # Obfuscation & Encoding
    percent_encodings = re.findall(r'%[0-9a-fA-F]{2}', cleaned)
    percent_count = len(percent_encodings)
    excessive_encoding = percent_count >= 3

    # Shannon Entropy
    path_entropy = calculate_entropy(path)
    query_entropy = calculate_entropy(query)

    # Userinfo deception (e.g. https://google.com@evil.com)
    has_userinfo = bool(parsed.username or parsed.password or ('@' in (parsed.netloc or '')))

    # Punycode / IDN
    is_punycode = hostname.startswith("xn--") or (".xn--" in hostname)

    # Non-standard web port
    has_non_standard_port = bool(port and port not in STANDARD_WEB_PORTS)

    # Shortener check
    is_shortener = reg_domain in KNOWN_URL_SHORTENERS or hostname in KNOWN_URL_SHORTENERS

    # Redirect parameter detection
    query_params = urllib.parse.parse_qs(query, keep_blank_values=True)
    redirect_params_found = [k for k in query_params if k.lower().strip() in REDIRECT_PARAM_NAMES]
    has_redirect_param = len(redirect_params_found) > 0

    # Brand Mimicry Check
    matched_brands: List[Dict[str, str]] = []
    for brand, canonical_dom in TARGET_BRANDS.items():
        if brand in hostname and reg_domain != canonical_dom:
            location = "subdomain" if (brand in subdomain) else "registered_domain"
            matched_brands.append({
                "brand": brand,
                "canonical_domain": canonical_dom,
                "location": location
            })

    # Keyword scanning
    path_and_query_lower = (path + '?' + query).lower()
    matched_cred_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in path_and_query_lower]
    matched_urgency_keywords = [kw for kw in URGENCY_KEYWORDS if kw in path_and_query_lower]

    features = {
        # Dimensionality
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        # Structural Complexity
        "subdomain_depth": subdomain_depth,
        "subdomain_labels": subdomain_parts,
        "hyphen_count_hostname": hyphen_count_host,
        "consecutive_dots": consecutive_dots,
        "special_char_count": special_char_count,
        "digit_ratio_hostname": digit_ratio_host,
        # Lexical Entropy
        "path_entropy": path_entropy,
        "query_entropy": query_entropy,
        # Encoding
        "percent_encoding_count": percent_count,
        "excessive_encoding": excessive_encoding,
        # Host & Network
        "scheme": scheme,
        "is_https": (scheme == 'https'),
        "hostname": hostname,
        "registered_domain": reg_domain,
        "tld": suffix,
        "port": port,
        "has_non_standard_port": has_non_standard_port,
        "is_ip_host": is_ip_host(hostname),
        "is_punycode": is_punycode,
        # Deception & Evasion
        "has_userinfo": has_userinfo,
        "is_shortener": is_shortener,
        "has_redirect_param": has_redirect_param,
        "redirect_params": redirect_params_found,
        "matched_brands": matched_brands,
        # Keywords
        "credential_keywords": matched_cred_keywords,
        "urgency_keywords": matched_urgency_keywords,
        "query_param_count": len(query_params),
    }

    return {
        "valid": True,
        "error_code": None,
        "features": features
    }


def extract_numerical_feature_vector(raw_url: str) -> Dict[str, float]:
    """
    Converts extracted URL features into a fixed-length numerical dictionary suitable
    for machine-learning classifiers or statistical scoring pipelines.
    """
    res = extract_url_features(raw_url)
    if not res.get("valid") or not res.get("features"):
        return {}

    f = res["features"]
    return {
        "f_url_len": float(f["url_length"]),
        "f_host_len": float(f["hostname_length"]),
        "f_path_len": float(f["path_length"]),
        "f_query_len": float(f["query_length"]),
        "f_subdomain_depth": float(f["subdomain_depth"]),
        "f_hyphen_count": float(f["hyphen_count_hostname"]),
        "f_digit_ratio": float(f["digit_ratio_hostname"]),
        "f_percent_count": float(f["percent_encoding_count"]),
        "f_path_entropy": float(f["path_entropy"]),
        "f_query_entropy": float(f["query_entropy"]),
        "f_is_https": 1.0 if f["is_https"] else 0.0,
        "f_is_ip_host": 1.0 if f["is_ip_host"] else 0.0,
        "f_is_punycode": 1.0 if f["is_punycode"] else 0.0,
        "f_has_userinfo": 1.0 if f["has_userinfo"] else 0.0,
        "f_is_shortener": 1.0 if f["is_shortener"] else 0.0,
        "f_has_redirect_param": 1.0 if f["has_redirect_param"] else 0.0,
        "f_has_non_standard_port": 1.0 if f["has_non_standard_port"] else 0.0,
        "f_brand_mimicry": 1.0 if len(f["matched_brands"]) > 0 else 0.0,
        "f_cred_keywords": float(len(f["credential_keywords"])),
        "f_urgency_keywords": float(len(f["urgency_keywords"])),
        "f_query_param_count": float(f["query_param_count"]),
    }
