"""
URL Analyzer Module for QShield.
Performs static heuristic inspections and structural feature extraction on web URLs.
Purely defensive: NEVER makes outbound HTTP requests, fetches redirects, or executes content.
"""
import ipaddress
import re
import urllib.parse
from typing import Dict, Any, List, Optional
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

# Initialize offline tldextract extractor (cachefile disabled or offline to guarantee zero outbound network calls)
_extract = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None)

SENSITIVE_PARAM_NAMES = {
    'token', 'access_token', 'id_token', 'refresh_token', 'auth', 'key', 'apikey', 'api_key',
    'secret', 'password', 'pass', 'pwd', 'session', 'sessionid', 'session_id', 'sid',
    'bearer', 'jwt', 'code', 'otp', 'pin', 'ssn', 'cvv', 'card', 'account', 'credit'
}

def mask_sensitive_url(url_str: str) -> str:
    """
    Masks userinfo credentials and sensitive query parameters (tokens, passwords, keys)
    for privacy-preserving display and reporting.
    """
    if not isinstance(url_str, str) or not url_str:
        return ""

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except Exception:
        return url_str

    netloc = parsed.netloc
    if '@' in netloc:
        _, host_port = netloc.split('@', 1)
        netloc = f"[REDACTED]@{host_port}"

    query = parsed.query
    if query:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        masked_pairs = []
        for k, v in pairs:
            k_lower = k.lower().strip()
            is_sensitive = (
                k_lower in SENSITIVE_PARAM_NAMES or
                any(sens in k_lower for sens in ('token', 'secret', 'pass', 'key', 'auth', 'cred', 'session'))
            )
            if is_sensitive:
                masked_pairs.append((k, '[REDACTED]'))
            else:
                masked_pairs.append((k, v))
        query = urllib.parse.urlencode(masked_pairs)

    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))

def is_ip_address(hostname: str) -> bool:
    """Checks whether hostname is a valid IPv4 or IPv6 address."""
    clean = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False

def analyze_url_heuristics(raw_url: str) -> Dict[str, Any]:
    """
    Analyzes a URL string for structural characteristics and suspicious indicators.
    
    Returns structured dictionary:
    {
        "valid": bool,
        "error_code": Optional[str],
        "message": str,
        "parsed_url": {
            "scheme": str,
            "hostname": str,
            "port": Optional[int],
            "registered_domain": str,
            "subdomain": str,
            "tld": str,
            "path": str,
            "has_query": bool,
            "is_https": bool
        },
        "indicators": List[Dict[str, Any]]
    }
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "valid": False,
            "error_code": "EMPTY_INPUT",
            "message": "URL string cannot be empty.",
            "parsed_url": None,
            "indicators": []
        }

    cleaned = raw_url.strip()

    if len(cleaned) > MAX_ALLOWED_ANALYSIS_URL_LENGTH:
        return {
            "valid": False,
            "error_code": "URL_TOO_LONG",
            "message": f"URL exceeds maximum allowed length of {MAX_ALLOWED_ANALYSIS_URL_LENGTH} characters.",
            "parsed_url": None,
            "indicators": []
        }

    # Reject non-web or dangerous schemes immediately
    lower_input = cleaned.lower()
    if lower_input.startswith(('javascript:', 'data:', 'file:', 'vbscript:', 'blob:', 'about:')):
        return {
            "valid": False,
            "error_code": "UNSUPPORTED_SCHEME",
            "message": "Unsupported or unsafe protocol scheme. Only HTTP and HTTPS addresses are accepted.",
            "parsed_url": None,
            "indicators": []
        }

    # Check if this input is clearly a non-URL schema like wifi or vcard
    if lower_input.startswith(('wifi:', 'begin:vcard', 'mecard:', 'tel:', 'mailto:', 'smsto:')):
        return {
            "valid": False,
            "error_code": "NOT_A_WEB_URL",
            "message": "Input is not a web link (HTTP/HTTPS). URL analysis is not applicable to this payload type.",
            "parsed_url": None,
            "indicators": []
        }

    # Parse using standard urllib.parse
    url_to_parse = cleaned
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_to_parse):
        # Default to http:// for normalization if scheme missing
        url_to_parse = 'http://' + url_to_parse

    try:
        parsed = urllib.parse.urlsplit(url_to_parse)
    except Exception:
        return {
            "valid": False,
            "error_code": "MALFORMED_URL",
            "message": "URL structure is malformed and could not be parsed.",
            "parsed_url": None,
            "indicators": []
        }

    scheme = (parsed.scheme or '').lower()
    if scheme not in ('http', 'https'):
        return {
            "valid": False,
            "error_code": "UNSUPPORTED_SCHEME",
            "message": f"Scheme '{scheme}' is not supported. Only HTTP and HTTPS URLs are accepted for web analysis.",
            "parsed_url": None,
            "indicators": []
        }

    hostname = (parsed.hostname or '').lower()
    if not hostname:
        return {
            "valid": False,
            "error_code": "MISSING_HOSTNAME",
            "message": "URL does not contain a valid hostname or destination host.",
            "parsed_url": None,
            "indicators": []
        }

    # Extract public suffix / registered domain safely
    extracted = _extract(hostname)
    reg_domain = extracted.registered_domain.lower() if extracted.registered_domain else hostname
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ''
    suffix = extracted.suffix.lower() if extracted.suffix else ''
    port = parsed.port
    path = parsed.path or '/'
    query = parsed.query or ''
    is_https = (scheme == 'https')

    indicators: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # Check 1: Userinfo syntax (e.g. https://google.com@evil-site.com)
    # -------------------------------------------------------------
    if parsed.username or parsed.password or ('@' in (parsed.netloc or '')):
        indicators.append({
            "id": "URL_USERINFO_PRESENT",
            "title": "Misleading Credential / User-Info Syntax",
            "explanation": "The URL includes an '@' character before the hostname. Web browsers connect to the host AFTER the '@', potentially misleading users into mistaking the prefix for the actual destination.",
            "severity": "high",
            "evidence": "Embedded '@' syntax found in URL authority component."
        })

    # -------------------------------------------------------------
    # Check 2: IP address used as website host
    # -------------------------------------------------------------
    if is_ip_address(hostname):
        indicators.append({
            "id": "URL_RAW_IP_HOST",
            "title": "Raw IP Address Destination",
            "explanation": "The website host is a numerical IP address rather than a verified registered domain. Legitimate corporate and consumer services almost always use branded domain names.",
            "severity": "high",
            "evidence": f"Host is raw IP: {hostname}"
        })

    # -------------------------------------------------------------
    # Check 3: Punycode / Internationalized Domain Name (IDN)
    # -------------------------------------------------------------
    if hostname.startswith("xn--") or ".xn--" in hostname:
        indicators.append({
            "id": "URL_PUNYCODE_HOMOGRAPH",
            "title": "Punycode (IDN) Hostname Detected",
            "explanation": "The domain name begins with 'xn--', which indicates an encoded internationalized domain name. Attackers sometimes use visually similar foreign characters (homoglyphs) to impersonate trusted domains.",
            "severity": "medium",
            "evidence": f"Punycode encoded host: {hostname}"
        })

    # -------------------------------------------------------------
    # Check 4: Brand Impersonation & Typosquatting in Subdomain/Host
    # -------------------------------------------------------------
    for brand, canonical_dom in TARGET_BRANDS.items():
        # Check if the brand name is present anywhere in the hostname
        if brand in hostname:
            # If the registered domain is NOT the canonical domain of that brand
            if reg_domain != canonical_dom:
                if brand in subdomain:
                    indicators.append({
                        "id": "URL_BRAND_IN_SUBDOMAIN",
                        "title": f"Trusted Brand Substring in Subdomain ({brand.capitalize()})",
                        "explanation": f"The brand name '{brand}' appears in the subdomain prefix, but the actual root registered domain is '{reg_domain}'. This is a common quishing technique designed to mimic trusted portals.",
                        "severity": "high",
                        "evidence": f"'{brand}' found in subdomain '{subdomain}' on root domain '{reg_domain}'."
                    })
                elif brand in reg_domain:
                    indicators.append({
                        "id": "URL_BRAND_TYPOSQUAT_SUSPICION",
                        "title": f"Possible Brand Name Mimicry ({brand.capitalize()})",
                        "explanation": f"The registered domain '{reg_domain}' includes the brand token '{brand}', but does not match the official domain '{canonical_dom}'. Verify whether this is an authorized affiliate or a mimic.",
                        "severity": "medium",
                        "evidence": f"'{brand}' in unregistered match '{reg_domain}' vs official '{canonical_dom}'."
                    })

    # -------------------------------------------------------------
    # Check 5: Excessive Subdomain Depth
    # -------------------------------------------------------------
    if subdomain:
        subdomain_labels = [s for s in subdomain.split('.') if s]
        if len(subdomain_labels) >= MAX_SUBDOMAIN_DEPTH:
            indicators.append({
                "id": "URL_EXCESSIVE_SUBDOMAINS",
                "title": "Unusually Deep Subdomain Structure",
                "explanation": f"The hostname contains {len(subdomain_labels)} nested subdomain levels. Complex subdomain chains are often utilized by phishing kits to conceal the primary domain on mobile screens.",
                "severity": "medium",
                "evidence": f"{len(subdomain_labels)} subdomains: {subdomain}"
            })

    # -------------------------------------------------------------
    # Check 6: Known URL Shortener
    # -------------------------------------------------------------
    if reg_domain in KNOWN_URL_SHORTENERS or hostname in KNOWN_URL_SHORTENERS:
        indicators.append({
            "id": "URL_SHORTENER_DETECTED",
            "title": "URL Shortening Service Detected",
            "explanation": f"The destination is routed through a public URL shortener ('{reg_domain}'). Shortened links obscure the final landing website until opened.",
            "severity": "medium",
            "evidence": f"Shortener service host: {reg_domain}"
        })

    # -------------------------------------------------------------
    # Check 7: Credential / Account Keywords in Path or Parameters
    # -------------------------------------------------------------
    path_and_query_lower = (path + '?' + query).lower()
    matched_cred_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in path_and_query_lower]
    matched_urgency_keywords = [kw for kw in URGENCY_KEYWORDS if kw in path_and_query_lower]

    if matched_cred_keywords:
        indicators.append({
            "id": "URL_CREDENTIAL_KEYWORDS_IN_PATH",
            "title": "Authentication / Credential Terms in Link Path",
            "explanation": f"The URL path contains terms associated with login or account verification ({', '.join(matched_cred_keywords[:3])}). While normal on legitimate sites, examine the domain carefully before typing credentials.",
            "severity": "low",
            "evidence": f"Matched terms: {', '.join(matched_cred_keywords[:4])}"
        })

    if matched_urgency_keywords:
        indicators.append({
            "id": "URL_URGENCY_KEYWORDS_IN_PATH",
            "title": "Urgency / Coercive Terms in Link Path",
            "explanation": f"The URL contains urgency keywords ({', '.join(matched_urgency_keywords[:3])}) often used in social engineering lures.",
            "severity": "low",
            "evidence": f"Matched urgency terms: {', '.join(matched_urgency_keywords[:3])}"
        })

    # -------------------------------------------------------------
    # Check 8: Unusual Web Port
    # -------------------------------------------------------------
    if port and port not in STANDARD_WEB_PORTS:
        indicators.append({
            "id": "URL_NON_STANDARD_PORT",
            "title": "Non-Standard Network Port",
            "explanation": f"The URL connects via port {port} instead of standard web ports (80 for HTTP or 443 for HTTPS). Unusual ports can indicate an ad-hoc server or malicious proxy.",
            "severity": "medium",
            "evidence": f"Port: {port}"
        })

    # -------------------------------------------------------------
    # Check 9: Unusually Long URL or Excessive Parameters
    # -------------------------------------------------------------
    if len(cleaned) > MAX_URL_LENGTH_STANDARD:
        indicators.append({
            "id": "URL_EXCESSIVE_LENGTH",
            "title": "Unusually Long URL Length",
            "explanation": f"The URL is {len(cleaned)} characters long. Attackers often pad URLs with long tokens or dummy strings to push the real domain off-screen on mobile devices.",
            "severity": "low",
            "evidence": f"Total character length: {len(cleaned)}"
        })

    if query:
        query_param_count = len(urllib.parse.parse_qs(query, keep_blank_values=True))
        if query_param_count > MAX_QUERY_PARAMS_COUNT:
            indicators.append({
                "id": "URL_EXCESSIVE_QUERY_PARAMS",
                "title": "High Number of Query Parameters",
                "explanation": f"The URL contains {query_param_count} distinct query parameters, which may include tracking beacons, nested redirects, or encoded session tokens.",
                "severity": "low",
                "evidence": f"{query_param_count} parameters in query string."
            })

    # -------------------------------------------------------------
    # Check 10: HTTPS / Encryption Context
    # -------------------------------------------------------------
    if not is_https:
        indicators.append({
            "id": "URL_UNENCRYPTED_HTTP",
            "title": "Unencrypted HTTP Protocol",
            "explanation": "This link uses unencrypted plain HTTP. While absence of HTTPS alone does not prove malicious intent, any passwords or data entered on this page would be transmitted in plain text across the network.",
            "severity": "medium",
            "evidence": "Scheme is http:// without TLS encryption."
        })
    else:
        # Information indicator regarding HTTPS meaning
        indicators.append({
            "id": "URL_HTTPS_PRESENT_NOTICE",
            "title": "Encrypted HTTPS Protocol",
            "explanation": "This website uses HTTPS encryption. Note: HTTPS secures communication between your browser and the server, but it does NOT guarantee the website is legitimate or safe.",
            "severity": "info",
            "evidence": "Scheme is https://"
        })

    parsed_data = {
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "registered_domain": reg_domain,
        "subdomain": subdomain,
        "tld": suffix,
        "path": path,
        "has_query": bool(query),
        "is_https": is_https
    }

    return {
        "valid": True,
        "error_code": None,
        "message": f"URL analysis complete. {len(indicators)} structural indicator(s) noted.",
        "parsed_url": parsed_data,
        "indicators": indicators
    }
