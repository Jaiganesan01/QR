"""
Safe Redirect Inspector & Redirect Chain Analyzer for QShield.
Performs manual, single-hop HTTP inspections with strict SSRF defense:
- Scheme whitelist (HTTP/HTTPS only)
- Strict loopback, private, link-local, multicast, and cloud metadata destination blocks
- Manual redirect loop and hop counting (max 5 hops)
- Relative location resolution with urllib.parse.urljoin
- Scheme downgrade (HTTPS -> HTTP) and cross-domain detection
- Bounded header and response body consumption
- Privacy screening against sensitive URLs and credentials
"""
from datetime import datetime, timezone
import ipaddress
import logging
import re
import socket
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.error
from urllib.parse import urlparse, urljoin

from app.core.rules_config import KNOWN_URL_SHORTENERS
from app.core.threat_intelligence import is_sensitive_url

logger = logging.getLogger(__name__)

# Maximum redirect hops allowed
MAX_REDIRECT_HOPS = 5

# Network timeouts in seconds
INSPECTION_CONNECT_TIMEOUT = 3.5

# Cloud metadata endpoints and well-known internal destinations
PROHIBITED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
    "instance-data"
}

PROHIBITED_METADATA_IPS = {
    "169.254.169.254",   # AWS/GCP/Azure/OpenStack metadata
    "169.254.170.2",     # AWS ECS container metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
}


def is_ip_prohibited(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Check if an IP address is private, loopback, link-local, multicast, reserved, or cloud metadata.
    """
    # Check string match for known metadata IP addresses
    if str(ip_obj) in PROHIBITED_METADATA_IPS:
        return True

    # If IPv4-mapped IPv6, inspect the underlying IPv4 address
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        return is_ip_prohibited(ip_obj.ipv4_mapped)

    return (
        ip_obj.is_private or
        ip_obj.is_loopback or
        ip_obj.is_link_local or
        ip_obj.is_multicast or
        ip_obj.is_reserved or
        ip_obj.is_unspecified
    )


def validate_destination_safety(hostname: str) -> Tuple[bool, str, List[str]]:
    """
    Resolves hostname and verifies that all resolved IP addresses are globally routable,
    public, and not reserved/private/loopback/cloud metadata.
    Returns (is_safe, error_reason, resolved_ips).
    """
    cleaned_host = hostname.strip().lower()

    if not cleaned_host:
        return False, "Destination host is empty.", []

    if cleaned_host in PROHIBITED_HOSTNAMES or cleaned_host.endswith(".local") or cleaned_host.endswith(".internal"):
        return False, f"Destination host '{cleaned_host}' is a prohibited local/internal hostname.", []

    # Check if host is already an IP literal
    try:
        ip_obj = ipaddress.ip_address(cleaned_host)
        if is_ip_prohibited(ip_obj):
            return False, f"Destination IP address {ip_obj} is a prohibited private, loopback, or metadata address.", [str(ip_obj)]
        return True, "", [str(ip_obj)]
    except ValueError:
        pass  # Host is a domain name, proceed to DNS resolution

    resolved_ips: List[str] = []
    try:
        # Resolve both IPv4 and IPv6 addresses
        addr_info = socket.getaddrinfo(cleaned_host, None)
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)

        if not resolved_ips:
            return False, f"Could not resolve destination hostname '{cleaned_host}'.", []

        # Enforce all-addresses-safe rule: If ANY resolved IP is private/prohibited, reject destination
        for ip_str in resolved_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_prohibited(ip_obj):
                return False, f"Destination hostname resolved to prohibited internal IP address ({ip_str}).", resolved_ips

    except socket.gaierror:
        return False, f"DNS resolution failed for hostname '{cleaned_host}'.", []
    except Exception as ex:
        return False, f"Error validating destination safety: {type(ex).__name__}", []

    return True, "", resolved_ips


class SafeRedirectInspector:
    """
    Manual redirect stepper that validates every single hop before fetching,
    disabling automatic redirect following in HTTP clients to strictly prevent SSRF.
    """

    def __init__(self, max_hops: int = MAX_REDIRECT_HOPS, timeout: float = INSPECTION_CONNECT_TIMEOUT):
        self.max_hops = max_hops
        self.timeout = timeout

    def _execute_single_hop_request(self, target_url: str) -> Tuple[int, Dict[str, str], str]:
        """
        Executes a single HTTP HEAD (or fallback GET) request without following redirects.
        Returns (status_code, headers_dict, error_message).
        """
        import http.client

        parsed = urlparse(target_url)
        scheme = (parsed.scheme or '').lower()
        host = parsed.hostname
        port = parsed.port or (443 if scheme == 'https' else 80)
        path = parsed.path or '/'
        if parsed.query:
            path += f"?{parsed.query}"

        # Create connection based on scheme
        conn = None
        try:
            if scheme == 'https':
                import ssl
                context = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=context)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

            # Send minimal HEAD request to read headers without pulling payload bodies
            conn.request("HEAD", path, headers={
                "User-Agent": "QShield-Redirect-Inspector/1.0 (+https://github.com/qshield)",
                "Accept": "*/*",
                "Connection": "close"
            })

            res = conn.getresponse()
            status_code = res.status
            headers_dict = {k.lower(): v for k, v in res.getheaders()}

            # If server forbids HEAD (405 Method Not Allowed), retry with bounded GET
            if status_code == 405:
                conn.close()
                if scheme == 'https':
                    conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=context)
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

                conn.request("GET", path, headers={
                    "User-Agent": "QShield-Redirect-Inspector/1.0",
                    "Accept": "*/*",
                    "Connection": "close"
                })
                res = conn.getresponse()
                status_code = res.status
                headers_dict = {k.lower(): v for k, v in res.getheaders()}
                # Consume max 4KB of body and close
                res.read(4096)

            return status_code, headers_dict, ""

        except TimeoutError:
            return 0, {}, "Connection timed out."
        except Exception as ex:
            return 0, {}, f"Connection error: {type(ex).__name__}"
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect(self, initial_url: str) -> Dict[str, Any]:
        """
        Traces redirect hops from initial_url up to max_hops.
        """
        hops: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        current_url = initial_url
        status = "completed"
        final_destination = current_url
        initial_parsed = urlparse(initial_url)
        initial_host = (initial_parsed.hostname or '').lower()

        # Check if initial domain is a known shortener
        if initial_host in KNOWN_URL_SHORTENERS:
            findings.append({
                "id": "known_url_shortener",
                "title": "Known URL Shortener Detected",
                "severity": "info",
                "explanation": f"The initial destination '{initial_host}' is a known public URL shortening service.",
                "evidence": f"Domain matched shortener index: {initial_host}",
                "recommended_action": "Verify where the shortened destination resolves before interacting."
            })

        for hop_index in range(1, self.max_hops + 1):
            parsed_curr = urlparse(current_url)
            curr_scheme = (parsed_curr.scheme or '').lower()
            curr_host = (parsed_curr.hostname or '').lower()

            # 1. Scheme Validation
            if curr_scheme not in ('http', 'https'):
                status = "blocked"
                findings.append({
                    "id": "unexpected_scheme",
                    "title": "Unsupported or Dangerous Protocol Scheme",
                    "severity": "high",
                    "explanation": f"Redirect destination specified disallowed scheme '{curr_scheme}:'.",
                    "evidence": f"Hop #{hop_index} scheme is '{curr_scheme}'.",
                    "recommended_action": "Do not follow links using non-standard URI schemes."
                })
                break

            # 2. SSRF Destination Validation
            is_safe, block_reason, _ = validate_destination_safety(curr_host)
            if not is_safe:
                status = "blocked"
                findings.append({
                    "id": "inspection_blocked",
                    "title": "Prohibited Internal / Private Destination Blocked",
                    "severity": "high",
                    "explanation": f"SSRF protection blocked access to destination host '{curr_host}': {block_reason}",
                    "evidence": f"Hop #{hop_index} attempted connection to prohibited destination.",
                    "recommended_action": "Do not interact with QR codes directing toward private or metadata addresses."
                })
                break

            # 3. Redirect Loop Check
            normalized_curr = f"{curr_scheme}://{curr_host}{parsed_curr.path}"
            if normalized_curr in seen_urls:
                status = "completed"
                findings.append({
                    "id": "redirect_loop",
                    "title": "Redirect Loop Detected",
                    "severity": "medium",
                    "explanation": "The destination redirects back to a URL already encountered in the chain.",
                    "evidence": f"Repeated destination: {curr_host}{parsed_curr.path}",
                    "recommended_action": "Avoid following links stuck in redirect loops."
                })
                break
            seen_urls.add(normalized_curr)

            # 4. Execute Single Request
            status_code, headers, err_msg = self._execute_single_hop_request(current_url)

            if status_code == 0:
                status = "destination_unreachable"
                findings.append({
                    "id": "destination_unreachable",
                    "title": "Destination Host Unreachable",
                    "severity": "info",
                    "explanation": f"Could not establish connection to '{curr_host}': {err_msg}",
                    "evidence": err_msg,
                    "recommended_action": "Check connection or verify if destination domain is offline."
                })
                break

            # 5. Check if response is a redirect (301, 302, 303, 307, 308)
            is_redirect_code = status_code in (301, 302, 303, 307, 308)
            location_header = headers.get("location")

            if is_redirect_code and location_header:
                # Resolve relative redirects against current_url
                next_url = urljoin(current_url, location_header.strip())
                next_parsed = urlparse(next_url)
                next_host = (next_parsed.hostname or '').lower()
                next_scheme = (next_parsed.scheme or '').lower()

                is_cross_domain = bool(curr_host and next_host and curr_host != next_host)
                is_downgrade = (curr_scheme == 'https' and next_scheme == 'http')

                hop_record = {
                    "hop_number": hop_index,
                    "status_code": status_code,
                    "source_host": curr_host,
                    "destination_host": next_host,
                    "destination_display": f"{next_scheme}://{next_host}{next_parsed.path or '/'}",
                    "is_cross_domain": is_cross_domain,
                    "is_downgrade": is_downgrade
                }
                hops.append(hop_record)

                if is_cross_domain:
                    findings.append({
                        "id": "cross_domain_redirect",
                        "title": "Cross-Domain Redirect Observed",
                        "severity": "medium",
                        "explanation": f"Hop #{hop_index} redirects from domain '{curr_host}' to external domain '{next_host}'.",
                        "evidence": f"{curr_host} -> {next_host}",
                        "recommended_action": "Verify that the final destination host is the intended authentic service."
                    })

                if is_downgrade:
                    findings.append({
                        "id": "https_to_http_downgrade",
                        "title": "Insecure Protocol Downgrade (HTTPS to HTTP)",
                        "severity": "high",
                        "explanation": f"Hop #{hop_index} redirected from encrypted HTTPS to unencrypted HTTP.",
                        "evidence": f"From https://{curr_host} to http://{next_host}",
                        "recommended_action": "Do not enter passwords or personal data on unencrypted HTTP destinations."
                    })

                current_url = next_url
                final_destination = next_url

            else:
                # Terminal destination reached!
                hop_record = {
                    "hop_number": hop_index,
                    "status_code": status_code,
                    "source_host": curr_host,
                    "destination_host": curr_host,
                    "destination_display": f"{curr_scheme}://{curr_host}{parsed_curr.path or '/'}",
                    "is_cross_domain": False,
                    "is_downgrade": False
                }
                hops.append(hop_record)
                final_destination = current_url
                break
        else:
            # Loop ended due to hitting max_hops
            status = "incomplete"
            findings.append({
                "id": "long_redirect_chain",
                "title": "Excessive Redirect Chain",
                "severity": "medium",
                "explanation": f"Redirect chain exceeded the maximum inspection limit of {self.max_hops} hops.",
                "evidence": f"{len(hops)} consecutive redirect hops recorded.",
                "recommended_action": "Exercise high caution; elongated redirect chains are frequently used to evade security scanners."
            })

        final_parsed = urlparse(final_destination)
        final_host = (final_parsed.hostname or '').lower()

        # Build concise human summary
        if len(hops) <= 1:
            summary = f"No redirects observed. Destination resolves directly to {final_host} (HTTP {hops[0]['status_code'] if hops else 200})."
        else:
            summary = f"Observed {len(hops) - 1} redirect hop(s) concluding at destination host '{final_host}'."

        return {
            "status": status,
            "inspection_mode": "safe_single_hop_sandbox",
            "submitted_url_display": f"{initial_parsed.scheme}://{initial_host}{initial_parsed.path or '/'}",
            "hops": hops,
            "redirect_count": max(0, len(hops) - 1),
            "final_destination_display": f"{final_parsed.scheme}://{final_host}{final_parsed.path or '/'}",
            "findings": findings,
            "summary": summary,
            "limitations": (
                "Inspection contacts public web endpoints with strict SSRF controls (no private IPs/metadata). "
                "Client-side redirects (HTML meta refresh, JavaScript location updates) are not followed."
            ),
            "checked_at": datetime.now(timezone.utc).isoformat()
        }


def inspect_redirects(url: str, consent_confirmed: bool = False, inspector: Optional[SafeRedirectInspector] = None) -> Dict[str, Any]:
    """
    Main evaluation interface for Safe Redirect Inspection.
    Enforces explicit user consent, privacy screening against sensitive query tokens,
    and strict URL validation before calling the inspector.
    """
    # 1. Explicit Consent Enforcement
    if not consent_confirmed:
        return {
            "status": "skipped_no_consent",
            "inspection_mode": "uninspected",
            "submitted_url_display": url[:80] if url else "",
            "hops": [],
            "redirect_count": 0,
            "final_destination_display": None,
            "findings": [{
                "id": "consent_required",
                "title": "User Consent Required",
                "severity": "info",
                "explanation": "Safe redirect inspection contacts external web hosts and requires explicit user consent.",
                "evidence": "Consent flag was False or not provided.",
                "recommended_action": "Click 'Inspect Redirects' to authorize inspection."
            }],
            "summary": "Redirect inspection was not run because explicit consent was not provided.",
            "limitations": "No external connections are made without explicit user confirmation.",
            "checked_at": None
        }

    # 2. URL Scheme & Structure Validation
    if not isinstance(url, str) or not url.strip():
        return {
            "status": "invalid_url",
            "inspection_mode": "uninspected",
            "submitted_url_display": "",
            "hops": [],
            "redirect_count": 0,
            "final_destination_display": None,
            "findings": [],
            "summary": "Invalid or empty URL.",
            "limitations": "Only valid HTTP and HTTPS URLs can be inspected.",
            "checked_at": None
        }

    cleaned = url.strip()
    try:
        parsed = urlparse(cleaned)
        scheme = (parsed.scheme or '').lower()
        if scheme not in ('http', 'https') or not parsed.hostname:
            return {
                "status": "invalid_url",
                "inspection_mode": "uninspected",
                "submitted_url_display": cleaned[:80],
                "hops": [],
                "redirect_count": 0,
                "final_destination_display": None,
                "findings": [{
                    "id": "unsupported_scheme",
                    "title": "Unsupported Protocol Scheme",
                    "severity": "high",
                    "explanation": f"Scheme '{scheme}' is unsupported. Only standard HTTP and HTTPS URLs can be inspected.",
                    "evidence": f"Scheme: {scheme}",
                    "recommended_action": "Inspect only standard web addresses."
                }],
                "summary": f"Scheme '{scheme}' is not supported for redirect inspection.",
                "limitations": "Only valid HTTP and HTTPS URLs can be inspected.",
                "checked_at": None
            }
    except Exception:
        return {
            "status": "invalid_url",
            "inspection_mode": "uninspected",
            "submitted_url_display": cleaned[:80],
            "hops": [],
            "redirect_count": 0,
            "final_destination_display": None,
            "findings": [],
            "summary": "Malformed URL format.",
            "limitations": "Only valid HTTP and HTTPS URLs can be inspected.",
            "checked_at": None
        }

    # 3. Privacy-by-Default Screening
    if is_sensitive_url(cleaned):
        return {
            "status": "skipped_sensitive_url",
            "inspection_mode": "privacy_guarded",
            "submitted_url_display": f"{parsed.scheme}://{parsed.hostname}{parsed.path or '/'}",
            "hops": [],
            "redirect_count": 0,
            "final_destination_display": None,
            "findings": [{
                "id": "privacy_guard_skipped",
                "title": "Inspection Skipped for Privacy Protection",
                "severity": "info",
                "explanation": "This URL contains authentication tokens, passwords, session parameters, or credentials in its path or query string.",
                "evidence": "Sensitive parameter or embedded credential pattern detected.",
                "recommended_action": "Do not transmit sensitive access links across external inspection pipelines."
            }],
            "summary": "Redirect inspection skipped to protect private session credentials.",
            "limitations": "URLs with authentication tokens or embedded passwords are never fetched.",
            "checked_at": None
        }

    # 4. Execute Inspection
    if inspector is None:
        inspector = SafeRedirectInspector()

    return inspector.inspect(cleaned)
