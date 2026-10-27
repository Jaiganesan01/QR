"""
Configurable detection rules and reference datasets for URL heuristic analysis.
All rules are defensive, static, and require zero external network lookups.
"""

# Configurable list of high-profile target brands frequently targeted by quishing / phishing
# Format: { brand_token: canonical_registered_domain }
TARGET_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "dropbox": "dropbox.com",
    "github": "github.com",
    "telegram": "telegram.org",
}

# Known public URL shortener domains (frequently conceal destinations in QR codes)
KNOWN_URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "rebrand.ly",
    "cutt.ly",
    "tiny.cc",
    "qr.ae",
    "shorturl.at",
    "v.gd",
    "rb.gy",
    "linktr.ee",
    "soo.gd",
    "s.id",
}

# Sensitive credential / account collection terms in path and query parameters
CREDENTIAL_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "sign_in",
    "log-in",
    "log_in",
    "verify",
    "verification",
    "authenticate",
    "authentication",
    "password",
    "credential",
    "passcode",
    "secure-banking",
    "account-update",
    "update-billing",
    "security-challenge",
    "wallet-connect",
    "recover-account",
    "validate-session",
    "otp",
]

# Urgency / coercing terms commonly paired with phishing lures
URGENCY_KEYWORDS = [
    "urgent",
    "suspended",
    "immediate",
    "action-required",
    "expire",
    "restricted",
    "unauthorized",
    "locked",
]

# Standard web ports (ports outside this set trigger an unusual port indicator)
STANDARD_WEB_PORTS = {80, 443, 8080, 8443}

# Threshold limits
MAX_URL_LENGTH_STANDARD = 250
MAX_SUBDOMAIN_DEPTH = 3
MAX_QUERY_PARAMS_COUNT = 8
MAX_ALLOWED_ANALYSIS_URL_LENGTH = 2048
