"""
Explainable Risk Scoring Engine for QShield.
Converts heuristic URL analysis indicators into an explainable 0-100 risk score,
risk category, and targeted safety recommendations.
"""
from typing import Dict, Any, List, Optional

# Configurable weights for indicator severities
SEVERITY_WEIGHTS = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 25,
}

# Configurable risk score categories and thresholds
# Format: (min_score, max_score, category_label)
RISK_THRESHOLDS = [
    (0, 19, "low"),
    (20, 49, "medium"),
    (50, 79, "high"),
    (80, 100, "critical"),
]

# Indicator grouping map to prevent inflation from closely related features
# Related indicators under the same group share a cumulative cap or sub-weighting
RELATED_GROUPS = {
    "brand_mimicry": ["URL_BRAND_IN_SUBDOMAIN", "URL_BRAND_TYPOSQUAT_SUSPICION"],
    "credential_context": ["URL_CREDENTIAL_KEYWORDS_IN_PATH", "URL_URGENCY_KEYWORDS_IN_PATH"],
    "length_obfuscation": ["URL_EXCESSIVE_LENGTH", "URL_EXCESSIVE_QUERY_PARAMS"],
}

# Targeted safety recommendations mapped to specific indicator identifiers
INDICATOR_RECOMMENDATIONS = {
    "URL_USERINFO_PRESENT": (
        "Inspect the actual hostname carefully; text before the '@' symbol is deceptive and may conceal the true host."
    ),
    "URL_RAW_IP_HOST": (
        "Verify the destination independently before entering personal information. Legitimate consumer services rarely use raw IP numbers."
    ),
    "URL_BRAND_IN_SUBDOMAIN": (
        "Check the domain spelling and verify that the root registered domain actually belongs to the organization you intended to visit."
    ),
    "URL_BRAND_TYPOSQUAT_SUSPICION": (
        "Watch for lookalike or misspelled domain names mimicking trusted services. Manually navigate via official bookmarks instead."
    ),
    "URL_PUNYCODE_HOMOGRAPH": (
        "This destination uses internationalized punycode characters that may visually imitate legitimate domain letters. Examine the full ASCII address."
    ),
    "URL_SHORTENER_DETECTED": (
        "The destination is not obvious from the shortened URL. Use a trusted link expansion service or verify the destination with the sender before proceeding."
    ),
    "URL_EXCESSIVE_SUBDOMAINS": (
        "Be wary of complex subdomain prefixes that push the root domain out of view on smaller smartphone screens."
    ),
    "URL_NON_STANDARD_PORT": (
        "This address communicates over a non-standard port. Avoid submitting credentials or private information across unusual ports."
    ),
    "URL_CREDENTIAL_KEYWORDS_IN_PATH": (
        "Do not enter passwords, OTPs, or payment information unless you independently verify that you are on the authentic website."
    ),
    "URL_URGENCY_KEYWORDS_IN_PATH": (
        "Beware of urgency claims demanding immediate account verification or payment. Contact the provider directly through official channels."
    ),
    "URL_UNENCRYPTED_HTTP": (
        "This link uses unencrypted plain HTTP. Never enter passwords or sensitive personal data on unencrypted web pages."
    ),
}

DEFAULT_CLEAN_RECOMMENDATIONS = [
    "No suspicious indicators were triggered by our configured static rules. However, always verify that the domain name matches your intended destination.",
    "Be cautious if a page suddenly prompts you for authentication credentials or payment information."
]

LIMITATIONS_NOTICE = (
    "This assessment is a deterministic heuristic evaluation based on static structural features. "
    "It does not represent a calibrated phishing probability, does not inspect dynamic website content, "
    "and does not guarantee that a link is safe or malicious."
)

def get_risk_category(score: int) -> str:
    """Maps a 0-100 score to its defined risk category."""
    for min_s, max_s, label in RISK_THRESHOLDS:
        if min_s <= score <= max_s:
            return label
    return "critical" if score >= 100 else "low"

def calculate_risk_score(url_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates validated URL analysis data and calculates an explainable risk score (0-100).
    
    Returns structured dictionary:
    {
        "score": Optional[int],
        "risk_level": str,  # 'low', 'medium', 'high', 'critical', or 'inconclusive'
        "summary": str,
        "score_breakdown": {
            "raw_total": int,
            "capped_score": int,
            "deduplication_adjustments": int
        },
        "contributing_indicators": List[Dict[str, Any]],
        "recommendations": List[str],
        "limitations": str
    }
    """
    if not isinstance(url_analysis, dict):
        return {
            "score": None,
            "risk_level": "inconclusive",
            "summary": "Scoring is not applicable because input analysis data is invalid or missing.",
            "score_breakdown": {"raw_total": 0, "capped_score": 0, "deduplication_adjustments": 0},
            "contributing_indicators": [],
            "recommendations": ["Ensure you submit a valid HTTP or HTTPS web address for inspection."],
            "limitations": LIMITATIONS_NOTICE
        }

    # If the URL analysis failed or input was non-URL
    if not url_analysis.get("valid", False):
        err = url_analysis.get("error_code", "INVALID_INPUT")
        msg = url_analysis.get("message", "Unable to analyze URL structure.")
        return {
            "score": None,
            "risk_level": "inconclusive",
            "summary": f"Scoring is inconclusive: {msg}",
            "score_breakdown": {"raw_total": 0, "capped_score": 0, "deduplication_adjustments": 0},
            "contributing_indicators": [],
            "recommendations": ["Submit a valid HTTP or HTTPS web address to obtain a risk assessment."],
            "limitations": LIMITATIONS_NOTICE
        }

    raw_indicators = url_analysis.get("indicators", [])

    # 1. Deduplicate identical indicators to prevent artificial score inflation
    seen_ids = set()
    deduped_indicators = []
    for ind in raw_indicators:
        ind_id = ind.get("id")
        if ind_id and ind_id not in seen_ids:
            seen_ids.add(ind_id)
            deduped_indicators.append(ind)

    # 2. Weighted scoring and related-group aggregation
    # If multiple indicators belong to the same related group (e.g., brand in subdomain + typosquat),
    # we apply full weight to the highest indicator in the group and 50% discount to secondary indicators
    group_counts: Dict[str, int] = {}
    contributing_indicators: List[Dict[str, Any]] = []
    raw_total = 0
    discount_total = 0

    for ind in deduped_indicators:
        ind_id = ind.get("id")
        sev = ind.get("severity", "info").lower()
        base_weight = SEVERITY_WEIGHTS.get(sev, 0)

        # Check if indicator belongs to a grouped family
        applied_weight = base_weight
        assigned_group = None
        for group_name, members in RELATED_GROUPS.items():
            if ind_id in members:
                assigned_group = group_name
                break

        if assigned_group:
            group_counts[assigned_group] = group_counts.get(assigned_group, 0) + 1
            if group_counts[assigned_group] > 1:
                # Secondary correlated indicator receives discounted weight
                discounted = int(round(base_weight * 0.5))
                discount_total += (base_weight - discounted)
                applied_weight = discounted

        raw_total += applied_weight

        # Add to contributing list (only if it contributes > 0 points or provides key context)
        contributing_indicators.append({
            "id": ind_id,
            "title": ind.get("title", ""),
            "explanation": ind.get("explanation", ""),
            "severity": sev,
            "weight": applied_weight,
            "evidence": ind.get("evidence", "")
        })

    # 3. Cap score at 100
    final_score = min(100, max(0, raw_total))
    risk_level = get_risk_category(final_score)

    # 4. Generate dynamic, relevant recommendations grouped by category
    raw_recs: List[str] = []
    for ind in contributing_indicators:
        rec = INDICATOR_RECOMMENDATIONS.get(ind["id"])
        if rec and rec not in raw_recs:
            raw_recs.append(rec)

    if not raw_recs:
        raw_recs = list(DEFAULT_CLEAN_RECOMMENDATIONS)

    # Structure into user-friendly groups (What to check, What to avoid, Next step)
    what_to_check = [r for r in raw_recs if "Check" in r or "Verify" in r or "Inspect" in r or "Examine" in r]
    what_to_avoid = [r for r in raw_recs if "Never" in r or "Do not" in r or "Avoid" in r or "Beware" in r]
    
    if not what_to_check:
        what_to_check.append("Verify that the root domain accurately matches your intended destination.")
    if not what_to_avoid:
        what_to_avoid.append("Avoid entering sensitive passwords, OTPs, or financial details unless authenticity is verified.")

    if final_score >= 80:
        recommended_next_step = "Do not open this link or proceed to this destination. If received from an unexpected source or physical sign, report the QR code."
    elif final_score >= 50:
        recommended_next_step = "Proceed with high caution. Independently confirm the destination URL with the authentic organization before interacting."
    elif final_score >= 20:
        recommended_next_step = "Exercise standard caution. Review the root domain carefully before typing any credentials or making payments."
    else:
        recommended_next_step = "Standard web destination. You may proceed, while maintaining ordinary web safety precautions."

    # 5. Formulate concise summary
    count = len([i for i in contributing_indicators if i["weight"] > 0])
    if count == 0:
        summary = (
            "No configured suspicious indicators were detected by the static rules. "
            "The link exhibits standard web formatting, but always verify the domain before interacting."
        )
    elif final_score >= 80:
        summary = (
            f"Critical risk level ({final_score}/100) based on {count} significant suspicious indicator(s). "
            "Avoid interacting with this destination or submitting credentials."
        )
    elif final_score >= 50:
        summary = (
            f"High risk level ({final_score}/100) with {count} notable indicator(s). "
            "Significant caution is advised before following or trusting this destination."
        )
    elif final_score >= 20:
        summary = (
            f"Medium risk level ({final_score}/100) with {count} contextual indicator(s). "
            "Exercise caution and double-check the destination host."
        )
    else:
        summary = (
            f"Low detected risk ({final_score}/100). "
            "Only minimal or weak indicators were detected by the configured heuristic rules."
        )

    return {
        "score": final_score,
        "risk_level": risk_level,
        "summary": summary,
        "score_breakdown": {
            "raw_total": raw_total,
            "capped_score": final_score,
            "deduplication_adjustments": discount_total
        },
        "contributing_indicators": contributing_indicators,
        "recommendations": raw_recs,
        "grouped_recommendations": {
            "what_to_check": what_to_check,
            "what_to_avoid": what_to_avoid,
            "recommended_next_step": recommended_next_step
        },
        "limitations": LIMITATIONS_NOTICE
    }
