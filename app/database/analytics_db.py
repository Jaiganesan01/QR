"""
QShield Analytics Database Aggregator
Provides privacy-preserving, parameterized analytics queries, trend comparisons,
activity timeline bucketing, and indicator aggregations over scan history.
Strictly adheres to Privacy-by-Design: operates solely on stored metadata,
never processes or retains raw decoded payloads or sensitive URL tokens.
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple
import sqlite3

from app.database.db_manager import get_db

# Known structured indicators catalogue with educational descriptions
INDICATOR_METADATA = {
    "URL_RAW_IP_HOST": {
        "name": "Raw IP Host Destination",
        "category": "structural",
        "severity": "high",
        "description": "Destination uses a numeric IP address instead of a standard domain name, often evading domain reputation filters."
    },
    "URL_PUNYCODE_HOST": {
        "name": "Punycode / IDN Homograph Host",
        "category": "structural",
        "severity": "high",
        "description": "Hostname utilizes Internationalized Domain Name (Punycode) characters that can visually spoof trusted brand names."
    },
    "URL_BRAND_IN_SUBDOMAIN": {
        "name": "Brand Mimicry in Subdomain",
        "category": "structural",
        "severity": "high",
        "description": "Subdomain contains a recognized financial or tech brand name while pointing to an unrelated registered root domain."
    },
    "URL_NON_STANDARD_PORT": {
        "name": "Non-Standard Web Port",
        "category": "structural",
        "severity": "medium",
        "description": "Web request connects to an unusual TCP port outside standard HTTP/HTTPS ports (80, 443, 8080, 8443)."
    },
    "URL_SHORTENER_DOMAIN": {
        "name": "URL Shortener Service",
        "category": "structural",
        "severity": "medium",
        "description": "Destination conceals its true endpoint behind a shortening service (e.g., bit.ly, tinyurl), preventing pre-scan inspection."
    },
    "URL_CREDENTIAL_KEYWORDS_IN_PATH": {
        "name": "Credential & Login Keywords in Path",
        "category": "structural",
        "severity": "medium",
        "description": "URL path contains authentication tokens or keywords (login, verify, secure, update) on unverified domains."
    },
    "URL_USERINFO_EMBEDDED": {
        "name": "Inline Userinfo Credentials",
        "category": "structural",
        "severity": "critical",
        "description": "URL embeds credentials or deception tokens before an @ symbol, obscuring the true authority host."
    },
    "URL_UNENCRYPTED_HTTP": {
        "name": "Cleartext HTTP Protocol",
        "category": "structural",
        "severity": "medium",
        "description": "Destination relies on unencrypted HTTP, leaving communications vulnerable to interception and tampering."
    },
    "URL_SUSPICIOUS_STRUCTURE": {
        "name": "Excessive Subdomains or Structural Bloat",
        "category": "structural",
        "severity": "low",
        "description": "URL exhibits deeply nested subdomains or unusual lexical structure atypical of legitimate portals."
    },
    "URL_HIGH_ENTROPY": {
        "name": "High Information Entropy",
        "category": "structural",
        "severity": "medium",
        "description": "Path or query parameters exhibit elevated Shannon entropy, characteristic of packed, encrypted, or randomized tokens."
    },
    "URL_OPEN_REDIRECT_PARAM": {
        "name": "Open Redirect Parameter",
        "category": "structural",
        "severity": "medium",
        "description": "Query parameters contain redirection targets (e.g. redirect_to, next_url) susceptible to open bounce attacks."
    },
    "THREAT_INTEL_FLAGGED": {
        "name": "External Threat Intelligence Flag",
        "category": "external_confirmed",
        "severity": "critical",
        "description": "Domain or URL has been explicitly flagged as malicious or phishing by external threat intelligence feeds."
    }
}


def _parse_time_range(
    time_range: str = '7d',
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> Tuple[Optional[datetime], Optional[datetime], str]:
    """
    Parses and validates time range specifications into UTC datetime bounds.
    Supported shortcuts: '24h', '7d', '30d', 'all'.
    """
    now = datetime.now(timezone.utc)
    tr = (time_range or '7d').lower().strip()

    if tr == '24h':
        return now - timedelta(hours=24), now, 'last_24_hours'
    elif tr == '7d':
        return now - timedelta(days=7), now, 'last_7_days'
    elif tr == '30d':
        return now - timedelta(days=30), now, 'last_30_days'
    elif tr == 'all':
        return None, now, 'all_time'

    # Custom date parsing if supplied
    s_dt = None
    e_dt = now
    if start_date:
        try:
            s_str = start_date.strip().split('T')[0]
            s_dt = datetime.strptime(s_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            s_dt = now - timedelta(days=7)

    if end_date:
        try:
            e_str = end_date.strip().split('T')[0]
            # End of specified day
            e_dt = datetime.strptime(e_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        except (ValueError, TypeError):
            e_dt = now

    return s_dt, e_dt, 'custom_range'


def _build_where_clause(
    start_dt: Optional[datetime] = None,
    end_dt: Optional[datetime] = None,
    risk_level: Optional[str] = None,
    payload_type: Optional[str] = None,
    detection_method: Optional[str] = None,
    status: Optional[str] = None
) -> Tuple[str, List[Any]]:
    """
    Constructs a parameterized WHERE clause for scan_history queries.
    Strictly uses '?' parameter placeholders to prevent SQL injection.
    """
    clauses = ["1=1"]
    params: List[Any] = []

    if start_dt:
        clauses.append("created_at >= ?")
        params.append(start_dt.strftime('%Y-%m-%d %H:%M:%S'))

    if end_dt:
        clauses.append("created_at <= ?")
        params.append(end_dt.strftime('%Y-%m-%d %H:%M:%S'))

    if risk_level and isinstance(risk_level, str) and risk_level.lower() != 'all':
        rl = risk_level.strip().lower()
        if rl in ('low', 'medium', 'high', 'critical', 'inconclusive'):
            clauses.append("LOWER(COALESCE(risk_level, 'inconclusive')) = ?")
            params.append(rl)

    if payload_type and isinstance(payload_type, str) and payload_type.lower() != 'all':
        clauses.append("payload_type = ?")
        params.append(payload_type.strip())

    if detection_method and isinstance(detection_method, str) and detection_method.lower() != 'all':
        clauses.append("LOWER(COALESCE(detection_method, 'heuristic_rules')) = ?")
        params.append(detection_method.strip().lower())

    if status and isinstance(status, str) and status.lower() != 'all':
        clauses.append("LOWER(status) = ?")
        params.append(status.strip().lower())

    return " AND ".join(clauses), params


def get_analytics_summary(
    time_range: str = '7d',
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    risk_level: Optional[str] = None,
    payload_type: Optional[str] = None,
    detection_method: Optional[str] = None,
    status: Optional[str] = None
) -> Dict[str, Any]:
    """
    Computes high-level KPI summary cards from actual database records.
    Handles empty databases, zero records, and division-by-zero safely.
    """
    start_dt, end_dt, tr_label = _parse_time_range(time_range, start_date, end_date)
    where_sql, params = _build_where_clause(
        start_dt, end_dt, risk_level, payload_type, detection_method, status
    )

    db = get_db()
    cursor = db.cursor()

    # Total scans in range
    cursor.execute(f"SELECT COUNT(*) AS total FROM scan_history WHERE {where_sql}", params)
    total_scans = cursor.fetchone()["total"]

    # Scans by risk classifications
    cursor.execute(
        f"""
        SELECT 
            SUM(CASE WHEN LOWER(COALESCE(risk_level, '')) = 'high' THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN LOWER(COALESCE(risk_level, '')) = 'critical' THEN 1 ELSE 0 END) AS crit_count,
            SUM(CASE WHEN LOWER(COALESCE(risk_level, '')) = 'low' THEN 1 ELSE 0 END) AS low_count,
            SUM(CASE WHEN LOWER(COALESCE(risk_level, '')) = 'medium' THEN 1 ELSE 0 END) AS med_count,
            SUM(CASE WHEN LOWER(COALESCE(risk_level, 'inconclusive')) = 'inconclusive' 
                          OR LOWER(status) = 'inconclusive' THEN 1 ELSE 0 END) AS inconclusive_count,
            COUNT(risk_score) AS scored_count,
            AVG(risk_score) AS avg_score
        FROM scan_history
        WHERE {where_sql}
        """,
        params
    )
    risk_row = cursor.fetchone()

    high_scans = risk_row["high_count"] or 0
    critical_scans = risk_row["crit_count"] or 0
    high_or_critical = high_scans + critical_scans
    low_scans = risk_row["low_count"] or 0
    med_scans = risk_row["med_count"] or 0
    inconclusive_scans = risk_row["inconclusive_count"] or 0
    scored_scans = risk_row["scored_count"] or 0
    avg_score = round(risk_row["avg_score"], 1) if risk_row["avg_score"] is not None else None

    # External threat intelligence detections (only genuine matches)
    cursor.execute(
        f"""
        SELECT COUNT(*) AS flagged_count
        FROM scan_history
        WHERE {where_sql} AND LOWER(COALESCE(threat_intel_status, '')) = 'flagged'
        """,
        params
    )
    threat_flagged = cursor.fetchone()["flagged_count"]

    return {
        "time_range": tr_label,
        "period_start": start_dt.isoformat() if start_dt else None,
        "period_end": end_dt.isoformat() if end_dt else None,
        "total_scans": total_scans,
        "high_risk_scans": high_scans,
        "critical_risk_scans": critical_scans,
        "high_or_critical_scans": high_or_critical,
        "inconclusive_scans": inconclusive_scans,
        "low_risk_scans": low_scans,
        "medium_risk_scans": med_scans,
        "scored_scans": scored_scans,
        "avg_risk_score": avg_score,
        "external_threat_detections": threat_flagged,
        "is_empty": (total_scans == 0)
    }


def get_risk_distribution(
    time_range: str = '7d',
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    payload_type: Optional[str] = None,
    detection_method: Optional[str] = None,
    status: Optional[str] = None
) -> Dict[str, Any]:
    """
    Computes exact risk level counts and percentages adhering to standard QShield thresholds:
    Low (0-19), Medium (20-49), High (50-79), Critical (80-100), Inconclusive.
    """
    start_dt, end_dt, tr_label = _parse_time_range(time_range, start_date, end_date)
    where_sql, params = _build_where_clause(
        start_dt, end_dt, None, payload_type, detection_method, status
    )

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        f"""
        SELECT LOWER(COALESCE(risk_level, 'inconclusive')) AS lvl, COUNT(*) AS count
        FROM scan_history
        WHERE {where_sql}
        GROUP BY lvl
        """,
        params
    )
    raw_counts = {row["lvl"]: row["count"] for row in cursor.fetchall()}

    total = sum(raw_counts.values())

    categories = [
        {
            "id": "low",
            "name": "Low Risk",
            "score_range": "0 – 19",
            "count": raw_counts.get("low", 0),
            "percentage": round((raw_counts.get("low", 0) / total * 100), 1) if total > 0 else 0.0,
            "color": "#22c55e",
            "description": "Standard structure; no anomalous phishing indicators detected."
        },
        {
            "id": "medium",
            "name": "Medium Risk",
            "score_range": "20 – 49",
            "count": raw_counts.get("medium", 0),
            "percentage": round((raw_counts.get("medium", 0) / total * 100), 1) if total > 0 else 0.0,
            "color": "#f59e0b",
            "description": "Minor structural anomalies present (e.g. shortener, non-standard port)."
        },
        {
            "id": "high",
            "name": "High Risk",
            "score_range": "50 – 79",
            "count": raw_counts.get("high", 0),
            "percentage": round((raw_counts.get("high", 0) / total * 100), 1) if total > 0 else 0.0,
            "color": "#ef4444",
            "description": "Strong deceptive indicators (e.g. brand in subdomain, IP host, credentials)."
        },
        {
            "id": "critical",
            "name": "Critical Risk",
            "score_range": "80 – 100",
            "count": raw_counts.get("critical", 0),
            "percentage": round((raw_counts.get("critical", 0) / total * 100), 1) if total > 0 else 0.0,
            "color": "#7f1d1d",
            "description": "Severe credential-harvesting markers or confirmed threat feed flag."
        },
        {
            "id": "inconclusive",
            "name": "Inconclusive / Other",
            "score_range": "N/A",
            "count": raw_counts.get("inconclusive", 0),
            "percentage": round((raw_counts.get("inconclusive", 0) / total * 100), 1) if total > 0 else 0.0,
            "color": "#6b7280",
            "description": "Non-URL payloads (vCard, Wi-Fi) or unparseable inputs."
        }
    ]

    return {
        "time_range": tr_label,
        "total_scans": total,
        "is_empty": (total == 0),
        "distribution": categories
    }


def get_activity_timeline(
    time_range: str = '7d',
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    risk_level: Optional[str] = None,
    payload_type: Optional[str] = None,
    detection_method: Optional[str] = None,
    status: Optional[str] = None
) -> Dict[str, Any]:
    """
    Computes time-bucketed scan activity counts using SQLite datetime formatting.
    Pads empty buckets so timeline is smooth and continuous.
    - '24h': 24 hourly buckets
    - '7d' & '30d': Daily buckets
    - 'all': Daily buckets or monthly if wide
    """
    start_dt, end_dt, tr_label = _parse_time_range(time_range, start_date, end_date)
    where_sql, params = _build_where_clause(
        start_dt, end_dt, risk_level, payload_type, detection_method, status
    )

    db = get_db()
    cursor = db.cursor()

    is_hourly = (tr_label == 'last_24_hours')

    if is_hourly:
        # Group by YYYY-MM-DD HH:00
        sql = f"""
            SELECT 
                strftime('%Y-%m-%d %H:00', created_at) AS bucket,
                COUNT(*) AS total_count,
                SUM(CASE WHEN LOWER(COALESCE(risk_level, '')) IN ('high', 'critical') THEN 1 ELSE 0 END) AS high_or_critical,
                SUM(CASE WHEN LOWER(COALESCE(risk_level, 'inconclusive')) = 'inconclusive' THEN 1 ELSE 0 END) AS inconclusive
            FROM scan_history
            WHERE {where_sql}
            GROUP BY bucket
            ORDER BY bucket ASC
        """
    else:
        # Group by YYYY-MM-DD
        sql = f"""
            SELECT 
                strftime('%Y-%m-%d', created_at) AS bucket,
                COUNT(*) AS total_count,
                SUM(CASE WHEN LOWER(COALESCE(risk_level, '')) IN ('high', 'critical') THEN 1 ELSE 0 END) AS high_or_critical,
                SUM(CASE WHEN LOWER(COALESCE(risk_level, 'inconclusive')) = 'inconclusive' THEN 1 ELSE 0 END) AS inconclusive
            FROM scan_history
            WHERE {where_sql}
            GROUP BY bucket
            ORDER BY bucket ASC
        """

    cursor.execute(sql, params)
    rows = cursor.fetchall()
    raw_map = {row["bucket"]: row for row in rows}

    # Generate complete bucket sequence to prevent gaps
    timeline: List[Dict[str, Any]] = []
    
    if start_dt and end_dt:
        cur = start_dt
        if is_hourly:
            # 24 hour sequence
            while cur <= end_dt:
                b_key = cur.strftime('%Y-%m-%d %H:00')
                label = cur.strftime('%H:00')
                row = raw_map.get(b_key)
                timeline.append({
                    "bucket": b_key,
                    "label": label,
                    "total": row["total_count"] if row else 0,
                    "high_or_critical": row["high_or_critical"] if row else 0,
                    "inconclusive": row["inconclusive"] if row else 0
                })
                cur += timedelta(hours=1)
        else:
            # Day sequence
            while cur.date() <= end_dt.date():
                b_key = cur.strftime('%Y-%m-%d')
                label = cur.strftime('%b %d')
                row = raw_map.get(b_key)
                timeline.append({
                    "bucket": b_key,
                    "label": label,
                    "total": row["total_count"] if row else 0,
                    "high_or_critical": row["high_or_critical"] if row else 0,
                    "inconclusive": row["inconclusive"] if row else 0
                })
                cur += timedelta(days=1)
    else:
        # All time: use query rows directly
        for row in rows:
            b_key = row["bucket"]
            timeline.append({
                "bucket": b_key,
                "label": b_key,
                "total": row["total_count"],
                "high_or_critical": row["high_or_critical"],
                "inconclusive": row["inconclusive"]
            })

    total_scans = sum(item["total"] for item in timeline)

    return {
        "time_range": tr_label,
        "interval": "hour" if is_hourly else "day",
        "total_scans": total_scans,
        "is_empty": (total_scans == 0),
        "timeline": timeline
    }


def get_payload_categories(
    time_range: str = '7d',
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    risk_level: Optional[str] = None,
    detection_method: Optional[str] = None,
    status: Optional[str] = None
) -> Dict[str, Any]:
    """
    Computes distribution across payload formats (URL, Plain Text, Wi-Fi, vCard, Payment, etc.).
    Preserves strict privacy: never exposes raw decoded payloads.
    """
    start_dt, end_dt, tr_label = _parse_time_range(time_range, start_date, end_date)
    where_sql, params = _build_where_clause(
        start_dt, end_dt, risk_level, None, detection_method, status
    )

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        f"""
        SELECT payload_type, COUNT(*) AS count
        FROM scan_history
        WHERE {where_sql}
        GROUP BY payload_type
        ORDER BY count DESC
        """,
        params
    )
    rows = cursor.fetchall()
    total = sum(row["count"] for row in rows)

    categories = [
        {
            "category": row["payload_type"],
            "count": row["count"],
            "percentage": round((row["count"] / total * 100), 1) if total > 0 else 0.0
        }
        for row in rows
    ]

    return {
        "time_range": tr_label,
        "total_scans": total,
        "is_empty": (total == 0),
        "categories": categories
    }


def get_detection_methods(
    time_range: str = '7d',
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    risk_level: Optional[str] = None,
    payload_type: Optional[str] = None,
    status: Optional[str] = None
) -> Dict[str, Any]:
    """
    Computes breakdown of execution methods actually invoked.
    Distinguishes local rule heuristics, ML inference, and external reputation lookups.
    """
    start_dt, end_dt, tr_label = _parse_time_range(time_range, start_date, end_date)
    where_sql, params = _build_where_clause(
        start_dt, end_dt, risk_level, payload_type, None, status
    )

    db = get_db()
    cursor = db.cursor()

    # Query counts by detection_method column
    cursor.execute(
        f"""
        SELECT LOWER(COALESCE(detection_method, 'heuristic_rules')) AS method, COUNT(*) AS count
        FROM scan_history
        WHERE {where_sql}
        GROUP BY method
        ORDER BY count DESC
        """,
        params
    )
    rows = cursor.fetchall()
    method_counts = {row["method"]: row["count"] for row in rows}

    # Query threat intelligence checks executed
    cursor.execute(
        f"""
        SELECT 
            SUM(CASE WHEN LOWER(COALESCE(threat_intel_status, 'not_requested')) != 'not_requested' THEN 1 ELSE 0 END) AS executed_threat_checks,
            SUM(CASE WHEN LOWER(COALESCE(threat_intel_status, '')) = 'flagged' THEN 1 ELSE 0 END) AS flagged_threat_checks
        FROM scan_history
        WHERE {where_sql}
        """,
        params
    )
    threat_row = cursor.fetchone()
    threat_executed = threat_row["executed_threat_checks"] or 0
    threat_flagged = threat_row["flagged_threat_checks"] or 0

    total = sum(method_counts.values())

    methods = [
        {
            "id": "heuristic_rules",
            "name": "Deterministic Heuristic Rules",
            "count": method_counts.get("heuristic_rules", 0),
            "percentage": round((method_counts.get("heuristic_rules", 0) / total * 100), 1) if total > 0 else 0.0,
            "description": "Evaluated using offline structural and lexical rule heuristics."
        },
        {
            "id": "ml_inference",
            "name": "Machine Learning Classifier",
            "count": method_counts.get("ml_inference", 0),
            "percentage": round((method_counts.get("ml_inference", 0) / total * 100), 1) if total > 0 else 0.0,
            "description": "Evaluated using trained scikit-learn model artifact."
        },
        {
            "id": "ensemble",
            "name": "Modular Intelligence Ensemble",
            "count": method_counts.get("ensemble", 0),
            "percentage": round((method_counts.get("ensemble", 0) / total * 100), 1) if total > 0 else 0.0,
            "description": "Evaluated combining heuristics, ML adapter, and payload features."
        },
        {
            "id": "inconclusive",
            "name": "Non-URL / Inconclusive",
            "count": method_counts.get("inconclusive", 0),
            "percentage": round((method_counts.get("inconclusive", 0) / total * 100), 1) if total > 0 else 0.0,
            "description": "Payloads not requiring URL structural heuristics."
        }
    ]

    return {
        "time_range": tr_label,
        "total_scans": total,
        "is_empty": (total == 0),
        "methods": methods,
        "external_reputation_checks": {
            "total_performed": threat_executed,
            "flagged_matches": threat_flagged,
            "clean_or_neutral": max(0, threat_executed - threat_flagged)
        }
    }


def get_observed_indicators(
    time_range: str = '7d',
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    risk_level: Optional[str] = None,
    payload_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Summarizes observed structural and external threat indicators across scan records.
    Counts unique scans exhibiting each indicator to avoid double-counting within a single scan.
    Returns educational descriptions explaining that indicators are risk evidence, not proof.
    """
    start_dt, end_dt, tr_label = _parse_time_range(time_range, start_date, end_date)
    where_sql, params = _build_where_clause(
        start_dt, end_dt, risk_level, payload_type, None, None
    )

    db = get_db()
    cursor = db.cursor()

    # Query all indicators_summary from records in range
    cursor.execute(
        f"""
        SELECT indicators_summary, threat_intel_status
        FROM scan_history
        WHERE {where_sql} AND (indicators_summary != '' OR threat_intel_status = 'flagged')
        """,
        params
    )
    rows = cursor.fetchall()

    # Total scans in range for percentage calculation
    cursor.execute(f"SELECT COUNT(*) AS total FROM scan_history WHERE {where_sql}", params)
    total_scans = cursor.fetchone()["total"]

    indicator_counts: Dict[str, int] = {}

    for row in rows:
        tokens_str = row["indicators_summary"] or ""
        tokens = {t.strip() for t in tokens_str.split(",") if t.strip()}
        
        # If threat intelligence flagged, include THREAT_INTEL_FLAGGED
        if (row["threat_intel_status"] or "").lower() == "flagged":
            tokens.add("THREAT_INTEL_FLAGGED")

        for token in tokens:
            indicator_counts[token] = indicator_counts.get(token, 0) + 1

    indicators_list: List[Dict[str, Any]] = []

    # Process known catalogue first
    for ind_id, meta in INDICATOR_METADATA.items():
        count = indicator_counts.pop(ind_id, 0)
        pct = round((count / total_scans * 100), 1) if total_scans > 0 else 0.0
        indicators_list.append({
            "id": ind_id,
            "name": meta["name"],
            "category": meta["category"],
            "severity": meta["severity"],
            "count": count,
            "percentage": pct,
            "description": meta["description"]
        })

    # Include any custom/unlisted tokens
    for token, count in indicator_counts.items():
        pct = round((count / total_scans * 100), 1) if total_scans > 0 else 0.0
        indicators_list.append({
            "id": token,
            "name": token.replace("URL_", "").replace("_", " ").title(),
            "category": "structural",
            "severity": "medium",
            "count": count,
            "percentage": pct,
            "description": f"Custom structural indicator '{token}' observed during analysis."
        })

    # Sort by count DESC
    indicators_list.sort(key=lambda x: x["count"], reverse=True)

    return {
        "time_range": tr_label,
        "total_scans_evaluated": total_scans,
        "is_empty": (total_scans == 0),
        "total_indicators_observed": sum(i["count"] for i in indicators_list),
        "indicators": indicators_list,
        "guidance_notice": "Structural risk indicators provide observable evidence for security evaluation; an individual indicator does not constitute definitive proof of malicious intent."
    }


def get_trend_analysis(time_range: str = '7d') -> Dict[str, Any]:
    """
    Computes period-over-period trend analysis:
    Compares current selected window with the preceding equivalent period.
    - '24h': Last 24 hours vs Previous 24 hours (hours -48 to -24)
    - '7d': Last 7 days vs Previous 7 days (days -14 to -7)
    - '30d': Last 30 days vs Previous 30 days (days -60 to -30)
    Defensively protects against division-by-zero and small datasets (<5 records).
    Explicitly clarifies that trends reflect local scan activity, NOT global threat trends.
    """
    now = datetime.now(timezone.utc)
    tr = (time_range or '7d').lower().strip()

    if tr == '24h':
        delta_window = timedelta(hours=24)
        label = "Last 24 Hours vs Previous 24 Hours"
    elif tr == '30d':
        delta_window = timedelta(days=30)
        label = "Last 30 Days vs Previous 30 Days"
    else:  # default '7d'
        delta_window = timedelta(days=7)
        label = "Last 7 Days vs Previous 7 Days"

    cur_start = now - delta_window
    cur_end = now
    prev_start = cur_start - delta_window
    prev_end = cur_start

    db = get_db()
    cursor = db.cursor()

    def _query_period(start: datetime, end: datetime) -> Dict[str, Any]:
        cursor.execute(
            """
            SELECT 
                COUNT(*) AS total,
                SUM(CASE WHEN LOWER(COALESCE(risk_level, '')) IN ('high', 'critical') THEN 1 ELSE 0 END) AS high_or_critical,
                SUM(CASE WHEN LOWER(COALESCE(risk_level, 'inconclusive')) = 'inconclusive' 
                              OR LOWER(status) = 'inconclusive' THEN 1 ELSE 0 END) AS inconclusive,
                COUNT(risk_score) AS scored_count,
                AVG(risk_score) AS avg_score
            FROM scan_history
            WHERE created_at >= ? AND created_at <= ?
            """,
            (start.strftime('%Y-%m-%d %H:%M:%S'), end.strftime('%Y-%m-%d %H:%M:%S'))
        )
        r = cursor.fetchone()
        return {
            "total": r["total"] or 0,
            "high_or_critical": r["high_or_critical"] or 0,
            "inconclusive": r["inconclusive"] or 0,
            "scored_count": r["scored_count"] or 0,
            "avg_score": round(r["avg_score"], 1) if r["avg_score"] is not None else None
        }

    current = _query_period(cur_start, cur_end)
    previous = _query_period(prev_start, prev_end)

    combined_total = current["total"] + previous["total"]

    # Trend calculations with division by zero safety
    def _compute_delta(cur_val: int | float | None, prev_val: int | float | None) -> Dict[str, Any]:
        if cur_val is None or prev_val is None:
            if cur_val is not None and prev_val is None:
                return {"absolute_change": cur_val, "percentage_change": None, "direction": "up"}
            return {"absolute_change": 0, "percentage_change": None, "direction": "flat"}

        abs_diff = round(cur_val - prev_val, 1)
        direction = "up" if abs_diff > 0 else ("down" if abs_diff < 0 else "flat")
        
        pct_change = None
        if prev_val > 0:
            pct_change = round(((cur_val - prev_val) / prev_val) * 100, 1)

        return {
            "absolute_change": abs_diff,
            "percentage_change": pct_change,
            "direction": direction
        }

    scans_trend = _compute_delta(current["total"], previous["total"])
    threat_trend = _compute_delta(current["high_or_critical"], previous["high_or_critical"])
    inconclusive_trend = _compute_delta(current["inconclusive"], previous["inconclusive"])
    score_trend = _compute_delta(current["avg_score"], previous["avg_score"])

    # Small dataset safeguard
    has_sufficient_data = (combined_total >= 5 and current["total"] >= 2)
    summary_message = "Trends reflect shifts in local scanning patterns between observed periods."
    if not has_sufficient_data:
        summary_message = "Not enough data to identify a trend."

    return {
        "period_label": label,
        "current_period": {
            "start": cur_start.isoformat(),
            "end": cur_end.isoformat(),
            "total_scans": current["total"],
            "high_or_critical_scans": current["high_or_critical"],
            "inconclusive_scans": current["inconclusive"],
            "avg_risk_score": current["avg_score"]
        },
        "previous_period": {
            "start": prev_start.isoformat(),
            "end": prev_end.isoformat(),
            "total_scans": previous["total"],
            "high_or_critical_scans": previous["high_or_critical"],
            "inconclusive_scans": previous["inconclusive"],
            "avg_risk_score": previous["avg_score"]
        },
        "metrics": {
            "total_scans": scans_trend,
            "high_or_critical_scans": threat_trend,
            "inconclusive_scans": inconclusive_trend,
            "avg_risk_score": score_trend
        },
        "has_sufficient_data": has_sufficient_data,
        "summary_message": summary_message,
        "disclaimer": "Local scan activity only; does not represent global cyber threat patterns."
    }
