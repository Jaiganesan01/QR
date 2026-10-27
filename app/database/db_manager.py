"""
QShield Database Manager
Provides safe, parameterized SQLite connection handling, lifecycle management,
and scan metadata persistence following privacy-by-design principles.
"""
import sqlite3
import os
from pathlib import Path
from datetime import datetime, timezone
from flask import g, current_app

SCHEMA_PATH = Path(__file__).resolve().parent / 'schema.sql'


def get_db():
    """
    Get or create an active SQLite database connection for the current Flask application context.
    Configures row_factory for dict-like access and enforces foreign keys.
    """
    if 'db' not in g:
        db_path = current_app.config.get('DATABASE_PATH')
        if not db_path:
            db_path = os.path.join(current_app.instance_path, 'qshield.db')
        
        # In testing mode with ':memory:', create a URI shared memory database or test file so connections persist across test client requests within the app life
        if current_app.config.get('TESTING') and db_path == ':memory:':
            db_path = 'file:qshield_test_db?mode=memory&cache=shared'
            # Keep a persistent connection on the app instance so the shared memory database is not wiped when g.db closes after a request
            if not hasattr(current_app, '_persistent_memory_db'):
                current_app._persistent_memory_db = sqlite3.connect(db_path, uri=True)

        # Ensure parent directory exists for file-based DBs
        if not db_path.startswith('file:') and db_path != ':memory:':
            parent_dir = os.path.dirname(db_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
                
        g.db = sqlite3.connect(
            db_path,
            uri=db_path.startswith('file:')
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")

        # Automatically ensure schema is loaded and migrated idempotently
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
            g.db.executescript(f.read())
        _migrate_schema_if_needed(g.db)
        g.db.commit()
    
    return g.db


def _migrate_schema_if_needed(db: sqlite3.Connection):
    """
    Ensures scan_history contains telemetry columns and indexes idempotently.
    Safely migrates existing databases without dropping tables or losing historical records.
    """
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(scan_history)")
    columns = {row[1] for row in cursor.fetchall()}

    if 'detection_method' not in columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN detection_method TEXT DEFAULT 'heuristic_rules'")
    if 'threat_intel_status' not in columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN threat_intel_status TEXT DEFAULT 'not_requested'")
    if 'indicators_summary' not in columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN indicators_summary TEXT DEFAULT ''")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_detection_method ON scan_history(detection_method)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_threat_intel_status ON scan_history(threat_intel_status)")


def close_db(e=None):
    """
    Close the database connection if open at the end of the request context.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(app=None):
    """
    Initialize SQLite database tables from schema.sql idempotently.
    Can be called with an app instance or within an existing app context.
    """
    def _run_init():
        db = get_db()
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
            db.executescript(f.read())
        db.commit()

    if app is not None:
        with app.app_context():
            _run_init()
    else:
        _run_init()


def record_scan(
    scan_type: str,
    payload_type: str,
    target_domain: str | None = None,
    risk_score: int | None = None,
    risk_level: str | None = None,
    indicator_count: int = 0,
    status: str = 'completed',
    detection_method: str = 'heuristic_rules',
    threat_intel_status: str = 'not_requested',
    indicators: list | None = None
) -> int:
    """
    Persist privacy-preserving scan metadata.
    NEVER records raw payloads, passwords, full query parameters, or binary images.
    Returns the newly inserted record ID.
    """
    # Normalize inputs
    if scan_type == 'camera':
        scan_type = 'upload'
    elif scan_type not in ('upload', 'manual', 'unknown'):
        scan_type = 'unknown'
        
    if status not in ('completed', 'failed', 'inconclusive'):
        status = 'completed' if risk_score is not None else 'inconclusive'

    # Normalize indicators list to clean token string
    indicators_str = ""
    if indicators:
        tokens = []
        for item in indicators:
            if isinstance(item, dict):
                tid = item.get('id') or item.get('rule_id') or ''
                if tid:
                    tokens.append(str(tid).strip())
            elif isinstance(item, str) and item.strip():
                tokens.append(item.strip())
        indicators_str = ",".join(tokens)

    # Sanitize domain: strip path/query if mistakenly passed, store only hostname or None
    sanitized_domain = None
    if target_domain and isinstance(target_domain, str):
        # Extract host only
        d = target_domain.strip().lower()
        if '://' in d:
            from urllib.parse import urlparse
            parsed = urlparse(d)
            sanitized_domain = parsed.hostname
        else:
            sanitized_domain = d.split('/')[0].split('?')[0].split('#')[0]

    db = get_db()
    cursor = db.cursor()
    try:
        now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            """
            INSERT INTO scan_history (
                scan_type, payload_type, target_domain, risk_score,
                risk_level, indicator_count, status, detection_method,
                threat_intel_status, indicators_summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_type,
                payload_type,
                sanitized_domain,
                risk_score,
                risk_level,
                indicator_count,
                status,
                detection_method or 'heuristic_rules',
                threat_intel_status or 'not_requested',
                indicators_str,
                now_utc
            )
        )
        db.commit()
        return cursor.lastrowid
    except Exception:
        db.rollback()
        raise


def update_scan_threat_intel(scan_id: int, threat_status: str, is_flagged: bool = False) -> bool:
    """
    Updates external threat intelligence status for a previously completed scan record.
    Returns True if record was found and updated, False otherwise.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        norm_status = (threat_status or 'not_requested').strip().lower()
        if is_flagged:
            norm_status = 'flagged'

        cursor.execute(
            """
            UPDATE scan_history
            SET threat_intel_status = ?
            WHERE id = ?
            """,
            (norm_status, scan_id)
        )
        db.commit()
        return cursor.rowcount > 0
    except Exception:
        db.rollback()
        raise


def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    payload_type: str | None = None,
    risk_level: str | None = None,
    status: str | None = None,
    search: str | None = None
) -> list[dict]:
    """
    Retrieve sanitized scan metadata history in reverse chronological order with optional filters.
    All filters use parameterized SQL to guarantee safe execution.
    """
    db = get_db()
    cursor = db.cursor()

    query = """
        SELECT id, scan_type, payload_type, target_domain, risk_score,
               risk_level, indicator_count, status, detection_method,
               threat_intel_status, indicators_summary, created_at
        FROM scan_history
        WHERE 1=1
    """
    params = []

    if payload_type and isinstance(payload_type, str):
        query += " AND payload_type = ?"
        params.append(payload_type.strip())

    if risk_level and isinstance(risk_level, str):
        query += " AND risk_level = ?"
        params.append(risk_level.strip().lower())

    if status and isinstance(status, str):
        query += " AND status = ?"
        params.append(status.strip().lower())

    if search and isinstance(search, str):
        s = search.strip()
        if s.isdigit():
            query += " AND (id = ? OR payload_type LIKE ? OR status LIKE ?)"
            params.extend([int(s), f"%{s}%", f"%{s}%"])
        else:
            query += " AND (payload_type LIKE ? OR status LIKE ? OR target_domain LIKE ?)"
            params.extend([f"%{s}%", f"%{s}%", f"%{s}%"])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([max(1, min(limit, 100)), max(0, offset)])

    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [
        {
            "id": row["id"],
            "scan_type": row["scan_type"],
            "payload_type": row["payload_type"],
            "target_domain": row["target_domain"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "indicator_count": row["indicator_count"],
            "status": row["status"],
            "detection_method": row["detection_method"] if "detection_method" in row.keys() else "heuristic_rules",
            "threat_intel_status": row["threat_intel_status"] if "threat_intel_status" in row.keys() else "not_requested",
            "indicators_summary": row["indicators_summary"] if "indicators_summary" in row.keys() else "",
            "created_at": str(row["created_at"])
        }
        for row in rows
    ]


def get_scan_history_count(
    payload_type: str | None = None,
    risk_level: str | None = None,
    status: str | None = None,
    search: str | None = None
) -> int:
    """
    Retrieve total count of scan history records matching optional filters.
    """
    db = get_db()
    cursor = db.cursor()

    query = "SELECT COUNT(*) AS total FROM scan_history WHERE 1=1"
    params = []

    if payload_type and isinstance(payload_type, str):
        query += " AND payload_type = ?"
        params.append(payload_type.strip())

    if risk_level and isinstance(risk_level, str):
        query += " AND risk_level = ?"
        params.append(risk_level.strip().lower())

    if status and isinstance(status, str):
        query += " AND status = ?"
        params.append(status.strip().lower())

    if search and isinstance(search, str):
        s = search.strip()
        if s.isdigit():
            query += " AND (id = ? OR payload_type LIKE ? OR status LIKE ?)"
            params.extend([int(s), f"%{s}%", f"%{s}%"])
        else:
            query += " AND (payload_type LIKE ? OR status LIKE ? OR target_domain LIKE ?)"
            params.extend([f"%{s}%", f"%{s}%", f"%{s}%"])

    cursor.execute(query, params)
    row = cursor.fetchone()
    return row["total"] if row else 0


def get_admin_metrics() -> dict:
    """
    Aggregate application-level operational statistics and health metrics
    from actual database records. Handles empty datasets and null values gracefully.
    """
    db = get_db()
    cursor = db.cursor()

    # Total recorded scans
    cursor.execute("SELECT COUNT(*) AS total FROM scan_history")
    total_scans = cursor.fetchone()["total"]

    # Scans processed today (UTC date matching created_at prefix)
    today_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    cursor.execute("SELECT COUNT(*) AS today_count FROM scan_history WHERE created_at LIKE ?", (f"{today_utc}%",))
    scans_today = cursor.fetchone()["today_count"]

    # Counts by payload category
    cursor.execute("""
        SELECT payload_type, COUNT(*) AS count
        FROM scan_history
        GROUP BY payload_type
        ORDER BY count DESC
    """)
    by_payload_type = {row["payload_type"]: row["count"] for row in cursor.fetchall()}

    # Counts by risk level (handling NULL risk_level)
    cursor.execute("""
        SELECT COALESCE(risk_level, 'inconclusive') AS rlevel, COUNT(*) AS count
        FROM scan_history
        GROUP BY rlevel
        ORDER BY count DESC
    """)
    by_risk_level = {row["rlevel"]: row["count"] for row in cursor.fetchall()}

    # Counts by processing status
    cursor.execute("""
        SELECT status, COUNT(*) AS count
        FROM scan_history
        GROUP BY status
        ORDER BY count DESC
    """)
    by_status = {row["status"]: row["count"] for row in cursor.fetchall()}

    # Risk score stats
    cursor.execute("""
        SELECT COUNT(risk_score) AS scored_count,
               AVG(risk_score) AS avg_score,
               MIN(risk_score) AS min_score,
               MAX(risk_score) AS max_score
        FROM scan_history
        WHERE risk_score IS NOT NULL
    """)
    score_stats = cursor.fetchone()
    scans_with_scores = score_stats["scored_count"] if score_stats else 0
    avg_score = round(score_stats["avg_score"], 1) if score_stats and score_stats["avg_score"] is not None else None

    # Recent activity (last 10 scans)
    recent = get_scan_history(limit=10, offset=0)

    return {
        "total_scans": total_scans,
        "scans_today": scans_today,
        "scans_with_scores": scans_with_scores,
        "avg_risk_score": avg_score,
        "by_payload_type": by_payload_type,
        "by_risk_level": by_risk_level,
        "by_status": by_status,
        "recent_activity": recent
    }


def get_scan_by_id(scan_id: int) -> dict | None:
    """
    Retrieve single sanitized scan metadata record by ID.
    Returns None if not found.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT id, scan_type, payload_type, target_domain, risk_score,
               risk_level, indicator_count, status, detection_method,
               threat_intel_status, indicators_summary, created_at
        FROM scan_history
        WHERE id = ?
        """,
        (scan_id,)
    )
    row = cursor.fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "scan_type": row["scan_type"],
        "payload_type": row["payload_type"],
        "target_domain": row["target_domain"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "indicator_count": row["indicator_count"],
        "status": row["status"],
        "detection_method": row["detection_method"] if "detection_method" in row.keys() else "heuristic_rules",
        "threat_intel_status": row["threat_intel_status"] if "threat_intel_status" in row.keys() else "not_requested",
        "indicators_summary": row["indicators_summary"] if "indicators_summary" in row.keys() else "",
        "created_at": str(row["created_at"])
    }


def delete_scan(scan_id: int) -> bool:
    """
    Delete a scan history record by ID.
    Returns True if record was found and deleted, False otherwise.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
        db.commit()
        return cursor.rowcount > 0
    except Exception:
        db.rollback()
        raise
