"""
QShield Database Package
"""
from app.database.db_manager import (
    get_db,
    close_db,
    init_db,
    record_scan,
    update_scan_threat_intel,
    get_scan_history,
    get_scan_history_count,
    get_scan_by_id,
    delete_scan,
    get_admin_metrics
)
from app.database.analytics_db import (
    get_analytics_summary,
    get_risk_distribution,
    get_activity_timeline,
    get_payload_categories,
    get_detection_methods,
    get_observed_indicators,
    get_trend_analysis,
    INDICATOR_METADATA
)

__all__ = [
    'get_db',
    'close_db',
    'init_db',
    'record_scan',
    'update_scan_threat_intel',
    'get_scan_history',
    'get_scan_history_count',
    'get_scan_by_id',
    'delete_scan',
    'get_admin_metrics',
    'get_analytics_summary',
    'get_risk_distribution',
    'get_activity_timeline',
    'get_payload_categories',
    'get_detection_methods',
    'get_observed_indicators',
    'get_trend_analysis',
    'INDICATOR_METADATA'
]
