"""
API endpoints for QShield inspection operations.
"""
import hmac
from flask import Blueprint, request, jsonify, current_app, Response
from app.core.qr_decoder import decode_qr_image_bytes
from app.core.rate_limiter import rate_limit

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/decode-qr', methods=['POST'])
@rate_limit('RATELIMIT_DECODE', default_limit=30)
def decode_qr_endpoint():
    """
    POST /api/decode-qr
    Accepts multipart/form-data with key 'qr_file'.
    Decodes QR matrix using in-memory OpenCV decoder.
    Enforces 5MB size limit and real image content validation.
    Never executes, navigates, or follows decoded content.
    """
    # 1. Verify file or frame was provided in request
    file_bytes = None
    max_bytes = current_app.config.get('MAX_CONTENT_LENGTH', 5 * 1024 * 1024)
    scan_type = 'upload'

    if request.is_json:
        data = request.get_json() or {}
        if data.get('scan_type') in ('camera', 'upload', 'manual'):
            scan_type = data.get('scan_type')

        # Fast-path: client-side BarcodeDetector already decoded text and requests structured classification
        if 'content' in data or 'text' in data:
            raw_text = data.get('content') if 'content' in data else data.get('text')
            if not isinstance(raw_text, str):
                return jsonify({
                    "success": False,
                    "error_code": "INVALID_TEXT_PAYLOAD",
                    "message": "Payload content must be a string."
                }), 400
            
            from app.core.payload_classifier import classify_payload
            classification = classify_payload(raw_text)
            payload_type = "URL" if classification.get("payload_type") == "url" else classification.get("display_name", "Payload")

            scan_id = None
            if classification.get('payload_type') != 'url':
                try:
                    from app.database import record_scan
                    scan_id = record_scan(
                        scan_type=scan_type,
                        payload_type=payload_type,
                        target_domain=None,
                        risk_score=None,
                        risk_level='Inconclusive',
                        indicator_count=0,
                        status='completed'
                    )
                except Exception:
                    pass

            return jsonify({
                "success": True,
                "decoded_content": raw_text,
                "payload_type": payload_type,
                "classification": classification,
                "truncated": len(raw_text) > 2000,
                "scan_id": scan_id
            }), 200

        # Frame capture fallback: decode image base64
        frame_str = data.get('frame') or data.get('image_data') or data.get('qr_image')
        if not frame_str or not isinstance(frame_str, str):
            return jsonify({
                "success": False,
                "error_code": "MISSING_FRAME_DATA",
                "message": "JSON body must contain 'frame', 'image_data', or 'content' key."
            }), 400
        try:
            import base64
            if ',' in frame_str:
                frame_str = frame_str.split(',', 1)[1]
            file_bytes = base64.b64decode(frame_str)
        except Exception:
            return jsonify({
                "success": False,
                "error_code": "INVALID_BASE64",
                "message": "Malformed base64 image data received."
            }), 400
    elif 'qr_file' in request.files:
        file = request.files['qr_file']
        if not file or file.filename == '':
            return jsonify({
                "success": False,
                "error_code": "NO_FILE_SELECTED",
                "message": "No file was selected. Please choose a QR code image to inspect."
            }), 400
        file_bytes = file.read()
    else:
        return jsonify({
            "success": False,
            "error_code": "MISSING_FILE",
            "message": "No file field 'qr_file' or JSON 'frame' was found in the upload request."
        }), 400

    # 2. Enforce 5MB limit on input stream
    if file_bytes is None or len(file_bytes) == 0:
        return jsonify({
            "success": False,
            "error_code": "EMPTY_FILE",
            "message": "The uploaded file or camera frame is empty."
        }), 400

    if len(file_bytes) > max_bytes:
        return jsonify({
            "success": False,
            "error_code": "FILE_TOO_LARGE",
            "message": f"File exceeds the maximum upload limit of 5 MB ({len(file_bytes)} bytes received)."
        }), 413

    # 3. Decode in memory using OpenCV
    result = decode_qr_image_bytes(file_bytes)

    if not result["success"]:
        # Record failed decode attempt metadata (no sensitive data)
        try:
            from app.database import record_scan
            record_scan(
                scan_type=scan_type,
                payload_type='Unknown',
                target_domain=None,
                risk_score=None,
                risk_level=None,
                indicator_count=0,
                status='failed'
            )
        except Exception:
            pass  # Do not block scan response if metadata recording fails

        # Select appropriate HTTP status code based on error code
        status_code = 422 if result["error_code"] == "NO_QR_DETECTED" else 400
        return jsonify(result), status_code

    # For non-URL payloads (e.g. Plain Text, vCard), record completed metadata
    if result.get("payload_type") != "URL":
        try:
            from app.database import record_scan
            scan_id = record_scan(
                scan_type=scan_type,
                payload_type=result.get("payload_type", "Text"),
                target_domain=None,
                risk_score=None,
                risk_level='Inconclusive',
                indicator_count=0,
                status='completed'
            )
            result["scan_id"] = scan_id
        except Exception:
            pass

    return jsonify(result), 200

@api_bp.route('/analyze-url', methods=['POST'])
@rate_limit('RATELIMIT_ANALYZE', default_limit=60)
def analyze_url_endpoint():
    """
    POST /api/analyze-url
    Accepts JSON body: {"url": "https://...", "scan_type": "upload"|"manual"}
    Performs static structural heuristic analysis.
    Never fetches, follows redirects, or executes the URL.
    Persists only non-sensitive scan metadata (domain, risk_score, indicator_count).
    """
    if not request.is_json:
        return jsonify({
            "valid": False,
            "error_code": "INVALID_JSON",
            "message": "Request body must be a JSON object containing a 'url' key.",
            "parsed_url": None,
            "indicators": []
        }), 400

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({
            "valid": False,
            "error_code": "MISSING_URL_FIELD",
            "message": "Field 'url' is required in JSON payload.",
            "parsed_url": None,
            "indicators": []
        }), 400

    raw_url = data.get('url')
    if not isinstance(raw_url, str):
        return jsonify({
            "valid": False,
            "error_code": "INVALID_TYPE",
            "message": "Field 'url' must be a string.",
            "parsed_url": None,
            "indicators": []
        }), 400

    from app.core.url_analyzer import analyze_url_heuristics
    from app.core.risk_scorer import calculate_risk_score
    from app.core.detection_engine import get_detection_engine
    from datetime import datetime, timezone

    scan_type = data.get('scan_type', 'manual')
    if scan_type not in ('upload', 'manual', 'camera'):
        scan_type = 'manual'

    url_result = analyze_url_heuristics(raw_url)
    risk_assessment = calculate_risk_score(url_result)
    detection_engine = get_detection_engine()
    modular_result = detection_engine.evaluate(raw_url, scan_type=scan_type)

    # Attach modular intelligence results, risk assessment, scan timestamp, and checks metadata
    url_result["risk_assessment"] = risk_assessment
    url_result["detection_engine"] = modular_result
    url_result["timestamp"] = datetime.now(timezone.utc).isoformat()
    url_result["checks_performed"] = {
        "qr_decoding": "complete",
        "url_parsing": "complete" if url_result.get("valid") else "failed",
        "heuristic_analysis": "complete" if url_result.get("valid") else "not_applicable",
        "risk_scoring": "complete" if risk_assessment.get("score") is not None else "inconclusive",
        "external_threat_intelligence": "available_on_user_request",
        "redirect_tracing": "not_implemented_in_this_phase"
    }

    # Persist non-sensitive metadata to database
    try:
        from app.database import record_scan
        domain = None
        if url_result.get("parsed_url"):
            domain = url_result["parsed_url"].get("hostname") or url_result["parsed_url"].get("registered_domain")

        scan_id = record_scan(
            scan_type=scan_type,
            payload_type='URL',
            target_domain=domain,
            risk_score=risk_assessment.get('score'),
            risk_level=risk_assessment.get('risk_level'),
            indicator_count=len(url_result.get('indicators', [])),
            status='completed' if url_result.get('valid') else 'inconclusive',
            detection_method=modular_result.get("analysis_method", "heuristic_rules"),
            threat_intel_status="not_requested",
            indicators=url_result.get('indicators', [])
        )
        url_result["scan_id"] = scan_id
    except Exception:
        pass  # Gracefully proceed even if DB write fails

    status_code = 200 if url_result["valid"] else 400
    return jsonify(url_result), status_code


@api_bp.route('/scan-history', methods=['GET'])
def get_scan_history_endpoint():
    """
    GET /api/scan-history?limit=50&offset=0&page=1&payload_type=...&risk_level=...&status=...&search=...
    Returns sanitized list of recent scans metadata with pagination and filtering.
    Contains NO raw payloads, query strings, or binary data.
    """
    from app.database import get_scan_history, get_scan_history_count

    payload_type = request.args.get('payload_type') or request.args.get('category')
    risk_level = request.args.get('risk_level')
    status = request.args.get('status')
    search = request.args.get('search')

    try:
        limit = max(1, min(int(request.args.get('limit', 20)), 100))
    except (ValueError, TypeError):
        limit = 20

    # Support either 'page' (1-indexed) or explicit 'offset'
    if 'page' in request.args:
        try:
            page = max(1, int(request.args.get('page', 1)))
            offset = (page - 1) * limit
        except (ValueError, TypeError):
            page = 1
            offset = 0
    else:
        try:
            offset = max(0, int(request.args.get('offset', 0)))
            page = (offset // limit) + 1
        except (ValueError, TypeError):
            offset = 0
            page = 1

    history = get_scan_history(
        limit=limit,
        offset=offset,
        payload_type=payload_type,
        risk_level=risk_level,
        status=status,
        search=search
    )
    total = get_scan_history_count(
        payload_type=payload_type,
        risk_level=risk_level,
        status=status,
        search=search
    )

    return jsonify({
        "success": True,
        "count": len(history),
        "total": total,
        "page": page,
        "limit": limit,
        "history": history
    }), 200


@api_bp.route('/scan-history/<int:scan_id>', methods=['GET'])
def get_scan_detail_endpoint(scan_id):
    """
    GET /api/scan-history/<id>
    Returns non-sensitive metadata for a single scan.
    """
    from app.database import get_scan_by_id
    record = get_scan_by_id(scan_id)
    if not record:
        return jsonify({
            "success": False,
            "error_code": "NOT_FOUND",
            "message": f"Scan record #{scan_id} not found."
        }), 404

    return jsonify({
        "success": True,
        "scan": record
    }), 200


@api_bp.route('/scan-history/<int:scan_id>', methods=['DELETE'])
def delete_scan_endpoint(scan_id):
    """
    DELETE /api/scan-history/<id>
    Removes a scan metadata record.
    """
    from app.database import delete_scan
    deleted = delete_scan(scan_id)
    if not deleted:
        return jsonify({
            "success": False,
            "error_code": "NOT_FOUND",
            "message": f"Scan record #{scan_id} not found."
        }), 404

    return jsonify({
        "success": True,
        "message": f"Scan record #{scan_id} successfully deleted."
    }), 200


@api_bp.route('/scan-history/<int:scan_id>/report', methods=['GET'])
@rate_limit('RATELIMIT_REPORT', default_limit=20)
def get_scan_history_report_endpoint(scan_id):
    """
    GET /api/scan-history/<id>/report
    Generates and downloads a historical PDF security summary report
    from persisted metadata. Explicitly identifies the report as a
    historical metadata summary.
    """
    from app.database import get_scan_by_id
    from app.core.pdf_reporter import generate_history_pdf_report

    record = get_scan_by_id(scan_id)
    if not record:
        return jsonify({
            "success": False,
            "error_code": "NOT_FOUND",
            "message": f"Scan record #{scan_id} not found."
        }), 404

    try:
        pdf_bytes = generate_history_pdf_report(record)
        filename = f"QShield-Audit-Report-{scan_id}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
                "Cache-Control": "no-store, no-cache, must-revalidate"
            }
        )
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "PDF_GENERATION_ERROR",
            "message": f"Failed to generate historical PDF report: {str(e)}"
        }), 500


@api_bp.route('/scan-report/generate', methods=['POST'])
@rate_limit('RATELIMIT_REPORT', default_limit=20)
def generate_live_scan_report_endpoint():
    """
    POST /api/scan-report/generate
    Accepts current scan result JSON and produces an immediate full PDF report.
    Never accepts arbitrary HTML or unsafe file paths.
    """
    from app.core.pdf_reporter import generate_scan_pdf_report

    if not request.is_json:
        return jsonify({
            "success": False,
            "error_code": "INVALID_JSON",
            "message": "Request body must be a JSON object containing scan results."
        }), 400

    scan_data = request.get_json(silent=True)
    if not scan_data or not isinstance(scan_data, dict):
        return jsonify({
            "success": False,
            "error_code": "INVALID_PAYLOAD",
            "message": "Valid scan result dictionary required."
        }), 400

    try:
        pdf_bytes = generate_scan_pdf_report(scan_data)
        scan_id = scan_data.get('scan_id', 'Live')
        filename = f"QShield-Security-Report-{scan_id}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
                "Cache-Control": "no-store, no-cache, must-revalidate"
            }
        )
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "PDF_GENERATION_ERROR",
            "message": f"Failed to generate live PDF report: {str(e)}"
        }), 500


def _check_admin_auth():
    """
    Helper to verify admin authorization.
    If ADMIN_API_KEY is configured, checks header 'X-Admin-Key' or param 'api_key'.
    If not configured in production, blocks access.
    In testing/development with no key configured, allows access.
    Returns (is_authorized: bool, error_response: tuple | None).
    """
    admin_key = current_app.config.get('ADMIN_API_KEY', '').strip()
    is_testing = current_app.config.get('TESTING', False)
    is_debug = current_app.config.get('DEBUG', False)

    if admin_key:
        provided_key = request.headers.get('X-Admin-Key') or request.args.get('api_key', '')
        if not provided_key or not hmac.compare_digest(provided_key.encode('utf-8'), admin_key.encode('utf-8')):
            return False, (jsonify({
                "success": False,
                "error_code": "UNAUTHORIZED",
                "message": "Invalid or missing administrative authorization key."
            }), 401)
        return True, None

    # No key configured:
    if is_testing or is_debug:
        # Permitted in development / test environments
        return True, None

    # In production without an ADMIN_API_KEY configured:
    return False, (jsonify({
        "success": False,
        "error_code": "ADMIN_DISABLED_IN_PRODUCTION",
        "message": "Administrative interface is disabled in production until ADMIN_API_KEY is configured in environment."
    }), 403)


@api_bp.route('/admin/summary', methods=['GET'])
def get_admin_summary_endpoint():
    """
    GET /api/admin/summary
    Returns aggregated metrics and statistics computed from actual database records.
    Requires administrative authorization in production.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database import get_admin_metrics
    try:
        metrics = get_admin_metrics()
        return jsonify({
            "success": True,
            "metrics": metrics
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "METRICS_ERROR",
            "message": f"Failed to aggregate administrative metrics: {str(e)}"
        }), 500


@api_bp.route('/admin/health', methods=['GET'])
def get_admin_health_endpoint():
    """
    GET /api/admin/health
    Provides safe application operational health information without leaking secrets.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database import get_db

    # Probe DB connection
    db_ok = False
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False

    # Check integrations without exposing keys
    sb_key = bool(current_app.config.get('GOOGLE_SAFE_BROWSING_API_KEY', '').strip())
    vt_key = bool(current_app.config.get('VIRUSTOTAL_API_KEY', '').strip())
    admin_key_set = bool(current_app.config.get('ADMIN_API_KEY', '').strip())

    env_name = "testing" if current_app.config.get('TESTING') else ("development" if current_app.config.get('DEBUG') else "production")

    return jsonify({
        "success": True,
        "health": {
            "application_status": "healthy" if db_ok else "degraded",
            "database_connected": db_ok,
            "environment": env_name,
            "threat_intelligence_configured": sb_key or vt_key,
            "threat_intel_provider": "Google Safe Browsing v4" if sb_key else "Not configured",
            "redirect_inspector_active": True,
            "admin_auth_mode": "key_enforced" if admin_key_set else ("development_unrestricted" if (env_name != "production") else "disabled"),
            "privacy_mode": "zero_payload_persistence"
        }
    }), 200


# =============================================================================
# Advanced Threat Intelligence Dashboard & QR Risk Analytics Endpoints
# =============================================================================

def _extract_analytics_filters():
    """
    Extracts, sanitizes, and validates common analytics query parameters.
    """
    time_range = request.args.get('time_range', '7d').strip().lower()
    if time_range not in ('24h', '7d', '30d', 'all'):
        time_range = '7d'

    start_date = request.args.get('start_date', '').strip() or None
    end_date = request.args.get('end_date', '').strip() or None
    risk_level = request.args.get('risk_level', '').strip().lower() or None
    if risk_level and risk_level not in ('low', 'medium', 'high', 'critical', 'inconclusive', 'all'):
        risk_level = None

    payload_type = request.args.get('payload_type', '').strip() or None
    if payload_type and payload_type.lower() == 'all':
        payload_type = None

    detection_method = request.args.get('detection_method', '').strip().lower() or None
    if detection_method and detection_method not in ('heuristic_rules', 'ml_inference', 'ensemble', 'inconclusive', 'all'):
        detection_method = None

    status = request.args.get('status', '').strip().lower() or None
    if status and status not in ('completed', 'failed', 'inconclusive', 'all'):
        status = None

    return {
        "time_range": time_range,
        "start_date": start_date,
        "end_date": end_date,
        "risk_level": risk_level,
        "payload_type": payload_type,
        "detection_method": detection_method,
        "status": status
    }


@api_bp.route('/analytics/summary', methods=['GET'])
def get_analytics_summary_endpoint():
    """
    GET /api/analytics/summary
    Returns high-level KPI cards computed from actual stored scan history.
    Requires administrative authorization in production.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database.analytics_db import get_analytics_summary
    filters = _extract_analytics_filters()

    try:
        summary = get_analytics_summary(**filters)
        sb_key = bool(current_app.config.get('GOOGLE_SAFE_BROWSING_API_KEY', '').strip())
        vt_key = bool(current_app.config.get('VIRUSTOTAL_API_KEY', '').strip())
        summary["external_threat_provider_configured"] = (sb_key or vt_key)
        return jsonify({
            "success": True,
            "summary": summary
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "ANALYTICS_SUMMARY_ERROR",
            "message": f"Failed to compute analytics summary: {str(e)}"
        }), 500


@api_bp.route('/analytics/risk-distribution', methods=['GET'])
def get_analytics_risk_distribution_endpoint():
    """
    GET /api/analytics/risk-distribution
    Returns exact counts and proportions for each risk level defined by QShield.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database.analytics_db import get_risk_distribution
    filters = _extract_analytics_filters()

    try:
        data = get_risk_distribution(
            time_range=filters["time_range"],
            start_date=filters["start_date"],
            end_date=filters["end_date"],
            payload_type=filters["payload_type"],
            detection_method=filters["detection_method"],
            status=filters["status"]
        )
        return jsonify({
            "success": True,
            "risk_distribution": data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "RISK_DISTRIBUTION_ERROR",
            "message": f"Failed to compute risk distribution: {str(e)}"
        }), 500


@api_bp.route('/analytics/activity', methods=['GET'])
def get_analytics_activity_endpoint():
    """
    GET /api/analytics/activity
    Returns time-bucketed scan activity timeline (hourly for 24h, daily for 7d/30d).
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database.analytics_db import get_activity_timeline
    filters = _extract_analytics_filters()

    try:
        data = get_activity_timeline(**filters)
        return jsonify({
            "success": True,
            "activity": data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "ACTIVITY_TIMELINE_ERROR",
            "message": f"Failed to compute activity timeline: {str(e)}"
        }), 500


@api_bp.route('/analytics/payload-categories', methods=['GET'])
def get_analytics_payload_categories_endpoint():
    """
    GET /api/analytics/payload-categories
    Returns distribution of scan records across supported QR payload formats.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database.analytics_db import get_payload_categories
    filters = _extract_analytics_filters()

    try:
        data = get_payload_categories(
            time_range=filters["time_range"],
            start_date=filters["start_date"],
            end_date=filters["end_date"],
            risk_level=filters["risk_level"],
            detection_method=filters["detection_method"],
            status=filters["status"]
        )
        return jsonify({
            "success": True,
            "payload_categories": data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "PAYLOAD_CATEGORIES_ERROR",
            "message": f"Failed to compute payload categories: {str(e)}"
        }), 500


@api_bp.route('/analytics/detection-methods', methods=['GET'])
def get_analytics_detection_methods_endpoint():
    """
    GET /api/analytics/detection-methods
    Returns counts of scans evaluated by each detection mechanism actually invoked.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database.analytics_db import get_detection_methods
    filters = _extract_analytics_filters()

    try:
        data = get_detection_methods(
            time_range=filters["time_range"],
            start_date=filters["start_date"],
            end_date=filters["end_date"],
            risk_level=filters["risk_level"],
            payload_type=filters["payload_type"],
            status=filters["status"]
        )
        return jsonify({
            "success": True,
            "detection_methods": data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "DETECTION_METHODS_ERROR",
            "message": f"Failed to compute detection methods: {str(e)}"
        }), 500


@api_bp.route('/analytics/indicators', methods=['GET'])
def get_analytics_indicators_endpoint():
    """
    GET /api/analytics/indicators
    Returns frequency analysis of observed structural and external threat indicators.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database.analytics_db import get_observed_indicators
    filters = _extract_analytics_filters()

    try:
        data = get_observed_indicators(
            time_range=filters["time_range"],
            start_date=filters["start_date"],
            end_date=filters["end_date"],
            risk_level=filters["risk_level"],
            payload_type=filters["payload_type"]
        )
        return jsonify({
            "success": True,
            "indicators": data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "INDICATORS_ERROR",
            "message": f"Failed to compute observed indicators: {str(e)}"
        }), 500


@api_bp.route('/analytics/trends', methods=['GET'])
def get_analytics_trends_endpoint():
    """
    GET /api/analytics/trends
    Returns period-over-period comparison with division-by-zero protection.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from app.database.analytics_db import get_trend_analysis
    time_range = request.args.get('time_range', '7d').strip().lower()
    if time_range not in ('24h', '7d', '30d'):
        time_range = '7d'

    try:
        data = get_trend_analysis(time_range=time_range)
        return jsonify({
            "success": True,
            "trends": data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "TRENDS_ERROR",
            "message": f"Failed to compute trends: {str(e)}"
        }), 500


@api_bp.route('/analytics/export-pdf', methods=['GET', 'POST'])
def export_analytics_pdf_endpoint():
    """
    GET/POST /api/analytics/export-pdf
    Generates and returns an audit-ready PDF report of aggregated analytics data.
    """
    auth_ok, error_resp = _check_admin_auth()
    if not auth_ok:
        return error_resp

    from flask import Response
    from app.database.analytics_db import (
        get_analytics_summary,
        get_risk_distribution,
        get_payload_categories,
        get_detection_methods,
        get_observed_indicators,
        get_trend_analysis
    )
    from app.core.pdf_reporter import generate_analytics_pdf_report

    filters = _extract_analytics_filters()

    try:
        summary = get_analytics_summary(**filters)
        risk_dist = get_risk_distribution(
            time_range=filters["time_range"],
            start_date=filters["start_date"],
            end_date=filters["end_date"],
            payload_type=filters["payload_type"],
            detection_method=filters["detection_method"],
            status=filters["status"]
        )
        payload_cats = get_payload_categories(
            time_range=filters["time_range"],
            start_date=filters["start_date"],
            end_date=filters["end_date"],
            risk_level=filters["risk_level"],
            detection_method=filters["detection_method"],
            status=filters["status"]
        )
        detection_methods = get_detection_methods(
            time_range=filters["time_range"],
            start_date=filters["start_date"],
            end_date=filters["end_date"],
            risk_level=filters["risk_level"],
            payload_type=filters["payload_type"],
            status=filters["status"]
        )
        indicators = get_observed_indicators(
            time_range=filters["time_range"],
            start_date=filters["start_date"],
            end_date=filters["end_date"],
            risk_level=filters["risk_level"],
            payload_type=filters["payload_type"]
        )
        trends = get_trend_analysis(time_range=filters["time_range"])

        analytics_bundle = {
            "summary": summary,
            "risk_distribution": risk_dist,
            "payload_categories": payload_cats,
            "detection_methods": detection_methods,
            "indicators": indicators,
            "trends": trends,
            "time_range_label": filters["time_range"]
        }

        pdf_bytes = generate_analytics_pdf_report(analytics_bundle)
        filename = f"qshield-threat-analytics-{filters['time_range']}.pdf"

        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=\"{filename}\"",
                "Content-Length": str(len(pdf_bytes)),
                "Cache-Control": "no-store, no-cache, must-revalidate, private"
            }
        )
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "PDF_EXPORT_ERROR",
            "message": f"Failed to generate analytics PDF export: {str(e)}"
        }), 500


@api_bp.route('/check-reputation', methods=['POST'])
@rate_limit('RATELIMIT_REPUTATION', default_limit=15)
def check_reputation_endpoint():
    """
    POST /api/check-reputation
    Accepts JSON body: {"url": "https://...", "user_consent": true}
    Checks external threat intelligence provider reputation upon explicit user consent.
    Enforces strict privacy checks, standard URL validation, and safe error normalization.
    Never logs or persists full URL with query tokens.
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "error_code": "INVALID_JSON",
            "message": "Request body must be a JSON object containing 'url' and 'user_consent' keys."
        }), 400

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({
            "success": False,
            "error_code": "MISSING_URL_FIELD",
            "message": "Field 'url' is required in JSON payload."
        }), 400

    raw_url = data.get('url')
    if not isinstance(raw_url, str):
        return jsonify({
            "success": False,
            "error_code": "INVALID_TYPE",
            "message": "Field 'url' must be a string."
        }), 400

    # Explicit user consent validation
    user_consent = bool(data.get('user_consent', False))
    if not user_consent:
        return jsonify({
            "success": False,
            "error_code": "CONSENT_REQUIRED",
            "message": "External reputation lookup requires explicit user confirmation.",
            "reputation_result": {
                "provider": "Threat Intelligence",
                "status": "skipped_no_consent",
                "reputation": "unknown",
                "threat_categories": [],
                "summary": "External threat reputation lookup requires explicit user consent.",
                "checked_at": None,
                "limitations": "External reputation was not queried because consent was not granted."
            }
        }), 400

    # URL Scheme and format validation using existing heuristic analyzer rules
    from app.core.url_analyzer import analyze_url_heuristics
    url_analysis = analyze_url_heuristics(raw_url)
    
    # Must be valid and have a genuine public suffix/TLD or valid domain with dot (or localhost)
    parsed_info = url_analysis.get('parsed_url') or {}
    hostname = parsed_info.get('hostname', '')
    has_valid_host = bool(hostname and ('.' in hostname or hostname == 'localhost'))

    if not url_analysis.get('valid') or not has_valid_host:
        return jsonify({
            "success": False,
            "error_code": url_analysis.get('error_code') or 'INVALID_HOSTNAME',
            "message": url_analysis.get('message') or 'URL does not contain a valid domain name.',
            "reputation_result": {
                "provider": "Threat Intelligence",
                "status": "invalid_url",
                "reputation": "unknown",
                "threat_categories": [],
                "summary": "Only complete HTTP and HTTPS URLs with valid hostnames can be evaluated.",
                "checked_at": None,
                "limitations": "Only valid HTTP/HTTPS URLs can be evaluated."
            }
        }), 400

    from app.core.threat_intelligence import evaluate_threat_intelligence
    api_key = current_app.config.get('GOOGLE_SAFE_BROWSING_API_KEY', '')

    reputation_result = evaluate_threat_intelligence(
        url=raw_url,
        user_consent=user_consent,
        api_key=api_key
    )

    # If scan_id provided, update scan record telemetry
    scan_id = data.get('scan_id')
    if scan_id and isinstance(scan_id, int):
        try:
            from app.database import update_scan_threat_intel
            is_flagged = bool(reputation_result.get('is_flagged') or (reputation_result.get('reputation') == 'suspicious'))
            update_scan_threat_intel(scan_id, threat_status=reputation_result.get('status', 'clean'), is_flagged=is_flagged)
        except Exception:
            pass

    return jsonify({
        "success": True,
        "reputation_result": reputation_result
    }), 200


@api_bp.route('/inspect-redirects', methods=['POST'])
@rate_limit('RATELIMIT_REDIRECT', default_limit=15)
def inspect_redirects_endpoint():
    """
    POST /api/inspect-redirects
    Accepts JSON body: {"url": "https://...", "user_consent": true}
    Inspects HTTP redirect chain hop-by-hop with strict SSRF destination safeguards.
    Never follows redirects to private/loopback/cloud metadata destinations.
    """
    if not request.is_json:
        return jsonify({
            "success": False,
            "error_code": "INVALID_JSON",
            "message": "Request body must be a JSON object containing 'url' and 'user_consent' keys."
        }), 400

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({
            "success": False,
            "error_code": "MISSING_URL_FIELD",
            "message": "Field 'url' is required in JSON payload."
        }), 400

    raw_url = data.get('url')
    if not isinstance(raw_url, str):
        return jsonify({
            "success": False,
            "error_code": "INVALID_TYPE",
            "message": "Field 'url' must be a string."
        }), 400

    # User consent check
    user_consent = bool(data.get('user_consent', False))
    if not user_consent:
        return jsonify({
            "success": False,
            "error_code": "CONSENT_REQUIRED",
            "message": "Redirect inspection requires explicit user confirmation.",
            "redirect_result": {
                "status": "skipped_no_consent",
                "hops": [],
                "redirect_count": 0,
                "summary": "Redirect inspection requires explicit user confirmation."
            }
        }), 400

    from app.core.redirect_inspector import inspect_redirects
    redirect_result = inspect_redirects(raw_url, consent_confirmed=user_consent)

    status_code = 200
    if redirect_result.get("status") == "invalid_url":
        status_code = 400

    return jsonify({
        "success": status_code == 200,
        "redirect_result": redirect_result
    }), status_code


@api_bp.route('/quiz/categories', methods=['GET'])
def quiz_categories():
    """
    GET /api/quiz/categories?lang=en
    Returns all quiz categories with localized titles, descriptions, and question counts.
    """
    lang = request.args.get('lang', 'en').lower().strip()
    from app.core.quiz_service import get_categories
    categories = get_categories(lang)
    total_questions = sum(c["question_count"] for c in categories)
    return jsonify({
        "success": True,
        "lang": lang,
        "total_questions": total_questions,
        "categories": categories
    }), 200


@api_bp.route('/quiz/start', methods=['POST'])
def quiz_start():
    """
    POST /api/quiz/start
    Body: { "category_id": "...", "lang": "en" }
    Returns questions for the category WITHOUT correct_answer fields.
    """
    data = request.get_json(silent=True)
    if not data or 'category_id' not in data:
        return jsonify({
            "success": False,
            "error_code": "MISSING_CATEGORY",
            "message": "Field 'category_id' is required."
        }), 400

    category_id = data['category_id']
    lang = data.get('lang', 'en')

    from app.core.quiz_service import get_category_questions_for_client
    questions = get_category_questions_for_client(category_id, lang)

    if not questions:
        return jsonify({
            "success": False,
            "error_code": "CATEGORY_EMPTY",
            "message": f"No questions available for category '{category_id}'."
        }), 404

    return jsonify({
        "success": True,
        "category_id": category_id,
        "lang": lang,
        "total_questions": len(questions),
        "questions": questions
    }), 200


@api_bp.route('/quiz/check-answer', methods=['POST'])
def quiz_check_answer():
    """
    POST /api/quiz/check-answer
    Body: { "question_id": "...", "selected_option_id": "A", "lang": "en" }
    Server-side answer validation; returns correctness, explanation, and takeaway.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "success": False,
            "error_code": "INVALID_PAYLOAD",
            "message": "JSON payload required."
        }), 400

    question_id = data.get('question_id')
    selected = data.get('selected_option_id')
    lang = data.get('lang', 'en')

    if not question_id or not selected:
        return jsonify({
            "success": False,
            "error_code": "MISSING_FIELDS",
            "message": "Fields 'question_id' and 'selected_option_id' are required."
        }), 400

    from app.core.quiz_service import check_answer
    result = check_answer(question_id, selected, lang)

    if not result.get("success"):
        return jsonify(result), 404

    return jsonify(result), 200


@api_bp.route('/quiz/evaluate', methods=['POST'])
def quiz_evaluate():
    """
    POST /api/quiz/evaluate
    Body: { "category_id": "...", "answers": [...], "lang": "en" }
    Full quiz evaluation with deduplication and performance tier labeling.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "success": False,
            "error_code": "INVALID_PAYLOAD",
            "message": "JSON payload required."
        }), 400

    category_id = data.get('category_id')
    answers = data.get('answers', [])
    lang = data.get('lang', 'en')

    if not category_id:
        return jsonify({
            "success": False,
            "error_code": "MISSING_CATEGORY",
            "message": "Field 'category_id' is required."
        }), 400

    if not isinstance(answers, list):
        return jsonify({
            "success": False,
            "error_code": "INVALID_ANSWERS",
            "message": "Field 'answers' must be an array."
        }), 400

    from app.core.quiz_service import evaluate_quiz_submission
    result = evaluate_quiz_submission(category_id, answers, lang)

    if not result.get("success"):
        return jsonify(result), 404

    return jsonify(result), 200


@api_bp.route('/locale/<lang>', methods=['GET'])
def get_locale(lang):
    """
    GET /api/locale/<lang>
    Returns localized strings for 'en' or 'ta'.
    """
    import os
    import json
    lang = lang.lower().strip()
    if lang not in ('en', 'ta'):
        return jsonify({
            "success": False,
            "error_code": "UNSUPPORTED_LANGUAGE",
            "message": f"Language '{lang}' is not supported. Choose 'en' or 'ta'."
        }), 404

    base_dir = current_app.root_path
    locale_path = os.path.join(os.path.dirname(base_dir), 'locales', f'{lang}.json')
    if not os.path.exists(locale_path):
        locale_path = os.path.join(base_dir, '..', 'locales', f'{lang}.json')

    try:
        with open(locale_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify({
            "success": True,
            "lang": lang,
            "data": data
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error_code": "LOCALE_READ_ERROR",
            "message": str(e)
        }), 500

