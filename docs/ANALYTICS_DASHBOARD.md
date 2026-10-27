# QShield Threat Intelligence Dashboard & QR Risk Analytics

## 1. Purpose & Scope

The **QShield Threat Intelligence Dashboard & QR Risk Analytics** (`/admin` and `/analytics`) provides operational observability, risk distribution statistics, observed structural threat indicators, and period-over-period trend analysis.

Built in strict adherence to **Privacy-by-Design**, the dashboard operates solely on sanitized database metadata:
- **Zero Raw Payloads:** Full URL query strings, credentials, Wi-Fi passwords, and contact tokens are discarded immediately after scanning.
- **Zero Optical Storage:** QR code images and binary buffers are processed entirely in ephemeral memory and never written to disk or the database.
- **Zero Fabricated Metrics:** When no records exist or data is insufficient, the system presents honest empty states rather than simulated counters.
- **Local Scan Scope:** All metrics reflect local inspections executed on this QShield instance and do not claim global cyber threat intelligence authority.

---

## 2. Key Metrics & Definitions

| Metric Card | Definition | Formula / Derivation |
| :--- | :--- | :--- |
| **Total Scans Recorded** | Cumulative scan attempts within the selected time period. | `COUNT(*)` in filtered window |
| **High & Critical Assessments** | Scans evaluated with elevated risk scores ($\ge 50$). | `SUM(risk_level IN ('high', 'critical'))` |
| **Inconclusive Assessments** | Non-URL or unparseable payloads (vCard, Wi-Fi, text). | `SUM(risk_level = 'inconclusive' OR status = 'inconclusive')` |
| **Threat Feed Matches** | Scans explicitly flagged as malicious by configured threat intelligence feeds. | `SUM(threat_intel_status = 'flagged')` |
| **Average Risk Score** | Mean evaluated score across scored URL payloads. | `ROUND(AVG(risk_score), 1)` |

---

## 3. Filters & Interactive Exploration

The analytics engine supports server-side parameterization across multiple dimensions:

| Parameter | Type / Allowed Values | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `time_range` | `'24h'`, `'7d'`, `'30d'`, `'all'` | `'7d'` | Temporal window for aggregation |
| `risk_level` | `'low'`, `'medium'`, `'high'`, `'critical'`, `'inconclusive'`, `'all'` | `'all'` | Filter by evaluated severity band |
| `payload_type` | `'URL'`, `'Payment Request (UPI)'`, `'Plain Text'`, `'Wi-Fi'`, `'all'` | `'all'` | Filter by payload format |
| `detection_method` | `'heuristic_rules'`, `'ml_inference'`, `'ensemble'`, `'inconclusive'` | `'all'` | Filter by detection mechanism executed |
| `status` | `'completed'`, `'failed'`, `'inconclusive'` | `'all'` | Filter by processing outcome |

All filters are validated and parameterized to eliminate SQL injection risks.

---

## 4. API Endpoints

All endpoints require administrative authorization in production (`X-Admin-Key` header or `ADMIN_API_KEY` environment variable).

### `GET /api/analytics/summary`
Returns high-level KPI cards and observation boundaries.
```json
{
  "success": true,
  "summary": {
    "time_range": "last_7_days",
    "total_scans": 14,
    "high_or_critical_scans": 3,
    "inconclusive_scans": 2,
    "avg_risk_score": 42.5,
    "external_threat_detections": 1,
    "external_threat_provider_configured": true,
    "is_empty": false
  }
}
```

### `GET /api/analytics/risk-distribution`
Returns counts, proportions, and descriptions across the 5 QShield risk tiers.

### `GET /api/analytics/activity`
Returns continuous time-bucketed activity timelines:
- `24h`: 24 hourly buckets (`HH:00`)
- `7d` / `30d`: Daily buckets (`YYYY-MM-DD`)

### `GET /api/analytics/payload-categories`
Returns volume and percentage shares across QR format types.

### `GET /api/analytics/detection-methods`
Breaks down scans by actual execution method: Deterministic Heuristic Rules, Machine Learning Inference, Modular Ensemble, or Inconclusive.

### `GET /api/analytics/indicators`
Aggregates observed structural signals (IP hosts, Punycode, brand mimicry, shorteners, unusual ports, credentials) and external threat feed matches.

### `GET /api/analytics/trends`
Compares current period vs immediate preceding period with division-by-zero protection.

### `GET /api/analytics/export-pdf`
Generates an audit-ready, executive ReportLab PDF report containing KPI summaries, distributions, indicators, and trends.

---

## 5. Empty-Data Behavior

When no scan records exist in the database or match the active filter criteria:
1. `is_empty: true` is returned.
2. KPI cards display `0` or `—` with descriptive labels.
3. Distribution bars display clean placeholder styling.
4. Timelines display a centered message: *"No scan records observed in the selected time range."*
5. Trend analysis displays: *"Not enough data to identify a trend."*
