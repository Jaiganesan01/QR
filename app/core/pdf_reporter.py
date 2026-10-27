"""
QShield PDF Security Report Generator
Produces professional, audit-ready cybersecurity reports in PDF format using ReportLab.
Enforces strict privacy: never embeds credentials, query tokens, API keys, or raw image binaries.
Supports both full live scan reports and historical metadata-only summaries.
"""
import io
import html
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable
)
from reportlab.pdfgen import canvas

# Palette Constants
COLOR_NAVY = colors.HexColor('#0F172A')       # Dark navy
COLOR_SLATE = colors.HexColor('#334155')      # Secondary slate
COLOR_MUTED = colors.HexColor('#64748B')      # Muted text
COLOR_BG_CARD = colors.HexColor('#F8FAFC')    # Soft card background
COLOR_BORDER = colors.HexColor('#E2E8F0')     # Border grey
COLOR_TEAL = colors.HexColor('#0D9488')       # Primary teal
COLOR_TEAL_LIGHT = colors.HexColor('#CCFBF1') # Teal soft tint
COLOR_LOW_RISK = colors.HexColor('#16A34A')   # Green
COLOR_MED_RISK = colors.HexColor('#D97706')   # Amber
COLOR_HIGH_RISK = colors.HexColor('#DC2626')  # Red
COLOR_CRIT_RISK = colors.HexColor('#7F1D1D')  # Deep dark red
COLOR_INCONCLUSIVE = colors.HexColor('#6B7280')# Grey


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to calculate total page count and draw running header/footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(COLOR_MUTED)

        # Header (pages after first)
        if self._pageNumber > 1:
            self.drawString(54, 750, "QShield — Cybersecurity Inspection & Threat Audit Report")
            self.drawRightString(612 - 54, 750, "CONFIDENTIAL / DEFENSIVE EVALUATION")
            self.setStrokeColor(COLOR_BORDER)
            self.setLineWidth(0.5)
            self.line(54, 744, 612 - 54, 744)

        # Footer (all pages)
        self.setStrokeColor(COLOR_BORDER)
        self.setLineWidth(0.5)
        self.line(54, 45, 612 - 54, 45)
        self.drawString(54, 32, "QShield: Decode the QR. Detect the Threat. | Privacy-Preserving Architecture")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 32, page_str)
        self.restoreState()


def _sanitize(text: Any) -> str:
    """Escapes characters that break ReportLab Paragraph XML parsing, strips control characters, and bounds length."""
    if text is None:
        return ""
    s = str(text)
    # Strip null bytes and non-printable control characters that crash ReportLab parser
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)
    # Limit max length to prevent table/layout overflow DoS
    if len(s) > 2048:
        s = s[:2048] + " [TRUNCATED]"
    return html.escape(s, quote=True)


def _get_risk_badge_color(risk_level: str | None) -> tuple[colors.Color, colors.Color]:
    """Returns (background_color, text_color) for a risk level."""
    r = (risk_level or "").lower().strip()
    if r == "low":
        return colors.HexColor('#DCFCE7'), COLOR_LOW_RISK
    elif r == "medium":
        return colors.HexColor('#FEF3C7'), COLOR_MED_RISK
    elif r == "high":
        return colors.HexColor('#FEE2E2'), COLOR_HIGH_RISK
    elif r == "critical":
        return colors.HexColor('#7F1D1D'), colors.white
    else:
        return colors.HexColor('#F3F4F6'), COLOR_INCONCLUSIVE


def build_pdf_document(story: List[Any]) -> bytes:
    """Builds a PDF document in memory using NumberedCanvas and returns raw bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def _create_header_flowables(report_type: str, scan_id: int | str | None, timestamp: str) -> List[Any]:
    """Builds standardized report header with branding, metadata and tags."""
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=COLOR_NAVY
    )
    tagline_style = ParagraphStyle(
        'DocTagline',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=COLOR_TEAL
    )
    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=COLOR_MUTED
    )
    badge_style = ParagraphStyle(
        'Badge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=COLOR_TEAL
    )

    header_data = [
        [
            Paragraph("<b>QShield.</b>", title_style),
            Paragraph(f"<b>REPORT ID:</b> #{_sanitize(scan_id or 'LIVE')}<br/><b>GENERATED:</b> {_sanitize(timestamp)}", meta_style)
        ],
        [
            Paragraph("DECODE THE QR. DETECT THE THREAT.", tagline_style),
            Paragraph(f"<b>TYPE:</b> {_sanitize(report_type)} (v1.0)", meta_style)
        ]
    ]

    header_table = Table(header_data, colWidths=[330, 174])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))

    return [
        header_table,
        Spacer(1, 10),
        HRFlowable(width="100%", thickness=1.5, color=COLOR_TEAL, spaceBefore=4, spaceAfter=14)
    ]


def _create_disclaimer_flowables() -> List[Any]:
    """Standardized defensive evaluation disclaimer."""
    styles = getSampleStyleSheet()
    disc_heading = ParagraphStyle(
        'DiscHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=COLOR_SLATE
    )
    disc_text = ParagraphStyle(
        'DiscText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=9.5,
        textColor=COLOR_MUTED
    )

    content = [
        Paragraph("SECURITY NOTICE & HEURISTIC LIMITATIONS", disc_heading),
        Spacer(1, 3),
        Paragraph(
            "This report is a deterministic defensive heuristic assessment based on static structural analysis. "
            "It does NOT represent a calibrated mathematical phishing probability, does not execute dynamic browser code, "
            "and does not guarantee that a link is safe or malicious. A clean scan or absence of known reputation hits indicates "
            "that no configured indicators were triggered; zero-day malicious sites may not yet be cataloged. "
            "QShield upholds Privacy-by-Design: passwords, raw images, session tokens, and full query parameters are never retained.",
            disc_text
        )
    ]

    t = Table([[content]], colWidths=[504])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_BG_CARD),
        ('BOX', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    return [Spacer(1, 14), t]


def generate_scan_pdf_report(scan_data: Dict[str, Any]) -> bytes:
    """
    Generates a full, multi-section inspection report from an active scan result object.
    Includes summary metrics, security findings, additional checks, and actionable advice.
    """
    styles = getSampleStyleSheet()

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=COLOR_NAVY,
        spaceBefore=8,
        spaceAfter=6
    )
    cell_bold = ParagraphStyle('CellB', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=COLOR_NAVY)
    cell_regular = ParagraphStyle('CellR', parent=styles['Normal'], fontName='Helvetica', fontSize=8.5, leading=11, textColor=COLOR_SLATE)
    code_style = ParagraphStyle('Code', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10, textColor=COLOR_SLATE)

    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    scan_id = scan_data.get('scan_id')

    story: List[Any] = []
    story.extend(_create_header_flowables("Full Inspection Report", scan_id, now_utc))

    # 1. Executive Summary Table
    parsed_info = scan_data.get('parsed_url') or {}
    domain = parsed_info.get('hostname') or scan_data.get('target_domain') or 'None (Non-URL Payload)'
    payload_type = scan_data.get('payload_type') or (scan_data.get('payload_inspection') or {}).get('type_name') or 'Web Address (URL)'
    
    risk_assessment = scan_data.get('risk_assessment') or {}
    score = risk_assessment.get('score')
    risk_level = risk_assessment.get('risk_level') or 'inconclusive'
    
    indicators = scan_data.get('indicators') or []
    status = "Completed" if scan_data.get('valid', True) else "Inconclusive"

    bg_risk, fg_risk = _get_risk_badge_color(risk_level)
    risk_badge_p = Paragraph(
        f"<font color='{fg_risk.hexval()}'><b>{_sanitize(risk_level.upper())} ({score if score is not None else 'N/A'}/100)</b></font>",
        cell_bold
    )

    summary_data = [
        [Paragraph("Target Host / Domain", cell_bold), Paragraph(_sanitize(domain), cell_regular)],
        [Paragraph("Payload Category", cell_bold), Paragraph(_sanitize(payload_type), cell_regular)],
        [Paragraph("Heuristic Risk Assessment", cell_bold), risk_badge_p],
        [Paragraph("Observed Indicator Count", cell_bold), Paragraph(f"{len(indicators)} finding(s)", cell_regular)],
        [Paragraph("Inspection Processing Status", cell_bold), Paragraph(_sanitize(status), cell_regular)]
    ]

    summary_table = Table(summary_data, colWidths=[160, 344])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), COLOR_BG_CARD),
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    story.append(Paragraph("1. Inspection Summary", h2_style))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # 2. Heuristic Security Findings
    story.append(Paragraph("2. Heuristic Indicators & Evidence", h2_style))
    if indicators:
        findings_data = [
            [
                Paragraph("<b>Rule / Indicator</b>", cell_bold),
                Paragraph("<b>Severity</b>", cell_bold),
                Paragraph("<b>Technical Analysis & Evidence</b>", cell_bold)
            ]
        ]
        for ind in indicators:
            sev = ind.get('severity', 'info').upper()
            _, sev_fg = _get_risk_badge_color(sev)
            sev_p = Paragraph(f"<font color='{sev_fg.hexval()}'><b>{_sanitize(sev)}</b></font>", cell_bold)
            
            rule_id = ind.get('rule_id', 'UNKNOWN_RULE')
            desc = ind.get('message', 'Suspicious structural indicator detected.')
            evidence = ind.get('evidence', '')
            
            detail_p = Paragraph(f"{_sanitize(desc)}<br/><font color='{COLOR_MUTED.hexval()}'>Evidence: {_sanitize(evidence) if evidence else 'Pattern match'}</font>", cell_regular)
            findings_data.append([Paragraph(_sanitize(rule_id), code_style), sev_p, detail_p])

        findings_table = Table(findings_data, colWidths=[150, 70, 284])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_BG_CARD),
            ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(findings_table)
    else:
        story.append(Paragraph("<i>No suspicious indicators were triggered by our configured static heuristic rules.</i>", cell_regular))

    story.append(Spacer(1, 10))

    # 3. Additional Modular Checks (Threat Intel, Redirects, Payload Inspector)
    story.append(Paragraph("3. Extended Security Inspections", h2_style))
    
    # Threat Intel
    threat = scan_data.get('reputation_result') or {}
    threat_status = threat.get('status', 'not_performed')
    threat_rep = threat.get('reputation', 'unknown')
    threat_summary = threat.get('summary', 'External threat reputation lookup was not performed.')

    # Redirects
    redir = scan_data.get('redirect_result') or {}
    redir_status = redir.get('status', 'not_inspected')
    redir_hops = redir.get('redirect_count', 0)
    redir_summary = redir.get('summary', 'Redirect chain inspection was not initiated.')

    # Payload classification
    payload_info = scan_data.get('payload_inspection') or {}
    payload_fmt = payload_info.get('format_syntax', 'N/A')
    caution = payload_info.get('caution_notice', 'Standard untrusted optical payload precautions apply.')

    checks_data = [
        [Paragraph("External Threat Intelligence", cell_bold), Paragraph(f"<b>{_sanitize(threat_status.upper())} ({_sanitize(threat_rep)})</b><br/>{_sanitize(threat_summary)}", cell_regular)],
        [Paragraph("Safe Redirect Inspector", cell_bold), Paragraph(f"<b>{_sanitize(redir_status.upper())} ({redir_hops} hops observed)</b><br/>{_sanitize(redir_summary)}", cell_regular)],
        [Paragraph("Payload Structural Classification", cell_bold), Paragraph(f"Format: <b>{_sanitize(payload_fmt)}</b><br/>{_sanitize(caution)}", cell_regular)]
    ]

    checks_table = Table(checks_data, colWidths=[160, 344])
    checks_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), COLOR_BG_CARD),
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(checks_table)
    story.append(Spacer(1, 10))

    # 4. Actionable Next Steps
    recs = risk_assessment.get('recommendations') or {}
    next_step = recs.get('next_step') or 'Independently verify destination authenticity before entering credentials.'
    story.append(Paragraph("4. Recommended Safety Action", h2_style))
    story.append(Paragraph(f"<b>Primary Guidance:</b> {_sanitize(next_step)}", cell_regular))

    # Disclaimer
    story.extend(_create_disclaimer_flowables())

    return build_pdf_document(story)


def generate_history_pdf_report(history_record: Dict[str, Any]) -> bytes:
    """
    Generates a PDF report for a historical scan record from database metadata.
    Explicitly labeled as a 'Historical Metadata Summary' to communicate that full
    payloads and raw URLs are intentionally omitted under Privacy-by-Design.
    """
    styles = getSampleStyleSheet()

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=COLOR_NAVY,
        spaceBefore=8,
        spaceAfter=6
    )
    cell_bold = ParagraphStyle('CellB', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=COLOR_NAVY)
    cell_regular = ParagraphStyle('CellR', parent=styles['Normal'], fontName='Helvetica', fontSize=8.5, leading=11, textColor=COLOR_SLATE)

    scan_id = history_record.get('id', 'N/A')
    timestamp = history_record.get('created_at', str(datetime.now(timezone.utc)))

    story: List[Any] = []
    story.extend(_create_header_flowables("Historical Metadata Summary", scan_id, timestamp))

    # Notice on Metadata Retention
    notice_text = (
        "<b>Privacy Retention Notice:</b> This audit report was reconstructed from persisted scan metadata. "
        "In strict adherence to QShield's Privacy-by-Design architecture, original full URL strings, query parameters, "
        "and decoded QR payloads were discarded immediately after processing and are not stored in the database. "
        "The metrics below reflect the authenticated operational record."
    )
    notice_p = Paragraph(notice_text, cell_regular)
    notice_table = Table([[notice_p]], colWidths=[504])
    notice_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_TEAL_LIGHT),
        ('BOX', (0, 0), (-1, -1), 0.5, COLOR_TEAL),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(notice_table)
    story.append(Spacer(1, 10))

    # Historical Record Table
    risk_level = history_record.get('risk_level') or 'inconclusive'
    score = history_record.get('risk_score')
    domain = history_record.get('target_domain') or 'N/A (Non-URL or masked)'
    payload_type = history_record.get('payload_type', 'Unknown')
    scan_type = history_record.get('scan_type', 'Unknown').capitalize()
    status = history_record.get('status', 'Completed').capitalize()
    indicators = history_record.get('indicator_count', 0)

    _, fg_risk = _get_risk_badge_color(risk_level)
    risk_badge_p = Paragraph(
        f"<font color='{fg_risk.hexval()}'><b>{_sanitize(risk_level.upper())} ({score if score is not None else 'N/A'}/100)</b></font>",
        cell_bold
    )

    data = [
        [Paragraph("Scan Database Record ID", cell_bold), Paragraph(f"#{_sanitize(scan_id)}", cell_regular)],
        [Paragraph("Submission Method", cell_bold), Paragraph(_sanitize(scan_type), cell_regular)],
        [Paragraph("Payload Category", cell_bold), Paragraph(_sanitize(payload_type), cell_regular)],
        [Paragraph("Sanitized Root Domain", cell_bold), Paragraph(_sanitize(domain), cell_regular)],
        [Paragraph("Evaluated Risk Category", cell_bold), risk_badge_p],
        [Paragraph("Indicators Flagged", cell_bold), Paragraph(f"{indicators} indicator(s)", cell_regular)],
        [Paragraph("Recorded Scan Status", cell_bold), Paragraph(_sanitize(status), cell_regular)],
        [Paragraph("Original Timestamp", cell_bold), Paragraph(_sanitize(timestamp), cell_regular)],
    ]

    t = Table(data, colWidths=[160, 344])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), COLOR_BG_CARD),
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))

    story.append(Paragraph("1. Recorded Scan Metadata", h2_style))
    story.append(t)

    # Disclaimer
    story.extend(_create_disclaimer_flowables())

    return build_pdf_document(story)


def generate_analytics_pdf_report(analytics_data: Dict[str, Any]) -> bytes:
    """
    Generates an executive cybersecurity analytics PDF report aggregating
    actual scan volumes, risk distributions, observed indicators, and trend observations.
    Strictly preserves privacy: zero raw URLs, tokens, or personal identifiers.
    """
    styles = getSampleStyleSheet()

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=COLOR_NAVY,
        spaceBefore=10,
        spaceAfter=5
    )
    cell_bold = ParagraphStyle('CellB', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=COLOR_NAVY)
    cell_regular = ParagraphStyle('CellR', parent=styles['Normal'], fontName='Helvetica', fontSize=8, leading=10, textColor=COLOR_SLATE)
    cell_small = ParagraphStyle('CellS', parent=styles['Normal'], fontName='Helvetica', fontSize=7.5, leading=9.5, textColor=COLOR_MUTED)

    summary = analytics_data.get('summary', {})
    risk_dist = analytics_data.get('risk_distribution', {}).get('distribution', [])
    payload_cats = analytics_data.get('payload_categories', {}).get('categories', [])
    detection_methods = analytics_data.get('detection_methods', {}).get('methods', [])
    indicators = analytics_data.get('indicators', {}).get('indicators', [])
    trends = analytics_data.get('trends', {})
    time_range = analytics_data.get('time_range_label', 'Observed Period')

    gen_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    story: List[Any] = []
    story.extend(_create_header_flowables("Security Analytics & Risk Intelligence Summary", "TELEMETRY", gen_timestamp))

    # Executive Overview Table
    total_scans = summary.get('total_scans', 0)
    high_crit = summary.get('high_or_critical_scans', 0)
    inconclusive = summary.get('inconclusive_scans', 0)
    avg_score = summary.get('avg_risk_score')
    threat_flagged = summary.get('external_threat_detections', 0)

    overview_data = [
        [
            Paragraph("<b>Reporting Period</b>", cell_bold),
            Paragraph(f"<b>{_sanitize(time_range.replace('_', ' ').title())}</b>", cell_regular),
            Paragraph("<b>Total Scans</b>", cell_bold),
            Paragraph(f"<b>{total_scans}</b>", cell_bold)
        ],
        [
            Paragraph("<b>High & Critical Detections</b>", cell_bold),
            Paragraph(f"<font color='#dc2626'><b>{high_crit}</b></font>", cell_bold),
            Paragraph("<b>Inconclusive / Other</b>", cell_bold),
            Paragraph(f"{inconclusive}", cell_regular)
        ],
        [
            Paragraph("<b>Average Evaluated Risk</b>", cell_bold),
            Paragraph(f"{avg_score}/100" if avg_score is not None else "N/A", cell_regular),
            Paragraph("<b>External Feed Matches</b>", cell_bold),
            Paragraph(f"<font color='#7f1d1d'><b>{threat_flagged}</b></font>", cell_regular)
        ]
    ]

    ot = Table(overview_data, colWidths=[130, 122, 130, 122])
    ot.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_BG_CARD),
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(Paragraph("1. Executive Telemetry Overview", h2_style))
    story.append(ot)

    # Risk Distribution Table
    story.append(Paragraph("2. Risk Severity Distribution (Actual Evaluations)", h2_style))
    risk_table_rows = [
        [
            Paragraph("<b>Severity Tier</b>", cell_bold),
            Paragraph("<b>Score Range</b>", cell_bold),
            Paragraph("<b>Scans</b>", cell_bold),
            Paragraph("<b>Share (%)</b>", cell_bold),
            Paragraph("<b>Evaluation Description</b>", cell_bold)
        ]
    ]
    for r in risk_dist:
        risk_table_rows.append([
            Paragraph(f"<b>{_sanitize(r.get('name'))}</b>", cell_bold),
            Paragraph(_sanitize(r.get('score_range')), cell_regular),
            Paragraph(str(r.get('count', 0)), cell_regular),
            Paragraph(f"{r.get('percentage', 0.0)}%", cell_regular),
            Paragraph(_sanitize(r.get('description')), cell_small)
        ])

    rt = Table(risk_table_rows, colWidths=[90, 60, 45, 55, 254])
    rt.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_BG_CARD),
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(rt)

    # Observed Indicators Table (Top 6)
    story.append(Paragraph("3. Observed Threat Indicators & Structural Anomalies", h2_style))
    ind_table_rows = [
        [
            Paragraph("<b>Indicator Name</b>", cell_bold),
            Paragraph("<b>Type</b>", cell_bold),
            Paragraph("<b>Severity</b>", cell_bold),
            Paragraph("<b>Scans Flagged</b>", cell_bold),
            Paragraph("<b>Share (%)</b>", cell_bold)
        ]
    ]
    for ind in indicators[:8]:
        ind_table_rows.append([
            Paragraph(f"<b>{_sanitize(ind.get('name'))}</b>", cell_bold),
            Paragraph(_sanitize(ind.get('category', '').title()), cell_regular),
            Paragraph(_sanitize(ind.get('severity', '').upper()), cell_bold),
            Paragraph(str(ind.get('count', 0)), cell_regular),
            Paragraph(f"{ind.get('percentage', 0.0)}%", cell_regular)
        ])

    it = Table(ind_table_rows, colWidths=[180, 80, 70, 84, 90])
    it.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_BG_CARD),
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(it)

    # Trend Comparison
    story.append(Paragraph("4. Period-over-Period Trend Analysis", h2_style))
    has_data = trends.get('has_sufficient_data', False)
    summary_msg = trends.get('summary_message', 'Not enough data to identify a trend.')
    trend_p = Paragraph(f"<b>Trend Assessment:</b> {_sanitize(summary_msg)}", cell_regular)
    story.append(trend_p)

    if has_data:
        m = trends.get('metrics', {})
        t_scans = m.get('total_scans', {})
        t_threats = m.get('high_or_critical_scans', {})
        t_inconc = m.get('inconclusive_scans', {})

        def _fmt_t(d):
            chg = d.get('absolute_change', 0)
            pct = d.get('percentage_change')
            sign = "+" if chg > 0 else ""
            if pct is not None:
                return f"{sign}{chg} ({sign}{pct}%)"
            return f"{sign}{chg} (new activity)"

        trend_rows = [
            [
                Paragraph("<b>Metric</b>", cell_bold),
                Paragraph("<b>Current Period</b>", cell_bold),
                Paragraph("<b>Previous Period</b>", cell_bold),
                Paragraph("<b>Observed Shift</b>", cell_bold)
            ],
            [
                Paragraph("Total Scans Recorded", cell_regular),
                Paragraph(str(trends.get('current_period', {}).get('total_scans', 0)), cell_regular),
                Paragraph(str(trends.get('previous_period', {}).get('total_scans', 0)), cell_regular),
                Paragraph(_fmt_t(t_scans), cell_bold)
            ],
            [
                Paragraph("High & Critical Detections", cell_regular),
                Paragraph(str(trends.get('current_period', {}).get('high_or_critical_scans', 0)), cell_regular),
                Paragraph(str(trends.get('previous_period', {}).get('high_or_critical_scans', 0)), cell_regular),
                Paragraph(_fmt_t(t_threats), cell_bold)
            ],
            [
                Paragraph("Inconclusive Assessments", cell_regular),
                Paragraph(str(trends.get('current_period', {}).get('inconclusive_scans', 0)), cell_regular),
                Paragraph(str(trends.get('previous_period', {}).get('inconclusive_scans', 0)), cell_regular),
                Paragraph(_fmt_t(t_inconc), cell_bold)
            ]
        ]
        tt = Table(trend_rows, colWidths=[160, 114, 115, 115])
        tt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_BG_CARD),
            ('GRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(tt)

    story.append(Spacer(1, 6))
    notice_text = (
        "<b>Defensive Telemetry Disclaimer:</b> All metrics, distributions, and trend deltas displayed in this report "
        "represent local scanning activity observed by this QShield deployment. They do not constitute global cyber threat intelligence, "
        "nor do individual structural indicators represent definitive confirmation of phishing. Original full URL payloads and credentials "
        "are intentionally omitted under QShield's Privacy-by-Design architecture."
    )
    notice_p = Paragraph(notice_text, cell_small)
    notice_box = Table([[notice_p]], colWidths=[504])
    notice_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_TEAL_LIGHT),
        ('BOX', (0, 0), (-1, -1), 0.5, COLOR_TEAL),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(notice_box)

    return build_pdf_document(story)
