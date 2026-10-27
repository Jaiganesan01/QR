"""
Main navigation and public view routes
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.utils import secure_filename
import urllib.parse

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html', active_page='home')

@main_bp.route('/scanner', methods=['GET', 'POST'])
def scanner_page():
    staged_result = False
    staged_content = None
    staged_type = None
    entered_url = None

    if request.method == 'POST':
        # Check if this was a manual URL submission
        if 'manual_url' in request.form:
            raw_url = request.form.get('manual_url', '').strip()
            entered_url = raw_url
            
            if not raw_url:
                flash("Please enter a web address to inspect.", "error")
            elif len(raw_url) > 2048:
                flash("URL exceeds maximum allowed length of 2048 characters.", "error")
            else:
                # Reject dangerous or non-web schemes explicitly first
                lower_url = raw_url.lower()
                if lower_url.startswith(('javascript:', 'data:', 'file:', 'vbscript:', 'blob:')):
                    flash("Unsupported or unsafe protocol. Only HTTP and HTTPS addresses are accepted.", "error")
                else:
                    # Validate protocol strictly (HTTP / HTTPS only)
                    parsed = urllib.parse.urlparse(raw_url if '://' in raw_url else 'http://' + raw_url)
                    if parsed.scheme.lower() not in ('http', 'https'):
                        flash("Unsupported or unsafe protocol. Only HTTP and HTTPS addresses are accepted.", "error")
                    elif not parsed.netloc:
                        flash("Please provide a valid hostname or web address.", "error")
                    else:
                        staged_result = True
                        staged_content = raw_url
                        staged_type = "URL (Manual Entry)"
                        
                        from app.core.url_analyzer import analyze_url_heuristics
                        from app.core.risk_scorer import calculate_risk_score
                        url_res = analyze_url_heuristics(raw_url)
                        risk_res = calculate_risk_score(url_res)
                        flash(f"URL analysis complete: {risk_res.get('risk_level', 'inconclusive').capitalize()} Risk ({risk_res.get('score', 0)}/100).", "info")

        # Check if this was a file upload
        elif 'qr_file' in request.files:
            file = request.files['qr_file']
            if not file or file.filename == '':
                flash("No file was selected. Please choose a QR code image to inspect.", "error")
            else:
                filename = secure_filename(file.filename)
                allowed_extensions = {'.png', '.jpg', '.jpeg', '.webp'}
                ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                
                if ext not in allowed_extensions:
                    flash(f"Unsupported format '{ext}'. Please upload a PNG, JPG, JPEG, or WebP image.", "error")
                else:
                    file_bytes = file.read()
                    max_bytes = current_app.config.get('MAX_CONTENT_LENGTH', 5 * 1024 * 1024)
                    if len(file_bytes) > max_bytes:
                        flash("The uploaded file exceeds the maximum 5 MB upload limit.", "error")
                    else:
                        from app.core.qr_decoder import decode_qr_image_bytes
                    decode_res = decode_qr_image_bytes(file_bytes)
                    
                    if decode_res["success"]:
                        staged_result = True
                        staged_content = decode_res["decoded_content"]
                        staged_type = decode_res["payload_type"]
                        flash("QR code successfully decoded. Click 'Analyze URL Structure' to review security indicators.", "info")
                    else:
                        flash(decode_res["message"], "error")

    return render_template(
        'scan.html',
        active_page='scanner',
        staged_result=staged_result,
        staged_content=staged_content,
        staged_type=staged_type,
        entered_url=entered_url
    )

@main_bp.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html', active_page='how_it_works')

@main_bp.route('/awareness')
def awareness():
    return render_template('awareness.html', active_page='awareness')

@main_bp.route('/academy')
def academy():
    return render_template('academy.html', active_page='academy')

@main_bp.route('/history')
def scan_history_page():
    return render_template('history.html', active_page='history')

@main_bp.route('/admin')
@main_bp.route('/analytics')
def admin_dashboard_page():
    return render_template('admin.html', active_page='admin')

@main_bp.route('/about')
def about():
    return render_template('about.html', active_page='about')

@main_bp.route('/privacy')
def privacy():
    return render_template('privacy.html', active_page='privacy')
