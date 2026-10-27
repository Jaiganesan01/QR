"""
QShield Application Factory
"""
import os
import logging
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from config import Config, DevelopmentConfig

logger = logging.getLogger(__name__)

def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure the instance directory exists for SQLite
    os.makedirs(app.instance_path, exist_ok=True)

    # Register Blueprints
    from app.routes.main import main_bp
    from app.routes.api import api_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    # Database setup and teardown
    from app.database import close_db, init_db
    app.teardown_appcontext(close_db)
    init_db(app)

    # Base health route for monitoring
    @app.route('/health')
    def health():
        return {"status": "ok", "app": "QShield", "tagline": "Decode the QR. Detect the Threat."}

    # Centralized Unified Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith('/api/'):
            msg = getattr(error, 'description', "The request was invalid or malformed.")
            return jsonify({
                "success": False,
                "error_code": "BAD_REQUEST",
                "message": msg
            }), 400
        return render_template('scan.html', active_page='scanner', staged_result=False, error_message="Invalid request"), 400

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith('/api/'):
            return jsonify({
                "success": False,
                "error_code": "NOT_FOUND",
                "message": "The requested API endpoint was not found."
            }), 404
        return render_template('scan.html', active_page='scanner', staged_result=False, error_message="Resource not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        if request.path.startswith('/api/'):
            return jsonify({
                "success": False,
                "error_code": "METHOD_NOT_ALLOWED",
                "message": "The HTTP method is not allowed for the requested endpoint."
            }), 405
        return render_template('scan.html', active_page='scanner', staged_result=False, error_message="Method not allowed"), 405

    @app.errorhandler(413)
    def request_entity_too_large(error):
        if request.path.startswith('/api/'):
            return jsonify({
                "success": False,
                "error_code": "FILE_TOO_LARGE",
                "message": "Request payload exceeds maximum allowed size of 5 MB."
            }), 413
        flash("The uploaded file exceeds the maximum 5 MB upload limit.", "error")
        return redirect(url_for('main.scanner_page'))

    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        if request.path.startswith('/api/'):
            return jsonify({
                "success": False,
                "error_code": "RATE_LIMIT_EXCEEDED",
                "message": "Rate limit exceeded. Please slow down your requests."
            }), 429
        return render_template('scan.html', active_page='scanner', staged_result=False, error_message="Too many requests. Please try again shortly."), 429

    @app.errorhandler(500)
    def internal_server_error(error):
        logger.error("Internal Server Error on %s: %s", request.path, str(error))
        if request.path.startswith('/api/'):
            return jsonify({
                "success": False,
                "error_code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected internal server error occurred. Please try again later."
            }), 500
        return render_template('scan.html', active_page='scanner', staged_result=False, error_message="An unexpected server error occurred"), 500

    # Defensive Security Headers
    @app.after_request
    def set_security_headers(response):
        # 1. Content Type Options (Nosniff)
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # 2. Frame Protection (Deny Clickjacking)
        response.headers['X-Frame-Options'] = 'DENY'

        # 3. Legacy XSS Filter Block
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # 4. Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # 5. Permissions Policy
        response.headers['Permissions-Policy'] = 'camera=(self), microphone=(), geolocation=(), payment=()'

        # 6. Content Security Policy (CSP)
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ]
        response.headers['Content-Security-Policy'] = "; ".join(csp_directives)

        # 7. Sensitive Endpoint Cache-Control
        if (request.path.startswith('/api/') or
            request.path.startswith('/admin') or
            request.path.startswith('/history')):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'

        return response

    return app
