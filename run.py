"""
Application Entry Point for QShield.
Supports development and production execution modes.
Exports the WSGI callable 'app' for production servers (e.g., Gunicorn).
"""
import os
from dotenv import load_dotenv
from app import create_app
from config import DevelopmentConfig, ProductionConfig

# Load environment variables from .env file if present
load_dotenv()

# Determine environment configuration
flask_env = os.environ.get('FLASK_ENV', 'development').strip().lower()
flask_debug = os.environ.get('FLASK_DEBUG', '1').strip().lower() in ('1', 'true', 'yes')

if flask_env == 'production' or not flask_debug:
    config_class = ProductionConfig
else:
    config_class = DevelopmentConfig

# Create WSGI application instance
app = create_app(config_class)

if __name__ == '__main__':
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    debug_mode = app.config.get('DEBUG', False)
    print(f"[*] Starting QShield on http://{host}:{port} (debug={debug_mode})")
    app.run(host=host, port=port, debug=debug_mode)
