"""
QShield Application Configuration
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-insecure-key-qshield-2026')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 5 * 1024 * 1024)) # 5MB limit
    UPLOAD_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp', '.bmp'}
    
    # SQLite Database
    DATABASE_PATH = os.environ.get('DATABASE_PATH', str(BASE_DIR / 'instance' / 'qshield.db'))
    
    # Security controls
    ENABLE_OUTBOUND_FETCH = False # Strict SSRF protection: never fetch user URLs by default
    
    # Administrative Authorization Key (Optional in dev, required in production)
    ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', '')

    # Threat Intelligence Keys (Optional)
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

    # Image Processing Defense Bounds (Decompression bomb prevention)
    MAX_IMAGE_WIDTH = int(os.environ.get('MAX_IMAGE_WIDTH', 4096))
    MAX_IMAGE_HEIGHT = int(os.environ.get('MAX_IMAGE_HEIGHT', 4096))
    MAX_IMAGE_PIXELS = int(os.environ.get('MAX_IMAGE_PIXELS', 16_000_000))

    # Rate Limiting Configuration
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'true').lower() in ('1', 'true', 'yes')
    RATELIMIT_DEFAULT_WINDOW = int(os.environ.get('RATELIMIT_DEFAULT_WINDOW', 60))
    RATELIMIT_DECODE = int(os.environ.get('RATELIMIT_DECODE', 30))
    RATELIMIT_ANALYZE = int(os.environ.get('RATELIMIT_ANALYZE', 60))
    RATELIMIT_REPUTATION = int(os.environ.get('RATELIMIT_REPUTATION', 15))
    RATELIMIT_REDIRECT = int(os.environ.get('RATELIMIT_REDIRECT', 15))
    RATELIMIT_REPORT = int(os.environ.get('RATELIMIT_REPORT', 20))

    # Cookie and Session Protections
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

class TestingConfig(Config):
    TESTING = True
    DATABASE_PATH = ':memory:'
    RATELIMIT_ENABLED = False
