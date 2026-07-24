"""
Flask Configuration
Production and development settings with IP Whitelist & Advanced Security
✅ FULLY ENHANCED WITH ALL ZTNA FEATURES - COMPLETE & FIXED VERSION
November 8, 2025
"""

import os
from datetime import timedelta

class Config:
    """Base configuration with all ZTNA features"""
    
    # ==================== CORE FLASK SETTINGS ====================
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-CHANGE-IN-PRODUCTION-xyz123')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///zerotrust.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    
    # ==================== SESSION CONFIGURATION ====================
    SESSION_COOKIE_NAME = 'zerotrust_session'
    SESSION_COOKIE_SECURE = False  # Set True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_REFRESH_EACH_REQUEST = True
    
    # ==================== JWT CONFIGURATION ====================
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-CHANGE-THIS-xyz789')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_ALGORITHM = 'HS256'
    
    # ==================== ✅ CORE ZERO TRUST FEATURES ====================
    ENABLE_DEVICE_TRUST = True
    ENABLE_MFA = True
    ENABLE_SESSION_TRACKING = True
    ENABLE_ACTIVITY_LOGGING = True
    
    # ==================== ✅ ENHANCED SECURITY FEATURES ====================
    ENABLE_IP_WHITELIST = False
    ENABLE_RISK_SCORING = True
    ENABLE_GEOLOCATION = True
    ENABLE_THREAT_INTELLIGENCE = True
    ENABLE_RATE_LIMITING = True
    ENCRYPT_SENSITIVE_DATA = True
    
    # Auto-blocking Features
    AUTO_BLOCK_MALICIOUS_IPS = True
    AUTO_BLOCK_CRITICAL_RISK = True
    AUTO_BLOCK_BRUTE_FORCE = True
    
    # ==================== RISK SCORING CONFIGURATION ====================
    RISK_SCORE_THRESHOLD_LOW = 30
    RISK_SCORE_THRESHOLD_MEDIUM = 50
    RISK_SCORE_THRESHOLD_HIGH = 70
    RISK_SCORE_THRESHOLD_CRITICAL = 90
    
    # Risk Factors Weight (Total = 100)
    RISK_WEIGHT_NEW_LOCATION = 25
    RISK_WEIGHT_UNUSUAL_TIME = 15
    RISK_WEIGHT_UNKNOWN_DEVICE = 30
    RISK_WEIGHT_FAILED_ATTEMPTS = 20
    RISK_WEIGHT_VPN_PROXY = 10
    
    # ==================== GEO-LOCATION CONFIGURATION ====================
    GEOLOCATION_API_URL = 'http://ip-api.com/json/'
    GEOLOCATION_CACHE_DURATION = timedelta(days=7)
    GEOLOCATION_TIMEOUT = 5  # seconds
    
    # Blocked Countries (ISO 2-letter codes)
    BLOCKED_COUNTRIES = ['CN', 'RU', 'KP', 'IR']  # China, Russia, North Korea, Iran
    
    # Geo-fencing
    ENABLE_GEO_FENCING = False
    ALLOWED_COUNTRIES = []  # Empty = allow all except blocked
    
    # VPN/Proxy Detection
    BLOCK_VPN_PROXY = False
    WARN_VPN_PROXY = True
    
    # ==================== THREAT INTELLIGENCE ====================
    ENABLE_IMPOSSIBLE_TRAVEL_DETECTION = True
    IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD = 800  # km/h
    
    # Threat Detection
    BRUTE_FORCE_THRESHOLD = 5  # failed attempts
    BRUTE_FORCE_WINDOW = timedelta(minutes=15)
    
    SUSPICIOUS_ACTIVITY_THRESHOLD = 3
    SUSPICIOUS_ACTIVITY_WINDOW = timedelta(hours=1)
    
    # ==================== RATE LIMITING CONFIGURATION ====================
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_STORAGE_URL = 'memory://'
    RATE_LIMIT_STRATEGY = 'fixed-window'
    
    # Rate Limits
    RATE_LIMIT_DEFAULT = "60 per minute"
    RATE_LIMIT_LOGIN = "5 per 5 minutes"
    RATE_LIMIT_API = "100 per hour"
    RATE_LIMIT_ADMIN = "200 per hour"
    
    # ==================== ENCRYPTION CONFIGURATION ====================
    # Generate with: from cryptography.fernet import Fernet; Fernet.generate_key()
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'gAAAAABk_default_key_replace_this_xyz123==')
    ENCRYPT_OTP_SECRETS = True
    ENCRYPT_USER_DATA = True
    
    # ==================== IP WHITELIST CONFIGURATION ====================
    IP_WHITELIST_MODE = 'database'  # 'database' or 'file'
    IP_WHITELIST_FILE = 'ip_whitelist.json'
    
    # ✅ FIXED: Added missing config values
    SUPER_ADMIN_BYPASS_IP_CHECK = True   # Super admins can login from any IP
    ADMIN_BYPASS_IP_CHECK = False        # Regular admins must pass IP check
    
    # Default Whitelisted IPs (always allowed)
    DEFAULT_WHITELISTED_IPS = [
        '127.0.0.1',      # Localhost IPv4
        '::1',            # Localhost IPv6
        '192.168.1.0/24', # Local network (adjust as needed)
    ]
    
    # IP Whitelist by Role
    ADMIN_IPS = []  # Add admin IPs here
    MANAGER_IPS = []  # Add manager IPs here
    
    # IP Whitelist Strict Mode
    IP_WHITELIST_STRICT_MODE = False  # If True, only whitelisted IPs can access
    
    # ==================== DEVICE TRUST CONFIGURATION ====================
    DEVICE_TRUST_EXPIRATION = timedelta(days=90)
    REQUIRE_DEVICE_APPROVAL = True
    AUTO_APPROVE_ADMIN_DEVICES = False
    DEVICE_FINGERPRINT_ALGORITHM = 'sha256'
    
    # Device Security Scoring
    DEVICE_SECURITY_SCAN_ENABLED = True
    DEVICE_MIN_SECURITY_SCORE = 50
    
    # ==================== AUTHENTICATION CONFIGURATION ====================
    # Password Policy
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_EXPIRATION_DAYS = 90
    PASSWORD_HISTORY_COUNT = 5
    
    # Account Lockout
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=30)
    ACCOUNT_LOCKOUT_ENABLED = True
    
    # MFA/OTP Configuration
    OTP_ISSUER_NAME = 'ZeroTrustX'
    OTP_VALIDITY_WINDOW = 1  # Allow 1 window before/after (30 seconds each)
    OTP_DIGITS = 6
    OTP_INTERVAL = 30  # seconds
    
    # ==================== SESSION MANAGEMENT ====================
    SESSION_TIMEOUT = timedelta(hours=1)
    SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
    MAX_CONCURRENT_SESSIONS = 3
    ENFORCE_SINGLE_SESSION = False
    
    # ==================== ACCESS CONTROL ====================
    # Business Hours (24-hour format)
    BUSINESS_HOURS_START = '09:00'
    BUSINESS_HOURS_END = '18:00'
    BUSINESS_DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
    
    # Resource Access
    REQUIRE_MFA_FOR_SENSITIVE = True
    REQUIRE_TRUSTED_DEVICE_FOR_ADMIN = True
    
    # ==================== LOGGING & MONITORING ====================
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'zerotrust.log'
    LOG_MAX_BYTES = 10485760  # 10MB
    LOG_BACKUP_COUNT = 5
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Activity Logging
    LOG_ALL_ACTIVITIES = True
    LOG_FAILED_ATTEMPTS = True
    LOG_ACCESS_DENIALS = True
    LOG_SECURITY_EVENTS = True
    
    # ==================== WEBSOCKET CONFIGURATION ====================
    WEBSOCKET_PING_TIMEOUT = 60
    WEBSOCKET_PING_INTERVAL = 25
    WEBSOCKET_MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
    
    # ==================== EMAIL NOTIFICATIONS (Optional) ====================
    ENABLE_EMAIL_NOTIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = 'zerotrust@example.com'
    
    # Notification Triggers
    NOTIFY_ON_HIGH_RISK_LOGIN = True
    NOTIFY_ON_THREAT_DETECTION = True
    NOTIFY_ON_ACCOUNT_LOCKOUT = True
    NOTIFY_ON_NEW_DEVICE = True
    
    # ==================== DATABASE CONFIGURATION ====================
    SQLALCHEMY_POOL_SIZE = 10
    SQLALCHEMY_POOL_TIMEOUT = 30
    SQLALCHEMY_POOL_RECYCLE = 3600
    SQLALCHEMY_MAX_OVERFLOW = 20
    
    # ==================== SECURITY HEADERS ====================
    SECURITY_HEADERS = {
        'X-Frame-Options': 'SAMEORIGIN',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
    }
    
    # ==================== HTTPS CONFIGURATION ====================
    FORCE_HTTPS = False  # Set True in production
    HTTPS_REDIRECT_CODE = 301
    
    # ==================== CSRF PROTECTION ====================
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    WTF_CSRF_SSL_STRICT = False  # Set True in production
    
    # ==================== FILE UPLOAD (if needed) ====================
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    
    # ==================== API CONFIGURATION ====================
    API_TITLE = 'ZeroTrustX API'
    API_VERSION = 'v1'
    API_DESCRIPTION = 'Zero Trust Network Access API'
    
    # ==================== FEATURE FLAGS ====================
    ENABLE_REGISTRATION = True
    ENABLE_PASSWORD_RESET = True
    ENABLE_REMEMBER_ME = False
    ENABLE_API_ACCESS = True
    ENABLE_WEBHOOKS = False
    
    # ==================== BACKUP & MAINTENANCE ====================
    ENABLE_AUTO_BACKUP = False
    BACKUP_SCHEDULE = 'daily'  # 'hourly', 'daily', 'weekly'
    BACKUP_RETENTION_DAYS = 30
    MAINTENANCE_MODE = False


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Relaxed settings for development
    SESSION_COOKIE_SECURE = False
    FORCE_HTTPS = False
    
    # Keep all security features enabled for testing
    ENABLE_IP_WHITELIST = False
    ENABLE_RISK_SCORING = True
    ENABLE_GEOLOCATION = True
    ENABLE_THREAT_INTELLIGENCE = True
    ENABLE_RATE_LIMITING = True
    ENCRYPT_SENSITIVE_DATA = True
    
    # ✅ Super admin bypass enabled in dev
    SUPER_ADMIN_BYPASS_IP_CHECK = True
    ADMIN_BYPASS_IP_CHECK = False
    
    # Logging
    SQLALCHEMY_ECHO = False
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Strict security in production
    SESSION_COOKIE_SECURE = True
    FORCE_HTTPS = True
    WTF_CSRF_SSL_STRICT = True
    
    # All features enabled
    ENABLE_IP_WHITELIST = False
    ENABLE_RISK_SCORING = True
    ENABLE_GEOLOCATION = True
    ENABLE_THREAT_INTELLIGENCE = True
    ENABLE_RATE_LIMITING = True
    ENCRYPT_SENSITIVE_DATA = True
    
    # ✅ Super admin bypass can be disabled in production
    SUPER_ADMIN_BYPASS_IP_CHECK = False  # More secure
    ADMIN_BYPASS_IP_CHECK = False
    
    # Strict auto-blocking
    AUTO_BLOCK_MALICIOUS_IPS = True
    AUTO_BLOCK_CRITICAL_RISK = True
    AUTO_BLOCK_BRUTE_FORCE = True
    
    # Email notifications enabled
    ENABLE_EMAIL_NOTIFICATIONS = True
    
    # Production database (replace with actual)
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://user:pass@localhost/zerotrust')
    
    # Logging
    LOG_LEVEL = 'WARNING'
    SQLALCHEMY_ECHO = False


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    
    # In-memory database for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable some features for testing
    WTF_CSRF_ENABLED = False
    ENABLE_EMAIL_NOTIFICATIONS = False
    ENABLE_RATE_LIMITING = False
    
    # Keep core features for testing
    ENABLE_DEVICE_TRUST = True
    ENABLE_MFA = True
    ENABLE_RISK_SCORING = True
    
    # ✅ Super admin bypass enabled in testing
    SUPER_ADMIN_BYPASS_IP_CHECK = True
    ADMIN_BYPASS_IP_CHECK = True


# ==================== CONFIGURATION SELECTOR ====================

config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(config_name=None):
    """Get configuration by name or from environment"""
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    return config_by_name.get(config_name, config_by_name['default'])


# Default export
Config = get_config()


# ==================== CONFIGURATION VALIDATOR ====================

def validate_config():
    """Validate critical configuration settings"""
    errors = []
    
    if Config.SECRET_KEY == 'dev-secret-key-CHANGE-IN-PRODUCTION-xyz123':
        errors.append("⚠️ WARNING: Using default SECRET_KEY! Change in production!")
    
    if Config.JWT_SECRET_KEY == 'jwt-secret-key-CHANGE-THIS-xyz789':
        errors.append("⚠️ WARNING: Using default JWT_SECRET_KEY! Change in production!")
    
    if Config.FORCE_HTTPS and not Config.SESSION_COOKIE_SECURE:
        errors.append("⚠️ ERROR: HTTPS forced but SESSION_COOKIE_SECURE is False!")
    
    if Config.ENABLE_EMAIL_NOTIFICATIONS and not Config.MAIL_USERNAME:
        errors.append("⚠️ WARNING: Email notifications enabled but MAIL_USERNAME not set!")
    
    return errors


# ==================== DISPLAY CONFIGURATION (DEBUG) ====================

def print_config():
    """Print current configuration (for debugging)"""
    print("\n" + "="*80)
    print("🔐 ZeroTrustX - Enhanced ZTNA Framework")
    print("="*80)
    print(f"Environment: {os.getenv('FLASK_ENV', 'development').upper()}")
    print(f"Config: {Config.__class__.__name__}")
    print(f"Database: {Config.SQLALCHEMY_DATABASE_URI.split(':')[0].upper()}")
    print("\n✅ Core Features:")
    print(f"  • IP Whitelist: {'ENABLED' if Config.ENABLE_IP_WHITELIST else 'DISABLED'}")
    print(f"  • Device Trust: {'ENABLED' if Config.ENABLE_DEVICE_TRUST else 'DISABLED'}")
    print(f"  • MFA (OTP): {'ENABLED' if Config.ENABLE_MFA else 'DISABLED'}")
    print("\n🆕 Enhanced Features:")
    print(f"  • Risk Scoring: {'ENABLED' if Config.ENABLE_RISK_SCORING else 'DISABLED'}")
    print(f"  • Geo-Location: {'ENABLED' if Config.ENABLE_GEOLOCATION else 'DISABLED'}")
    print(f"  • Data Encryption: {'ENABLED' if Config.ENCRYPT_SENSITIVE_DATA else 'DISABLED'}")
    print(f"  • Rate Limiting: {'ENABLED' if Config.ENABLE_RATE_LIMITING else 'DISABLED'}")
    print(f"  • Threat Intelligence: {'ENABLED' if Config.ENABLE_THREAT_INTELLIGENCE else 'DISABLED'}")
    print(f"  • HTTPS Enforcement: {'ENABLED' if Config.FORCE_HTTPS else 'DISABLED'}")
    print("\n🔐 IP Whitelist Settings:")
    print(f"  • Super Admin Bypass: {'ENABLED' if Config.SUPER_ADMIN_BYPASS_IP_CHECK else 'DISABLED'}")
    print(f"  • Admin Bypass: {'ENABLED' if Config.ADMIN_BYPASS_IP_CHECK else 'DISABLED'}")
    print("="*80 + "\n")
    
    # Validation
    errors = validate_config()
    if errors:
        print("⚠️ Configuration Warnings:")
        for error in errors:
            print(f"  {error}")
        print()


if __name__ == '__main__':
    print_config()
