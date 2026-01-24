"""
Flask configuration - INTENTIONALLY VULNERABLE for testing
These settings should NEVER be used in production
"""

import os

class Config:
    # CRITICAL: Debug mode enabled
    DEBUG = True
    TESTING = True

    # CRITICAL: Weak/hardcoded secret key
    SECRET_KEY = 'super-secret-key-12345'

    # HIGH: Session cookie insecure
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SAMESITE = None

    # CRITICAL: Hardcoded database credentials
    SQLALCHEMY_DATABASE_URI = 'postgresql://admin:password123@localhost/myapp'

    # HIGH: SQL query logging
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    # CRITICAL: Hardcoded API keys
    API_KEY = 'sk-1234567890abcdef'
    AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
    AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

    # HIGH: CORS allow all
    CORS_ORIGINS = '*'
    CORS_SUPPORTS_CREDENTIALS = True

    # HIGH: Upload configuration (unrestricted)
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB
    UPLOAD_FOLDER = '/tmp/uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'gif', 'exe', 'php', 'jsp'}  # Dangerous extensions!

    # MEDIUM: Mail server with credentials
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_USERNAME = 'myapp@gmail.com'
    MAIL_PASSWORD = 'email-password-123'

    # HIGH: Redis without auth
    REDIS_URL = 'redis://localhost:6379/0'

    # CRITICAL: Jinja2 autoescape disabled (XSS)
    TEMPLATES_AUTO_RELOAD = True
    # In template: {{ user_input | safe }}  # Dangerous!


class ProductionConfig(Config):
    """Production config - still vulnerable for testing"""
    DEBUG = True  # CRITICAL: Debug in production
    SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-insecure-key')  # Weak fallback
