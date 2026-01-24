"""
Django settings.py - INTENTIONALLY VULNERABLE for testing
These settings should NEVER be used in production
"""

import os

# CRITICAL: Debug mode exposes sensitive info
DEBUG = True

# CRITICAL: Weak/hardcoded secret key
SECRET_KEY = 'django-insecure-abc123-hardcoded-key-for-testing'

# HIGH: Allow all hosts
ALLOWED_HOSTS = ['*']

# HIGH: CSRF disabled
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False

# HIGH: Session cookie insecure
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False

# HIGH: Clickjacking protection disabled
X_FRAME_OPTIONS = 'ALLOW'

# MEDIUM: Password validators disabled
AUTH_PASSWORD_VALIDATORS = []

# HIGH: SQL logging with sensitive data
LOGGING = {
    'version': 1,
    'handlers': {
        'file': {
            'class': 'logging.FileHandler',
            'filename': '/var/log/django/debug.log',
        },
    },
    'loggers': {
        'django.db.backends': {
            'level': 'DEBUG',  # Logs all SQL queries
            'handlers': ['file'],
        },
    },
}

# Database with hardcoded credentials
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'myapp',
        'USER': 'admin',
        'PASSWORD': 'SuperSecret123!',  # CRITICAL: Hardcoded password
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

# CRITICAL: Pickle-based session serializer (RCE risk)
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'

# HIGH: Security middleware disabled
MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
    # SecurityMiddleware is missing!
    # 'django.middleware.security.SecurityMiddleware',
]

# HIGH: HTTPS not enforced
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
