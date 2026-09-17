"""
Backend Configuration & Environment Settings
--------------------------------------------
Loads application runtime configuration from system environment or .env file.
"""

import os
from dotenv import load_dotenv

# Load .env from project root if available
load_dotenv()

# System
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1")

# Test Target Server
TARGET_HOST = os.getenv("TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.getenv("TARGET_PORT", "8001"))
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "test_website/logs/access.log")

# Backend Server
BACKEND_HOST = os.getenv("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_detection.db")

# ML Model Paths
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.75"))
MODEL_PATH = os.getenv("MODEL_PATH", "ml/saved_models/threat_classifier.pkl")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "ml/saved_models/tfidf_vectorizer.pkl")

# Behavioral Thresholds
FAILED_LOGIN_THRESHOLD = int(os.getenv("FAILED_LOGIN_THRESHOLD", "5"))
FAILED_LOGIN_WINDOW_SEC = int(os.getenv("FAILED_LOGIN_WINDOW_SEC", "60"))
REQUEST_RATE_THRESHOLD = int(os.getenv("REQUEST_RATE_THRESHOLD", "25"))
REQUEST_RATE_WINDOW_SEC = int(os.getenv("REQUEST_RATE_WINDOW_SEC", "10"))

# Alert Settings
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "60"))

# Email Alerts
ENABLE_EMAIL_ALERTS = os.getenv("ENABLE_EMAIL_ALERTS", "False").lower() in ("true", "1")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_RECIPIENT_EMAIL = os.getenv("ALERT_RECIPIENT_EMAIL", "")

# SMS Alerts
ENABLE_SMS_ALERTS = os.getenv("ENABLE_SMS_ALERTS", "False").lower() in ("true", "1")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_PHONE = os.getenv("TWILIO_FROM_PHONE", "")
ALERT_RECIPIENT_PHONE = os.getenv("ALERT_RECIPIENT_PHONE", "")
