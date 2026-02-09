import os
from datetime import timedelta


def _get_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "10"))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        days=int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", "7"))
    )

    OTP_EXPIRES_MINUTES = int(os.getenv("OTP_EXPIRES_MINUTES", "5"))
    RESET_TOKEN_EXPIRES_MINUTES = int(os.getenv("RESET_TOKEN_EXPIRES_MINUTES", "30"))
    CSRF_PROTECT = _get_bool(os.getenv("CSRF_PROTECT"), True)
    CSRF_COOKIE_SAMESITE = os.getenv("CSRF_COOKIE_SAMESITE")
    CSRF_COOKIE_SECURE = _get_bool(os.getenv("CSRF_COOKIE_SECURE"), False)
    RATE_LIMIT_ENABLED = _get_bool(os.getenv("RATE_LIMIT_ENABLED"), True)

    MAIL_SENDER = os.getenv("MAIL_SENDER")
    FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL")

    SMTP_ENABLED = _get_bool(os.getenv("SMTP_ENABLED"), False)
    SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    SMTP_USE_TLS = _get_bool(os.getenv("SMTP_USE_TLS"), True)
    SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "10"))
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI")
