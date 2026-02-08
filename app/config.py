import os
from datetime import timedelta


def _get_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:////app/data/app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRES_MINUTES", "10")))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", "7")))

    OTP_EXPIRES_MINUTES = int(os.getenv("OTP_EXPIRES_MINUTES", "5"))
    RESET_TOKEN_EXPIRES_MINUTES = int(os.getenv("RESET_TOKEN_EXPIRES_MINUTES", "20"))

    CSRF_PROTECT = _get_bool(os.getenv("CSRF_PROTECT", "true"), True)
    CSRF_COOKIE_SAMESITE = os.getenv("CSRF_COOKIE_SAMESITE", "None")
    CSRF_COOKIE_SECURE = _get_bool(os.getenv("CSRF_COOKIE_SECURE", "true"), True)
    RATE_LIMIT_ENABLED = _get_bool(os.getenv("RATE_LIMIT_ENABLED", "true"), True)

    MAIL_SENDER = os.getenv("MAIL_SENDER", "no-reply@example.com")
    FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "https://frontend.app")

    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
