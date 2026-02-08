import hashlib
import secrets
from datetime import timedelta

from passlib.hash import argon2


def hash_password(password: str) -> str:
    return argon2.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return argon2.verify(password, hashed)


def generate_numeric_otp(length: int = 6) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(value: str, secret: str) -> str:
    payload = f"{secret}:{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def get_expiry(minutes: int) -> timedelta:
    return timedelta(minutes=minutes)
