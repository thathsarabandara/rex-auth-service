from datetime import datetime, timezone
from enum import Enum

from app.extensions import db


def utcnow():
    """Return current UTC time with timezone awareness."""
    return datetime.now(timezone.utc)


def ensure_aware(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware (convert naive to UTC)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class UserStatus(str, Enum):
    ACTIVE = "ACTIVE"
    TEMP_BANNED = "TEMP_BANNED"
    HARD_BANNED = "HARD_BANNED"


class OtpPurpose(str, Enum):
    REGISTER = "REGISTER"
    PASSWORD_RESET = "PASSWORD_RESET"


class PasswordChangeReason(str, Enum):
    RESET = "RESET"
    USER_ACTION = "USER_ACTION"
    ADMIN = "ADMIN"


class Tenant(db.Model):
    __tablename__ = "tenants"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    status = db.Column(
        db.Enum(UserStatus),
        default=UserStatus.ACTIVE,
        nullable=False,
    )
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime(timezone=True))

    __table_args__ = (
        db.UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        db.UniqueConstraint("tenant_id", "username", name="uq_user_tenant_username"),
    )


class OtpSession(db.Model):
    __tablename__ = "otp_sessions"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    otp_hash = db.Column(db.String(255), nullable=False)
    temp_token = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    sent_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    purpose = db.Column(db.Enum(OtpPurpose), nullable=False)


class AuthSession(db.Model):
    __tablename__ = "auth_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    access_token = db.Column(db.String(255), nullable=False)
    refresh_token = db.Column(db.String(255), nullable=False)
    refresh_token_jti = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    device_info = db.Column(db.String(255))
    ip_address = db.Column(db.String(64))


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    attempt_count = db.Column(db.Integer, default=0, nullable=False)
    ban_until = db.Column(db.DateTime(timezone=True))
    last_attempt_at = db.Column(
        db.DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        db.UniqueConstraint("tenant_id", "email", name="uq_login_attempts"),
    )


class PasswordChangeHistory(db.Model):
    __tablename__ = "password_change_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    changed_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    change_reason = db.Column(db.Enum(PasswordChangeReason), nullable=False)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    token_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True))
