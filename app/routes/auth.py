from datetime import timedelta

from flask import Blueprint, request, jsonify, current_app
from app.utils.tenantidGeneratory import generate_tenant_id
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity

from app.extensions import db, limiter
from app.models import (
    User,
    Tenant,
    OtpSession,
    OtpPurpose,
    LoginAttempt,
    UserStatus,
    PasswordResetToken,
    PasswordChangeHistory,
    PasswordChangeReason,
    AuthSession,
    utcnow,
)
from app.security import (
    hash_password,
    verify_password,
    generate_numeric_otp,
    generate_token,
    hash_token,
)
from app.services.email_service import send_email
from app.services.token_service import issue_tokens, revoke_all_sessions
from app.utils.validators import validate_password_strength, validate_email_format
from app.utils.responses import error_response


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# Rate limiting decorator - can be disabled via config
def _rate_limit(limit_str: str):
    def decorator(func):
        # Rate limiting is applied at init time in app/__init__.py
        # This decorator is a placeholder for documentation
        return func
    return decorator


@auth_bp.route("/register/initiate", methods=["POST"])
@_rate_limit("5 per minute")
def register_initiate():
    payload = request.get_json() or {}
    username = payload.get("username")
    email = payload.get("email")
    password = payload.get("password")

    if not all([username, email, password, ]):
        return error_response("Missing required fields")
    if not validate_email_format(email):
        return error_response("Invalid email")
    if not validate_password_strength(password):
        return error_response("Weak password")

    tenant_id = generate_tenant_id(email, username)

    existing = User.query.filter_by(email=email).first()
    if existing:
        return error_response("Email already registered", 409)

    existing_username = User.query.filter_by(username=username).first()
    if existing_username:
        return error_response("Username already registered", 409)

    hashed_password = hash_password(password)
    user = User(
        tenant_id=tenant_id,
        username=username,
        email=email,
        password_hash=hashed_password,
        email_verified=False,
        status=UserStatus.ACTIVE,
    )
    db.session.add(user)

    otp = generate_numeric_otp(6)
    temp_token = generate_token()
    secret = current_app.config.get("SECRET_KEY")
    otp_hash = hash_token(otp, secret)
    temp_token_hash = hash_token(temp_token, secret)

    expires_at = utcnow() + timedelta(minutes=current_app.config["OTP_EXPIRES_MINUTES"])
    otp_session = OtpSession(
        email=email,
        tenant_id=tenant_id,
        otp_hash=otp_hash,
        temp_token=temp_token_hash,
        expires_at=expires_at,
        attempts=0,
        purpose=OtpPurpose.REGISTER,
    )
    db.session.add(otp_session)
    db.session.commit()

    send_email(
        to_email=email,
        subject="Verify Your Email - REX",
        template_name="otp_verification",
        context={
            "username": username,
            "otp_code": otp,
            "otp_expiry": current_app.config["OTP_EXPIRES_MINUTES"],
        },
    )

    return jsonify({"message": "OTP sent", "temp_token": temp_token})


@auth_bp.route("/register/verify", methods=["POST"])
@_rate_limit("5 per minute")
def register_verify():
    payload = request.get_json() or {}
    email = payload.get("email")
    otp = payload.get("otp")
    temp_token = payload.get("temp_token")

    if not all([email, otp, temp_token]):
        return error_response("Missing required fields")

    secret = current_app.config.get("SECRET_KEY")
    temp_token_hash = hash_token(temp_token, secret)
    otp_session = OtpSession.query.filter_by(email=email, temp_token=temp_token_hash, purpose=OtpPurpose.REGISTER).first()

    if not otp_session:
        return error_response("Invalid or expired OTP session", 400)
    if otp_session.expires_at < utcnow():
        return error_response("OTP expired", 400)
    if otp_session.attempts >= 3:
        return error_response("OTP attempts exceeded", 429)

    otp_hash = hash_token(otp, secret)
    otp_session.attempts += 1

    if otp_hash != otp_session.otp_hash:
        db.session.commit()
        return error_response("Invalid OTP", 400)

    user = User.query.filter_by(email=email, tenant_id=otp_session.tenant_id).first()
    if not user:
        return error_response("User not found", 404)

    user.email_verified = True
    user.status = UserStatus.ACTIVE
    db.session.delete(otp_session)
    db.session.commit()

    access_token, refresh_token = issue_tokens(
        user,
        tenant_id=user.tenant_id,
        device_info=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )

    send_email(
        to_email=email,
        subject="Welcome to REX - Account Verified",
        template_name="welcome",
        context={
            "username": user.username,
            "dashboard_url": f"{current_app.config['FRONTEND_BASE_URL']}/dashboard",
        },
    )

    return jsonify(
        {
            "tenant_id": user.tenant_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
        }
    )


@auth_bp.route("/login", methods=["POST"])
@_rate_limit("10 per minute")
def login():
    payload = request.get_json() or {}
    email = payload.get("email")
    password = payload.get("password")
    tenant_id = payload.get("tenant_id")

    if not all([email, password, tenant_id]):
        return error_response("Missing required fields")

    attempt = LoginAttempt.query.filter_by(email=email, tenant_id=tenant_id).first()
    now = utcnow()

    if attempt and attempt.ban_until and attempt.ban_until > now:
        return error_response("Account temporarily banned", 403)

    user = User.query.filter_by(email=email, tenant_id=tenant_id).first()
    if not user or not verify_password(password, user.password_hash):
        attempt = attempt or LoginAttempt(email=email, tenant_id=tenant_id, attempt_count=0)
        attempt.attempt_count += 1
        attempt.last_attempt_at = now

        if attempt.attempt_count == 4:
            attempt.ban_until = now + timedelta(hours=1)
            if user:
                user.status = UserStatus.TEMP_BANNED
        elif attempt.attempt_count == 5:
            attempt.ban_until = now + timedelta(hours=6)
            if user:
                user.status = UserStatus.TEMP_BANNED
        elif attempt.attempt_count >= 6:
            if user:
                user.status = UserStatus.HARD_BANNED
            attempt.ban_until = None

        db.session.add(attempt)
        db.session.commit()
        return error_response("Invalid credentials", 401)

    if user.status == UserStatus.HARD_BANNED:
        return error_response("Account permanently banned", 403)
    if user.status == UserStatus.TEMP_BANNED:
        return error_response("Account temporarily banned", 403)

    if not user.email_verified:
        return error_response("Email not verified", 403)

    user.last_login_at = now
    if attempt:
        attempt.attempt_count = 0
        attempt.ban_until = None
        attempt.last_attempt_at = now
    if user.status == UserStatus.TEMP_BANNED:
        user.status = UserStatus.ACTIVE
    db.session.commit()

    access_token, refresh_token = issue_tokens(
        user,
        tenant_id=tenant_id,
        device_info=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )

    return jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "tenant_id": tenant_id,
            "expires_in": int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
        }
    )


@auth_bp.route("/token/refresh", methods=["POST"])
@jwt_required(refresh=True)
@_rate_limit("20 per minute")
def refresh_token():
    jwt_data = get_jwt()
    user_id = get_jwt_identity()
    jti = jwt_data.get("jti")

    session = AuthSession.query.filter_by(refresh_token_jti=jti, revoked=False).first()
    if not session:
        return error_response("Invalid refresh token", 401)
    if session.expires_at < utcnow():
        session.revoked = True
        db.session.commit()
        return error_response("Refresh token expired", 401)

    session.revoked = True
    db.session.commit()

    user = User.query.get(user_id)
    access_token, refresh_token = issue_tokens(
        user,
        tenant_id=session.tenant_id,
        device_info=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )

    return jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "tenant_id": session.tenant_id,
            "expires_in": int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
        }
    )


@auth_bp.route("/password/forgot", methods=["POST"])
@_rate_limit("5 per minute")
def forgot_password():
    payload = request.get_json() or {}
    email = payload.get("email")
    tenant_id = payload.get("tenant_id")

    if not all([email, tenant_id]):
        return error_response("Missing required fields")
    if not validate_email_format(email):
        return error_response("Invalid email")

    secret = current_app.config.get("SECRET_KEY")
    reset_token = generate_token()
    reset_token_hash = hash_token(reset_token, secret)
    expires_at = utcnow() + timedelta(minutes=current_app.config["RESET_TOKEN_EXPIRES_MINUTES"])

    user = User.query.filter_by(email=email, tenant_id=tenant_id).first()
    reset_record = PasswordResetToken(
        email=email,
        tenant_id=tenant_id,
        user_id=user.id if user else None,
        token_hash=reset_token_hash,
        expires_at=expires_at,
    )
    db.session.add(reset_record)
    db.session.commit()

    send_email(
        to_email=email,
        subject="Reset Your Password - REX",
        template_name="password_reset_request",
        context={
            "username": user.username if user else email,
            "reset_url": reset_url,
            "token_expiry": current_app.config["RESET_TOKEN_EXPIRES_MINUTES"],
        },
    )

    return jsonify({"message": "Password reset email sent"})


@auth_bp.route("/password/reset", methods=["POST"])
@_rate_limit("5 per minute")
def reset_password():
    payload = request.get_json() or {}
    reset_token = payload.get("reset_token")
    new_password = payload.get("new_password")

    if not all([reset_token, new_password]):
        return error_response("Missing required fields")
    if not validate_password_strength(new_password):
        return error_response("Weak password")

    secret = current_app.config.get("SECRET_KEY")
    reset_token_hash = hash_token(reset_token, secret)

    record = PasswordResetToken.query.filter_by(token_hash=reset_token_hash, used_at=None).first()
    if not record or record.expires_at < utcnow():
        return error_response("Invalid or expired token", 400)
    if not record.user_id:
        return error_response("Invalid or expired token", 400)

    user = User.query.get(record.user_id)
    if not user:
        return error_response("Invalid token", 400)

    user.password_hash = hash_password(new_password)
    record.used_at = utcnow()

    history = PasswordChangeHistory(
        user_id=user.id,
        change_reason=PasswordChangeReason.RESET,
    )
    db.session.add(history)
    db.session.commit()

    send_email(
        to_email=user.email,
        subject="Password Changed Successfully - REX",
        template_name="password_reset_success",
        context={"username": user.username},
    )

    return jsonify({"message": "Password updated"})
