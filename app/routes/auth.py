from datetime import timedelta

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from app.extensions import db, limiter
from app.models import (
    AuthSession,
    LoginAttempt,
    OtpPurpose,
    OtpSession,
    PasswordChangeHistory,
    PasswordChangeReason,
    PasswordResetToken,
    Tenant,
    User,
    UserStatus,
    ensure_aware,
    utcnow,
)
from app.security import (
    generate_numeric_otp,
    generate_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.services.email_service import send_email
from app.services.token_service import issue_tokens, revoke_all_sessions
from app.utils.request_handlers import get_request_data
from app.utils.responses import error_response
from app.utils.tenantidGeneratory import get_or_create_tenant
from app.utils.validators import validate_email_format, validate_password_strength

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# Rate limiting decorator - can be disabled via config
def _rate_limit(limit_str: str):
    def decorator(func):
        # Rate limiting is applied at init time in app/__init__.py
        # This decorator is a placeholder for documentation
        return func

    return decorator


def _set_token_cookies(
    response, access_token: str, refresh_token: str, expires_in: int
):
    """Set access and refresh tokens as httpOnly cookies."""
    # Access token cookie (short-lived, in-memory)
    response.set_cookie(
        "access_token",
        access_token,
        max_age=expires_in,
        httponly=True,
        secure=current_app.config.get("CSRF_COOKIE_SECURE", False),
        samesite=current_app.config.get("CSRF_COOKIE_SAMESITE", "None"),
        path="/",
    )

    # Refresh token cookie (long-lived)
    refresh_expires = int(
        current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds()
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        max_age=refresh_expires,
        httponly=True,
        secure=current_app.config.get("CSRF_COOKIE_SECURE", False),
        samesite=current_app.config.get("CSRF_COOKIE_SAMESITE", "None"),
        path="/",
    )

    return response


@auth_bp.route("/register/initiate", methods=["POST"])
@_rate_limit("5 per minute")
def register_initiate():
    payload = get_request_data()
    username = (payload.get("username") or "").strip()
    email = (payload.get("email") or "").strip()
    password = (payload.get("password") or "").strip()

    if not all([username, email, password]):
        return error_response("Missing required fields")
    if not validate_email_format(email):
        return error_response("Invalid email")
    if not validate_password_strength(password):
        return error_response("Weak password")

    tenant_id = get_or_create_tenant(email, username)

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
    payload = get_request_data()
    email = payload.get("email")
    otp = payload.get("otp")
    temp_token = payload.get("temp_token")

    if not all([email, otp, temp_token]):
        return error_response("Missing required fields")

    secret = current_app.config.get("SECRET_KEY")
    temp_token_hash = hash_token(temp_token, secret)
    otp_session = OtpSession.query.filter_by(
        email=email, temp_token=temp_token_hash, purpose=OtpPurpose.REGISTER
    ).first()

    if not otp_session:
        return error_response("Invalid or expired OTP session", 400)
    if ensure_aware(otp_session.expires_at) < utcnow():
        return error_response("OTP expired", 400)
    if otp_session.attempts >= 3:
        return error_response("OTP attempts exceeded", 429)
    if otp_session.is_used:
        return error_response("OTP already used", 400)

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
    otp_session.is_used = True
    db.session.commit()
    logger.info(f"User {user.id} - {user.email} verified their email")

    try:
        access_token, refresh_token = issue_tokens(
            user,
            tenant_id=user.tenant_id,
            device_info=request.headers.get("User-Agent"),
            ip_address=request.remote_addr,
        )
    except Exception as e:
        current_app.logger.error(f"Error issuing tokens: {type(e).__name__}: {str(e)}")
        current_app.logger.exception("Full traceback:")
        return error_response(f"Token generation failed: {str(e)}", 500)

    try:
        send_email(
            to_email=email,
            subject="Welcome to REX - Account Verified",
            template_name="welcome",
            context={
                "username": user.username,
                "dashboard_url": f"{current_app.config['FRONTEND_BASE_URL']}/dashboard",
            },
        )
    except Exception as e:
        current_app.logger.error(
            f"Error sending welcome email: {type(e).__name__}: {str(e)}"
        )
        current_app.logger.exception("Full traceback:")
        # Don't fail the entire registration if email fails, just log it

    response = jsonify(
        {
            "tenant_id": user.tenant_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": int(
                current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
            ),
        }
    )

    # Set tokens in httpOnly cookies
    _set_token_cookies(
        response,
        access_token,
        refresh_token,
        int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
    )

    return response


@auth_bp.route("/register/resend-otp", methods=["POST"])
@_rate_limit("5 per minute")
def resend_otp():
    """Resend OTP with 2-minute cooldown restriction."""
    payload = get_request_data()
    email = payload.get("email")
    temp_token = payload.get("temp_token")

    if not all([temp_token]):
        return error_response("Missing required fields")

    if not validate_email_format(email):
        return error_response("Invalid email")

    secret = current_app.config.get("SECRET_KEY")
    temp_token_hash = hash_token(temp_token, secret)

    # Find the OTP session
    otp_session = OtpSession.query.filter_by(
        email=email, temp_token=temp_token_hash, purpose=OtpPurpose.REGISTER
    ).first()

    if not otp_session:
        return error_response("Invalid or expired OTP session", 400)

    # Check if 2 minutes have passed since last send
    time_since_last_send = utcnow() - ensure_aware(otp_session.sent_at)
    resend_cooldown_seconds = 120  # 2 minutes

    if time_since_last_send.total_seconds() < resend_cooldown_seconds:
        seconds_remaining = int(
            resend_cooldown_seconds - time_since_last_send.total_seconds()
        )
        return error_response(
            f"Please wait {seconds_remaining} seconds before requesting a new OTP", 429
        )

    # Generate new OTP and temp token
    otp = generate_numeric_otp(6)
    new_temp_token = generate_token()
    otp_hash = hash_token(otp, secret)
    new_temp_token_hash = hash_token(new_temp_token, secret)

    # Update OTP session
    otp_session.otp_hash = otp_hash
    otp_session.temp_token = new_temp_token_hash
    otp_session.sent_at = utcnow()
    otp_session.attempts = 0  # Reset attempts on resend
    otp_session.expires_at = utcnow() + timedelta(
        minutes=current_app.config["OTP_EXPIRES_MINUTES"]
    )
    db.session.commit()

    # Send OTP email
    try:
        send_email(
            to_email=email,
            subject="Verify Your Email - REX (Resent)",
            template_name="otp_verification",
            context={
                "otp_code": otp,
                "otp_expiry": current_app.config["OTP_EXPIRES_MINUTES"],
            },
        )
    except Exception as e:
        current_app.logger.error(
            f"Error sending resend OTP email: {type(e).__name__}: {str(e)}"
        )
        current_app.logger.exception("Full traceback:")

    return jsonify({"message": "OTP resent successfully", "temp_token": new_temp_token})


@auth_bp.route("/login", methods=["POST"])
@_rate_limit("10 per minute")
def login():
    payload = get_request_data()
    email = payload.get("email")
    password = payload.get("password")

    if not all([email, password]):
        return error_response("Missing required fields")

    attempt = LoginAttempt.query.filter_by(email=email).first()
    now = utcnow()

    if attempt and attempt.ban_until and ensure_aware(attempt.ban_until) > now:
        return error_response("Account temporarily banned", 403)

    user = User.query.filter_by(email=email).first()
    if not user or not verify_password(password, user.password_hash):
        attempt = attempt or LoginAttempt(email=email, attempt_count=0)
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
        tenant_id=user.tenant_id,
        device_info=request.headers.get("User-Agent"),
        ip_address=request.remote_addr,
    )

    response = jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "tenant_id": user.tenant_id,
            "expires_in": int(
                current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
            ),
        }
    )

    # Set tokens in httpOnly cookies
    _set_token_cookies(
        response,
        access_token,
        refresh_token,
        int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
    )

    return response


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
    if ensure_aware(session.expires_at) < utcnow():
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

    response = jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "tenant_id": session.tenant_id,
            "expires_in": int(
                current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
            ),
        }
    )

    # Set tokens in httpOnly cookies
    _set_token_cookies(
        response,
        access_token,
        refresh_token,
        int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
    )

    return response


@auth_bp.route("/token/validate", methods=["GET"])
@_rate_limit("20 per minute")
def validate_token():
    """
    Validate access token. If expired, attempt to refresh using refresh token.
    Returns:
      - 200: Token is valid
      - 200 with new tokens: Token was refreshed
      - 401: Both tokens are invalid/expired
    """
    from flask_jwt_extended import verify_jwt_in_request
    from flask_jwt_extended.exceptions import JWTExtendedException

    try:
        # Try to verify access token
        verify_jwt_in_request(optional=False)
        user_id = get_jwt_identity()
        jwt_data = get_jwt()

        # Access token is valid
        user = User.query.get(user_id)
        if not user:
            return error_response("User not found", 404)

        return jsonify(
            {
                "message": "Token is valid",
                "user_id": str(user_id),
                "email": user.email,
                "username": user.username,
                "tenant_id": jwt_data.get("tenant_id"),
                "is_expired": False,
                "refreshed": False,
            }
        )

    except JWTExtendedException:
        # Access token is invalid or expired, try to refresh
        try:
            verify_jwt_in_request(
                optional=False, fresh=False
            )  # This won't help, trying different approach
        except:
            pass

        # Try to get refresh token from headers or cookies
        refresh_token = None
        auth_header = request.headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):
            # This would be access token, not refresh
            pass

        # Try to get refresh token from cookies
        refresh_token = request.cookies.get("refresh_token")

        if not refresh_token:
            # Try to get from Authorization header with "Refresh" prefix
            refresh_header = request.headers.get("X-Refresh-Token", "")
            if refresh_header:
                refresh_token = refresh_header

        if not refresh_token:
            return error_response(
                "Access token expired and no refresh token provided", 401
            )

        # Verify and use refresh token
        try:
            verify_jwt_in_request(refresh=True)
            jwt_data = get_jwt()
            user_id = get_jwt_identity()
            jti = jwt_data.get("jti")

            # Find and validate session
            session = AuthSession.query.filter_by(
                refresh_token_jti=jti, revoked=False
            ).first()
            if not session:
                return error_response("Invalid refresh token session", 401)

            if ensure_aware(session.expires_at) < utcnow():
                session.revoked = True
                db.session.commit()
                return error_response("Refresh token expired", 401)

            # Revoke old session and issue new tokens
            session.revoked = True
            db.session.commit()

            user = User.query.get(user_id)
            if not user:
                return error_response("User not found", 404)

            new_access_token, new_refresh_token = issue_tokens(
                user,
                tenant_id=session.tenant_id,
                device_info=request.headers.get("User-Agent"),
                ip_address=request.remote_addr,
            )

            response = jsonify(
                {
                    "message": "Token refreshed successfully",
                    "user_id": str(user_id),
                    "email": user.email,
                    "username": user.username,
                    "tenant_id": session.tenant_id,
                    "access_token": new_access_token,
                    "refresh_token": new_refresh_token,
                    "is_expired": True,
                    "refreshed": True,
                    "expires_in": int(
                        current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
                    ),
                }
            )

            # Set new tokens in cookies
            _set_token_cookies(
                response,
                new_access_token,
                new_refresh_token,
                int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
            )

            return response

        except JWTExtendedException:
            return error_response("Refresh token is also invalid or expired", 401)


@auth_bp.route("/password/forgot", methods=["POST"])
@_rate_limit("5 per minute")
def forgot_password():
    payload = get_request_data()
    email = payload.get("email")

    if not all([email]):
        return error_response("Missing required fields")
    if not validate_email_format(email):
        return error_response("Invalid email")

    secret = current_app.config.get("SECRET_KEY")
    reset_token = generate_token()
    reset_token_hash = hash_token(reset_token, secret)
    expires_at = utcnow() + timedelta(
        minutes=current_app.config["RESET_TOKEN_EXPIRES_MINUTES"]
    )

    user = User.query.filter_by(email=email).first()
    reset_record = PasswordResetToken(
        email=email,
        tenant_id=user.tenant_id if user else None,
        user_id=user.id if user else None,
        token_hash=reset_token_hash,
        expires_at=expires_at,
    )
    db.session.add(reset_record)
    db.session.commit()
    reset_url = (
        f"{current_app.config['FRONTEND_BASE_URL']}/reset-password?token={reset_token}"
    )
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


@auth_bp.route("/password/reset/validate", methods=["GET"])
@_rate_limit("10 per minute")
def validate_reset_token():
    """Validate password reset token before allowing password change."""
    reset_token = request.args.get("token")

    if not reset_token:
        return error_response("Missing reset token", 400)

    secret = current_app.config.get("SECRET_KEY")
    reset_token_hash = hash_token(reset_token, secret)

    # Check if token exists and hasn't been used
    record = PasswordResetToken.query.filter_by(
        token_hash=reset_token_hash, used_at=None
    ).first()

    if not record:
        return error_response("Invalid or already used token", 400)

    # Check if token has expired
    if ensure_aware(record.expires_at) < utcnow():
        return error_response("Token has expired", 400)

    # Check if user exists
    if not record.user_id:
        return error_response("Invalid token", 400)

    user = User.query.get(record.user_id)
    if not user:
        return error_response("User not found", 404)

    # Token is valid
    return jsonify(
        {
            "message": "Token is valid",
            "email": user.email,
            "username": user.username,
            "token_expiry_minutes": current_app.config["RESET_TOKEN_EXPIRES_MINUTES"],
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        }
    )


@auth_bp.route("/password/reset", methods=["POST"])
@_rate_limit("5 per minute")
def reset_password():
    payload = get_request_data()
    reset_token = payload.get("reset_token")
    new_password = payload.get("new_password")

    if not all([reset_token, new_password]):
        return error_response("Missing required fields")
    if not validate_password_strength(new_password):
        return error_response("Weak password")

    secret = current_app.config.get("SECRET_KEY")
    reset_token_hash = hash_token(reset_token, secret)

    record = PasswordResetToken.query.filter_by(
        token_hash=reset_token_hash, used_at=None
    ).first()
    if not record or ensure_aware(record.expires_at) < utcnow():
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
