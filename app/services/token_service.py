from flask import current_app
from flask_jwt_extended import create_access_token, create_refresh_token

from app.models import AuthSession, utcnow
from app.extensions import db
from app.security import hash_token


def issue_tokens(user, tenant_id: int, scopes=None, roles=None, device_info=None, ip_address=None):
    scopes = scopes or ["robot:read", "robot:write"]
    roles = roles or ["user"]

    additional_claims = {"tenant_id": tenant_id, "roles": roles, "scopes": scopes}
    access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=user.id, additional_claims=additional_claims)

    secret = current_app.config.get("JWT_SECRET_KEY", "dev-jwt-secret")
    access_token_hash = hash_token(access_token, secret)
    refresh_token_hash = hash_token(refresh_token, secret)

    expires_at = utcnow() + current_app.config["JWT_REFRESH_TOKEN_EXPIRES"]
    session = AuthSession(
        user_id=user.id,
        tenant_id=tenant_id,
        access_token=access_token_hash,
        refresh_token=refresh_token_hash,
        refresh_token_jti=_get_jti(refresh_token),
        expires_at=expires_at,
        revoked=False,
        device_info=device_info,
        ip_address=ip_address,
    )
    db.session.add(session)
    db.session.commit()

    return access_token, refresh_token


def revoke_session(session: AuthSession):
    session.revoked = True
    db.session.commit()


def revoke_all_sessions(user_id: int):
    AuthSession.query.filter_by(user_id=user_id, revoked=False).update({"revoked": True})
    db.session.commit()


def _get_jti(token: str) -> str:
    from flask_jwt_extended.utils import decode_token

    decoded = decode_token(token)
    return decoded.get("jti")
