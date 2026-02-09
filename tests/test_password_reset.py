from datetime import timedelta

from app.extensions import db
from app.models import PasswordResetToken, utcnow
from app.security import generate_token, hash_token


class TestForgotPassword:
    def test_forgot_password_success(self, client, default_tenant, default_user, app):
        with app.app_context():
            response = client.post(
                "/auth/password/forgot",
                json={"email": default_user.email, "tenant_id": default_tenant.id},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data["message"] == "Password reset email sent"

    def test_forgot_password_invalid_email(self, client, default_tenant):
        response = client.post(
            "/auth/password/forgot",
            json={"email": "invalid-email", "tenant_id": default_tenant.id},
        )
        assert response.status_code == 400
        assert "Invalid email" in response.get_json()["message"]

    def test_forgot_password_missing_fields(self, client):
        response = client.post(
            "/auth/password/forgot", json={"email": "test@example.com"}
        )
        assert response.status_code == 400
        assert "Missing required fields" in response.get_json()["message"]


class TestResetPassword:
    def test_reset_password_success(self, client, default_tenant, default_user, app):
        with app.app_context():
            secret = app.config.get("SECRET_KEY")
            reset_token = generate_token()
            reset_token_hash = hash_token(reset_token, secret)

            record = PasswordResetToken(
                email=default_user.email,
                tenant_id=default_tenant.id,
                user_id=default_user.id,
                token_hash=reset_token_hash,
                expires_at=utcnow() + timedelta(minutes=20),
            )
            db.session.add(record)
            db.session.commit()

        response = client.post(
            "/auth/password/reset",
            json={"reset_token": reset_token, "new_password": "NewStrongPass2"},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["message"] == "Password updated"

    def test_reset_password_weak_password(
        self, client, default_tenant, default_user, app
    ):
        with app.app_context():
            secret = app.config.get("SECRET_KEY")
            reset_token = generate_token()
            reset_token_hash = hash_token(reset_token, secret)

            record = PasswordResetToken(
                email=default_user.email,
                tenant_id=default_tenant.id,
                user_id=default_user.id,
                token_hash=reset_token_hash,
                expires_at=utcnow() + timedelta(minutes=20),
            )
            db.session.add(record)
            db.session.commit()

        response = client.post(
            "/auth/password/reset",
            json={"reset_token": reset_token, "new_password": "weak"},
        )
        assert response.status_code == 400
        assert "Weak password" in response.get_json()["message"]

    def test_reset_password_expired_token(
        self, client, default_tenant, default_user, app
    ):
        with app.app_context():
            secret = app.config.get("SECRET_KEY")
            reset_token = generate_token()
            reset_token_hash = hash_token(reset_token, secret)

            record = PasswordResetToken(
                email=default_user.email,
                tenant_id=default_tenant.id,
                user_id=default_user.id,
                token_hash=reset_token_hash,
                expires_at=utcnow() - timedelta(minutes=1),
            )
            db.session.add(record)
            db.session.commit()

        response = client.post(
            "/auth/password/reset",
            json={"reset_token": reset_token, "new_password": "NewStrongPass2"},
        )
        assert response.status_code == 400
        assert "expired" in response.get_json()["message"]

    def test_reset_password_invalid_token(self, client):
        response = client.post(
            "/auth/password/reset",
            json={"reset_token": "invalid_token_xyz", "new_password": "NewStrongPass2"},
        )
        assert response.status_code == 400
