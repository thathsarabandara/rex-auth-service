from datetime import timedelta

import pytest

from app.extensions import db
from app.models import LoginAttempt, User, UserStatus, utcnow
from app.security import hash_password


class TestLoginAttempts:
    def test_login_attempt_tracking(self, client, default_tenant, default_user):
        for i in range(3):
            response = client.post(
                "/auth/login",
                json={
                    "email": default_user.email,
                    "password": "WrongPass",
                    "tenant_id": default_tenant.id,
                },
            )
            assert response.status_code == 401

        with client.application.app_context():
            attempt = LoginAttempt.query.filter_by(
                email=default_user.email, tenant_id=default_tenant.id
            ).first()
            assert attempt.attempt_count == 3

    def test_login_attempt_fourth_triggers_temp_ban(
        self, client, default_tenant, default_user
    ):
        for i in range(4):
            client.post(
                "/auth/login",
                json={
                    "email": default_user.email,
                    "password": "WrongPass",
                    "tenant_id": default_tenant.id,
                },
            )

        response = client.post(
            "/auth/login",
            json={
                "email": default_user.email,
                "password": "WrongPass",
                "tenant_id": default_tenant.id,
            },
        )
        assert response.status_code == 403
        assert "temporarily banned" in response.get_json()["message"]

    def test_login_after_successful_resets_attempts(
        self, client, default_tenant, default_user, app
    ):
        for i in range(2):
            client.post(
                "/auth/login",
                json={
                    "email": default_user.email,
                    "password": "WrongPass",
                    "tenant_id": default_tenant.id,
                },
            )

        response = client.post(
            "/auth/login",
            json={
                "email": default_user.email,
                "password": "StrongPass1",
                "tenant_id": default_tenant.id,
            },
        )
        assert response.status_code == 200

        with app.app_context():
            attempt = LoginAttempt.query.filter_by(
                email=default_user.email, tenant_id=default_tenant.id
            ).first()
            assert attempt.attempt_count == 0


class TestUserBanning:
    def test_hard_ban_after_six_attempts(self, client, default_tenant, default_user):
        for i in range(6):
            client.post(
                "/auth/login",
                json={
                    "email": default_user.email,
                    "password": "WrongPass",
                    "tenant_id": default_tenant.id,
                },
            )

        with client.application.app_context():
            user = User.query.get(default_user.id)
            assert user.status == UserStatus.HARD_BANNED

    def test_hard_banned_user_cannot_login(self, client, default_tenant, app):
        with app.app_context():
            user = User(
                tenant_id=default_tenant.id,
                username="banneduser",
                email="banned@example.com",
                password_hash=hash_password("StrongPass1"),
                email_verified=True,
                status=UserStatus.HARD_BANNED,
            )
            db.session.add(user)
            db.session.commit()

        response = client.post(
            "/auth/login",
            json={
                "email": "banned@example.com",
                "password": "StrongPass1",
                "tenant_id": default_tenant.id,
            },
        )
        assert response.status_code == 403
        assert "permanently banned" in response.get_json()["message"]
