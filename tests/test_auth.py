from datetime import timedelta

from app.extensions import db
from app.models import OtpPurpose, OtpSession, User, UserStatus, utcnow
from app.security import generate_token, hash_token


class TestRegisterInitiate:
    def test_register_initiate_success(self, client, default_tenant, app):
        with app.app_context():
            response = client.post(
                "/auth/register/initiate",
                json={
                    "username": "newuser",
                    "email": "new@example.com",
                    "password": "StrongPass1",
                },
            )
            assert response.status_code == 200
            data = response.get_json()
            assert "temp_token" in data
            assert data["message"] == "OTP sent"

    def test_register_initiate_missing_fields(self, client, default_tenant):
        response = client.post(
            "/auth/register/initiate",
            json={"email": "new@example.com", "password": "StrongPass1"},
        )
        assert response.status_code == 400
        assert "Missing required fields" in response.get_json()["message"]

    def test_register_initiate_weak_password(self, client, default_tenant):
        response = client.post(
            "/auth/register/initiate",
            json={
                "username": "newuser",
                "email": "new@example.com",
                "password": "weak",
            },
        )
        assert response.status_code == 400
        assert "Weak password" in response.get_json()["message"]

    def test_register_initiate_invalid_email(self, client, default_tenant):
        response = client.post(
            "/auth/register/initiate",
            json={
                "username": "newuser",
                "email": "invalid-email",
                "password": "StrongPass1",
            },
        )
        assert response.status_code == 400
        assert "Invalid email" in response.get_json()["message"]

    def test_register_initiate_duplicate_email(
        self, client, default_tenant, default_user
    ):
        response = client.post(
            "/auth/register/initiate",
            json={
                "username": "newuser",
                "email": default_user.email,
                "password": "StrongPass1",
            },
        )
        assert response.status_code == 409
        assert "already registered" in response.get_json()["message"]


class TestRegisterVerify:
    def test_register_verify_success(self, client, default_tenant, app):
        with app.app_context():
            secret = app.config.get("SECRET_KEY")

            user = User(
                tenant_id=default_tenant.id,
                username="newuser",
                email="new@example.com",
                password_hash="hashed",
                email_verified=False,
                status=UserStatus.ACTIVE,
            )
            db.session.add(user)
            db.session.commit()

            otp = "123456"
            temp_token = generate_token()
            otp_hash = hash_token(otp, secret)
            temp_token_hash = hash_token(temp_token, secret)

            otp_session = OtpSession(
                email="new@example.com",
                otp_hash=otp_hash,
                temp_token=temp_token_hash,
                expires_at=utcnow() + timedelta(minutes=5),
                attempts=0,
                purpose=OtpPurpose.REGISTER,
            )
            db.session.add(otp_session)
            db.session.commit()

        response = client.post(
            "/auth/register/verify",
            json={"email": "new@example.com", "otp": otp, "temp_token": temp_token},
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["tenant_id"] == default_tenant.id

    def test_register_verify_invalid_otp(self, client, default_tenant, app):
        with app.app_context():
            secret = app.config.get("SECRET_KEY")

            user = User(
                tenant_id=default_tenant.id,
                username="newuser",
                email="new@example.com",
                password_hash="hashed",
                email_verified=False,
                status=UserStatus.ACTIVE,
            )
            db.session.add(user)
            db.session.commit()

            otp = "123456"
            temp_token = generate_token()
            otp_hash = hash_token(otp, secret)
            temp_token_hash = hash_token(temp_token, secret)

            otp_session = OtpSession(
                email="new@example.com",
                otp_hash=otp_hash,
                temp_token=temp_token_hash,
                expires_at=utcnow() + timedelta(minutes=5),
                attempts=0,
                purpose=OtpPurpose.REGISTER,
            )
            db.session.add(otp_session)
            db.session.commit()

        response = client.post(
            "/auth/register/verify",
            json={
                "email": "new@example.com",
                "otp": "000000",
                "temp_token": temp_token,
            },
        )
        assert response.status_code == 400
        assert "Invalid OTP" in response.get_json()["message"]

    def test_register_verify_otp_attempts_exceeded(self, client, default_tenant, app):
        with app.app_context():
            secret = app.config.get("SECRET_KEY")

            user = User(
                tenant_id=default_tenant.id,
                username="newuser",
                email="new@example.com",
                password_hash="hashed",
                email_verified=False,
                status=UserStatus.ACTIVE,
            )
            db.session.add(user)
            db.session.commit()

            otp = "123456"
            temp_token = generate_token()
            otp_hash = hash_token(otp, secret)
            temp_token_hash = hash_token(temp_token, secret)

            otp_session = OtpSession(
                email="new@example.com",
                otp_hash=otp_hash,
                temp_token=temp_token_hash,
                expires_at=utcnow() + timedelta(minutes=5),
                attempts=3,
                purpose=OtpPurpose.REGISTER,
            )
            db.session.add(otp_session)
            db.session.commit()

        response = client.post(
            "/auth/register/verify",
            json={
                "email": "new@example.com",
                "otp": "000000",
                "temp_token": temp_token,
            },
        )
        assert response.status_code == 429
        assert "OTP attempts exceeded" in response.get_json()["message"]


class TestLogin:
    def test_login_success(self, client, default_tenant, default_user):
        response = client.post(
            "/auth/login",
            json={
                "email": default_user.email,
                "password": "StrongPass1",
            },
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["tenant_id"] == default_tenant.id

    def test_login_invalid_credentials(self, client, default_tenant, default_user):
        response = client.post(
            "/auth/login",
            json={
                "email": default_user.email,
                "password": "WrongPass",
            },
        )
        assert response.status_code == 401
        assert "Invalid credentials" in response.get_json()["message"]

    def test_login_missing_fields(self, client):
        response = client.post("/auth/login", json={"email": "test@example.com"})
        assert response.status_code == 400
        assert "Missing required fields" in response.get_json()["message"]

    def test_login_email_not_verified(self, client, default_tenant, app):
        with app.app_context():
            from app.security import hash_password

            user = User(
                tenant_id=default_tenant.id,
                username="unverified",
                email="unverified@example.com",
                password_hash=hash_password("StrongPass1"),
                email_verified=False,
                status=UserStatus.ACTIVE,
            )
            db.session.add(user)
            db.session.commit()

        response = client.post(
            "/auth/login",
            json={
                "email": "unverified@example.com",
                "password": "StrongPass1",
            },
        )
        assert response.status_code == 403
        assert "Email not verified" in response.get_json()["message"]


class TestHealth:
    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"


class TestCSRF:
    def test_csrf_token_generation(self, client):
        response = client.get("/auth/csrf")
        assert response.status_code == 200
        data = response.get_json()
        assert "csrf_token" in data
        assert (
            "csrf_token" in response.headers.getlist("Set-Cookie")[0]
            if response.headers.getlist("Set-Cookie")
            else None
        )
