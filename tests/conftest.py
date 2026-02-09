import os
import tempfile

import pytest

from app import create_app
from app.extensions import db
from app.models import Tenant, User, UserStatus


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp()
    app = create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["RATE_LIMIT_ENABLED"] = False

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


@pytest.fixture
def default_tenant(app):
    with app.app_context():
        tenant = Tenant(name="default")
        db.session.add(tenant)
        db.session.commit()
        return tenant


@pytest.fixture
def default_user(app, default_tenant):
    with app.app_context():
        from app.security import hash_password

        user = User(
            tenant_id=default_tenant.id,
            username="testuser",
            email="test@example.com",
            password_hash=hash_password("StrongPass1"),
            email_verified=True,
            status=UserStatus.ACTIVE,
        )
        db.session.add(user)
        db.session.commit()
        return user
