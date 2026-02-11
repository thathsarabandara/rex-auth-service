import os
import tempfile
from collections import namedtuple

import pytest

from app import create_app
from app.extensions import db
from app.models import Tenant, User, UserStatus

# Simple named tuples to hold data without being tied to SQLAlchemy session
UserData = namedtuple("UserData", ["id", "email", "username"])
TenantData = namedtuple("TenantData", ["id", "name"])


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp()

    # Create app with test configuration
    app = create_app(
        config_overrides={
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
            "RATE_LIMIT_ENABLED": False,
            "CSRF_PROTECT": False,
            "SECRET_KEY": "4d666089fc013268197ab370ad619b96",
            "JWT_SECRET_KEY": "FvweS0L9ZVafXVuuKz6kK8ZRv1WuyaxV5BMVHamQg58H03NsmS90KuEvhMxQUvnXAUbrHTrHtIuYgeeu8D46sF",
        }
    )

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
        tenant_id = tenant.id
        tenant_name = tenant.name

    # Return a simple data structure that doesn't require an active session
    return TenantData(id=tenant_id, name=tenant_name)


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
        user_id = user.id
        user_email = user.email
        user_username = user.username

    # Return a simple data structure that doesn't require an active session
    return UserData(id=user_id, email=user_email, username=user_username)
