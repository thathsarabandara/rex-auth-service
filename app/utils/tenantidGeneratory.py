def get_or_create_tenant(email: str, username: str) -> int:
    """
    Get or create a tenant for a user and return its integer ID.
    Tenant is identified by email prefix as a unique tenant name.
    """
    from app.extensions import db
    from app.models import Tenant

    # Create a unique tenant name from email prefix
    email_prefix = email.split("@")[0]
    tenant_name = f"{email_prefix}:{username}"

    # Try to find existing tenant
    tenant = Tenant.query.filter_by(name=tenant_name).first()

    if not tenant:
        # Create new tenant
        tenant = Tenant(name=tenant_name)
        db.session.add(tenant)
        db.session.flush()  # Get the ID without committing

    return tenant.id
