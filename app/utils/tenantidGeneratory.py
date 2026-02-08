
from datetime import datetime
from datetime import datetime, timezone


def generate_tenant_id(email: str, username: str) -> str:
    email_prefix = email.split("@")[0]
    timestamp = datetime.now(timezone.utc).isoformat()
    tenant_id = f"{email_prefix}:{username}:{timestamp}"
    return tenant_id