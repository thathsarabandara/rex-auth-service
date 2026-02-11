import re

from email_validator import EmailNotValidError, validate_email

PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")


def validate_password_strength(password: str) -> bool:
    return bool(PASSWORD_REGEX.match(password or ""))


def validate_email_format(email: str) -> bool:
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False
