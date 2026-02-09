import pytest

from app.security import (generate_numeric_otp, generate_token, hash_password,
                          hash_token, verify_password)
from app.utils.validators import (validate_email_format,
                                  validate_password_strength)


class TestValidators:
    def test_validate_password_strength_valid(self):
        assert validate_password_strength("StrongPass1") is True

    def test_validate_password_strength_no_uppercase(self):
        assert validate_password_strength("weakpass1") is False

    def test_validate_password_strength_no_lowercase(self):
        assert validate_password_strength("WEAKPASS1") is False

    def test_validate_password_strength_no_digit(self):
        assert validate_password_strength("WeakPassX") is False

    def test_validate_password_strength_too_short(self):
        assert validate_password_strength("Pass1") is False

    def test_validate_email_format_valid(self):
        assert validate_email_format("test@example.com") is True

    def test_validate_email_format_invalid(self):
        assert validate_email_format("invalid-email") is False

    def test_validate_email_format_missing_domain(self):
        assert validate_email_format("test@") is False


class TestSecurity:
    def test_hash_password_creates_different_hashes(self):
        password = "StrongPass1"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2

    def test_verify_password_correct(self):
        password = "StrongPass1"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        password = "StrongPass1"
        hashed = hash_password(password)
        assert verify_password("WrongPass", hashed) is False

    def test_generate_numeric_otp_length(self):
        otp = generate_numeric_otp(6)
        assert len(otp) == 6
        assert otp.isdigit()

    def test_generate_numeric_otp_custom_length(self):
        otp = generate_numeric_otp(8)
        assert len(otp) == 8
        assert otp.isdigit()

    def test_generate_token_uniqueness(self):
        token1 = generate_token()
        token2 = generate_token()
        assert token1 != token2

    def test_hash_token(self):
        value = "test_token"
        secret = "secret_key"
        hash1 = hash_token(value, secret)
        hash2 = hash_token(value, secret)
        assert hash1 == hash2
        assert len(hash1) == 64
