# REX-47 Authentication Microservice

A secure, production-ready authentication microservice for the **REX-47 Smart Home Assistant Robot**. Built with Flask and designed to handle multi-tenant user registration, login, OTP verification, and password management with enterprise-grade security.

> Part of the REX-47 ecosystem providing secure identity and access management for the home automation system.

## 🌟 Features

### Core Authentication
- **Multi-Tenant Support**: Isolate users and data per tenant
- **OTP Verification**: 6-digit OTP via email with 2-minute resend cooldown
- **Secure Login**: Argon2 password hashing with progressive login penalties
- **Session Management**: Rotating refresh tokens with automatic revocation
- **Token Validation**: Real-time token status checking with automatic refresh capability

### Security
- **HttpOnly Cookies**: Tokens stored securely in httpOnly, Secure, SameSite cookies
- **CSRF Protection**: Built-in CSRF token validation for all state-changing operations
- **Rate Limiting**: Per-endpoint rate limits to prevent brute-force attacks
- **Account Lockout**: Automatic temporary and permanent account banning after failed attempts
- **Password Requirements**: Enforced password strength validation (minimum 8 chars, mixed case, numbers, symbols)

### Advanced Features
- **Email Notifications**: OTP, password reset, and welcome emails via SMTP
- **Password Reset**: Single-use tokens with expiration
- **Device Tracking**: Store device info and IP addresses for security audits
- **Activity Logging**: Comprehensive logging of all auth events
- **Database Migrations**: Alembic-based version control for schema changes

## 📋 System Requirements

- Python 3.11+
- MySQL 8.0+ / MariaDB 10.5+
- Redis (optional, for production rate limiting)
- Docker & Docker Compose (recommended)

## 🚀 Quick Start

### Using Docker (Recommended)

```bash
cd rex-auth-server
docker-compose up --build
```

API available at `http://localhost:8000`

### Local Development

```bash
python -m venv myenv
source myenv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
# Edit .env with your credentials
flask db upgrade
python -m flask --app manage.py run --port 8000
```

## 🔧 Configuration

See `.env.example` for all configuration options. Key settings:

```env
SMTP_ENABLED=true
SMTP_SERVER=smtp.gmail.com
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

## 📡 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register/initiate` | Start registration |
| POST | `/auth/register/verify` | Verify OTP |
| POST | `/auth/register/resend-otp` | Resend OTP |
| POST | `/auth/login` | User login |
| GET | `/auth/token/validate` | Check & auto-refresh token |
| POST | `/auth/token/refresh` | Refresh token |

### Password Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/password/forgot` | Request reset |
| GET | `/auth/password/reset/validate` | Validate token |
| POST | `/auth/password/reset` | Reset password |

## 🔒 Security

- **Account Lockout**: 4 failures = 1h ban, 5 = 6h ban, 6+ = permanent
- **OTP**: 3 attempts max, 5 min validity, 2 min resend cooldown
- **Tokens**: 10-min access + 7-day refresh in httpOnly cookies
- **Password**: 8+ chars, uppercase, lowercase, numbers, symbols

## 🧪 Testing

```bash
make test           # Run tests
make coverage       # Coverage report
make lint          # Lint check
make format        # Auto-format
```

Use `app/routes/auth.http` with VS Code REST Client for manual testing.

## 📊 Database

Key tables:
- `tenants`: Multi-tenant isolation
- `users`: User accounts
- `otp_sessions`: OTP requests
- `auth_sessions`: Login sessions
- `password_reset_tokens`: Reset links
- `login_attempts`: Security tracking

## 🐛 Troubleshooting

**Database not connecting:**
```bash
docker-compose ps
docker-compose logs db
docker-compose down -v && docker-compose up --build
```

**Email not sending:**
- Check `SMTP_ENABLED=true`
- Verify credentials
- Check logs: `docker logs rex-auth-server_api_1 | grep EMAIL`

**Token errors:**
- Verify `JWT_SECRET_KEY` is set
- Check expiration times
- Ensure cookies are allowed

## 📄 License

MIT License - see [LICENSE](LICENSE) file

## 🔗 Related Projects

- **REX-47**: Smart Home Assistant Robot
- **REX Frontend**: Web dashboard
- **REX Gateway**: API gateway

---

**Made with ❤️ for REX-47 Smart Home Assistant Robot**
