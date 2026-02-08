# Authentication Microservice (Flask)

Tenant-aware authentication service with OTP verification, rotating refresh tokens, and strict password-reset controls.

## Features
- Multi-tenant user registration and login
- OTP verification with `temp_token`
- Rotating refresh tokens and session revocation
- Password reset flow with single-use tokens
- Argon2 password hashing
- Rate limiting and CSRF protection
- Docker + docker-compose ready

## Quick Start (Local)
1. Create a virtual environment and install deps:
   - `python -m venv myenv`
   - `source myenv/bin/activate`
   - `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and edit values.
3. Initialize DB:
   - `flask db init`
   - `flask db migrate -m "init"`
   - `flask db upgrade`
4. Create a tenant record (example):
   - Use your DB client to insert into `tenants` (e.g., `INSERT INTO tenants (name, created_at) VALUES ('default', now());`).
5. Run:
   - `flask --app manage.py run --port 8000`

## Docker
- `docker compose up --build`

## API Endpoints
- `GET /health`
- `GET /auth/csrf` (sets CSRF cookie + returns token)
- `POST /auth/register/initiate`
- `POST /auth/register/verify`
- `POST /auth/login`
- `POST /auth/token/refresh`
- `POST /auth/password/forgot`
- `POST /auth/password/reset`

## Testing
Run tests with:
```bash
make test          # Run all tests
make coverage      # Generate coverage report
```

## Linting & Formatting
```bash
make lint          # Check code style (flake8, isort, black)
make format        # Auto-format code (isort + black)
```

## Development Helpers
```bash
make install-dev   # Install dev dependencies
make clean         # Remove cache files
make run           # Start dev server
```

## CI/CD Pipeline
GitHub Actions automatically:
- Runs linting checks (isort, black, flake8)
- Executes all test suites
- Generates coverage reports
- Builds Docker image
- Runs on: `main`, `develop` branches and all PRs

See `.github/workflows/ci.yml` for details.

## Notes
- Login is blocked until `email_verified=true`.
- Tokens are hashed at rest.
- Use `tenant_id` for all auth operations.
- For CSRF-protected requests, call `/auth/csrf` and send the returned token in `X-CSRF-Token`.
- Test database uses SQLite (in-memory) for speed.
