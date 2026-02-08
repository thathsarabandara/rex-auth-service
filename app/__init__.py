from flask import Flask, request, jsonify
from pathlib import Path

from app.config import Config
from app.extensions import db, migrate, jwt, limiter
from app.routes.auth import auth_bp
from app.routes.health import health_bp
from app.csrf import ensure_csrf, csrf_blueprint


def create_app() -> Flask:
    template_dir = Path(__file__).parent / "templates"
    app = Flask(__name__, template_folder=str(template_dir))
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(csrf_blueprint)

    @app.before_request
    def _csrf_protect():
        response = ensure_csrf(request, app.config)
        if response:
            return response

    @app.errorhandler(404)
    def _not_found(_error):
        return jsonify({"message": "Not found"}), 404

    @app.errorhandler(429)
    def _rate_limited(_error):
        return jsonify({"message": "Too many requests"}), 429

    return app
