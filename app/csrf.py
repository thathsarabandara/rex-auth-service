import secrets

from flask import Blueprint, jsonify, make_response, current_app


csrf_blueprint = Blueprint("csrf", __name__, url_prefix="/auth")


@csrf_blueprint.route("/csrf", methods=["GET"])
def get_csrf_token():
    token = secrets.token_urlsafe(32)
    response = make_response(jsonify({"csrf_token": token}))
    response.set_cookie(
        "csrf_token",
        token,
        httponly=True,
        samesite=current_app.config.get("CSRF_COOKIE_SAMESITE", "None"),
        secure=current_app.config.get("CSRF_COOKIE_SECURE", True),
    )
    return response


def ensure_csrf(req, config):
    if not config.get("CSRF_PROTECT", True):
        return
    if req.method in {"GET", "HEAD", "OPTIONS"}:
        return
    header_token = req.headers.get("X-CSRF-Token")
    cookie_token = req.cookies.get("csrf_token")
    if not header_token or not cookie_token or header_token != cookie_token:
        return make_csrf_error()


def make_csrf_error():
    response = jsonify({"message": "CSRF token missing or invalid"})
    response.status_code = 403
    return response
