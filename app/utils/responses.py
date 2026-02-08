from flask import jsonify


def error_response(message: str, status: int = 400):
    return jsonify({"message": message}), status
