"""
Utility functions for handling multiple request content types securely.
Supports both application/json and application/x-www-form-urlencoded.
"""

from flask import current_app, request

from app.utils.responses import error_response


def get_request_data():
    """
    Get request data from either JSON or URL-encoded form data.

    Returns:
        dict: Parsed request data
    """
    content_type = request.content_type or ""
    data = {}

    try:
        if "application/json" in content_type:
            # JSON request
            json_data = request.get_json(force=False, silent=True)
            data = json_data if json_data else {}
            current_app.logger.debug(f"Parsed JSON data: {data}")

        elif "application/x-www-form-urlencoded" in content_type:
            # URL-encoded form data
            form_data = request.form.to_dict()
            data = form_data if form_data else {}
            current_app.logger.debug(f"Parsed form data: {data}")

        else:
            # Try both - JSON first, then form data
            json_data = request.get_json(force=False, silent=True)
            if json_data:
                data = json_data
                current_app.logger.debug(f"Parsed JSON data (auto): {data}")
            else:
                form_data = request.form.to_dict()
                data = form_data if form_data else {}
                current_app.logger.debug(f"Parsed form data (auto): {data}")

    except Exception as e:
        current_app.logger.error(f"Error parsing request data: {str(e)}")
        data = {}

    return data


def validate_content_type():
    """
    Validate that the request has a supported content type.

    Returns:
        None if valid, error response if invalid
    """
    content_type = request.content_type or ""

    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return None

    if not content_type:
        # Allow empty content type - will try to parse automatically
        return None

    # Allowed content types
    if any(
        ct in content_type
        for ct in [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ]
    ):
        return None

    return error_response(
        f"Unsupported content type: {content_type}. "
        f"Use application/json or application/x-www-form-urlencoded",
        415,
    )
