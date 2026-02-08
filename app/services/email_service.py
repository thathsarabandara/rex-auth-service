from flask import current_app, render_template_string
from pathlib import Path


def _load_template(template_name: str) -> tuple:
    """Load HTML and text templates for an email."""
    template_dir = Path(__file__).parent.parent / "templates" / "emails"
    
    html_path = template_dir / f"{template_name}.html"
    txt_path = template_dir / f"{template_name}.txt"
    
    html_content = html_path.read_text() if html_path.exists() else None
    txt_content = txt_path.read_text() if txt_path.exists() else None
    
    return html_content, txt_content


def render_email_template(template_name: str, context: dict) -> tuple:
    """Render email templates with context variables."""
    html_template, txt_template = _load_template(template_name)
    
    html_body = render_template_string(html_template, **context) if html_template else None
    txt_body = render_template_string(txt_template, **context) if txt_template else None
    
    return html_body, txt_body


def send_email(
    to_email: str,
    subject: str,
    template_name: str = None,
    body: str = None,
    context: dict = None,
) -> None:
    """
    Send email with template rendering support.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        template_name: Name of template (without extension)
        body: Plain text body (fallback if template_name not provided)
        context: Dictionary of variables for template rendering
    """
    sender = current_app.config.get("MAIL_SENDER", "no-reply@example.com")
    
    if template_name and context is None:
        context = {}
    
    if template_name:
        context.setdefault("support_email", current_app.config.get("MAIL_SENDER"))
        context.setdefault("support_url", f"{current_app.config.get('FRONTEND_BASE_URL')}/support")
        context.setdefault("privacy_url", f"{current_app.config.get('FRONTEND_BASE_URL')}/privacy")
        context.setdefault("terms_url", f"{current_app.config.get('FRONTEND_BASE_URL')}/terms")
        
        html_body, txt_body = render_email_template(template_name, context)
    else:
        html_body = body
        txt_body = body
    
    current_app.logger.info(
        "Sending email from %s to %s (template=%s): %s",
        sender,
        to_email,
        template_name or "custom",
        subject,
    )
    current_app.logger.debug("Email HTML: %s", html_body[:200] if html_body else "N/A")
    current_app.logger.debug("Email TXT: %s", txt_body[:200] if txt_body else "N/A")
