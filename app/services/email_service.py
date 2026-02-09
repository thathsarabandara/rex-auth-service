import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app, render_template_string
from pathlib import Path

logger = logging.getLogger(__name__)


def _load_template(template_name: str) -> tuple:
    """Load HTML and text templates for an email."""
    template_dir = Path(__file__).parent.parent / "templates" / "emails"
    
    html_path = template_dir / f"{template_name}.html"
    txt_path = template_dir / f"{template_name}.txt"
    
    html_content = html_path.read_text() if html_path.exists() else None
    txt_content = txt_path.read_text() if txt_path.exists() else None
    
    current_app.logger.debug(f"[EMAIL] Template loaded: {template_name} (html={html_path.exists()}, txt={txt_path.exists()})")
    
    return html_content, txt_content


def render_email_template(template_name: str, context: dict) -> tuple:
    """Render email templates with context variables."""
    try:
        current_app.logger.debug(f"[EMAIL] Rendering template: {template_name} with context keys: {list(context.keys())}")
        html_template, txt_template = _load_template(template_name)
        
        html_body = render_template_string(html_template, **context) if html_template else None
        txt_body = render_template_string(txt_template, **context) if txt_template else None
        
        current_app.logger.debug(f"[EMAIL] Template rendered successfully (html_size={len(html_body) if html_body else 0}, txt_size={len(txt_body) if txt_body else 0})")
        
        return html_body, txt_body
    except Exception as e:
        current_app.logger.error(f"[EMAIL] Template rendering error for {template_name}: {str(e)}")
        raise


def _send_via_smtp(to_email: str, subject: str, html_body: str, txt_body: str) -> bool:
    """Send email via SMTP server."""
    try:
        current_app.logger.info(f"[EMAIL] Attempting SMTP send to: {to_email}")
        
        smtp_server = current_app.config.get("SMTP_SERVER")
        smtp_port = int(current_app.config.get("SMTP_PORT", 587))
        smtp_username = current_app.config.get("SMTP_USERNAME")
        smtp_password = current_app.config.get("SMTP_PASSWORD")
        use_tls = current_app.config.get("SMTP_USE_TLS", True)
        timeout = int(current_app.config.get("SMTP_TIMEOUT", 10))
        sender = current_app.config.get("MAIL_SENDER")
        
        current_app.logger.debug(f"[EMAIL] SMTP Config - Server: {smtp_server}:{smtp_port}, TLS: {use_tls}, Timeout: {timeout}s")
        
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = str(subject)
        msg["From"] = str(sender)
        msg["To"] = str(to_email)
        
        # Add text and HTML parts
        if txt_body:
            msg.attach(MIMEText(txt_body, "plain"))
            current_app.logger.debug(f"[EMAIL] Attached text body ({len(txt_body)} chars)")
        if html_body:
            msg.attach(MIMEText(html_body, "html"))
            current_app.logger.debug(f"[EMAIL] Attached HTML body ({len(html_body)} chars)")
        
        # Send via SMTP
        current_app.logger.debug(f"[EMAIL] Connecting to SMTP server {smtp_server}:{smtp_port}...")
        with smtplib.SMTP(smtp_server, smtp_port, timeout=timeout) as server:
            current_app.logger.debug(f"[EMAIL] Connected to SMTP server")
            if use_tls:
                server.starttls()
                current_app.logger.debug(f"[EMAIL] TLS enabled")
            server.login(smtp_username, smtp_password)
            current_app.logger.debug(f"[EMAIL] SMTP login successful")
            server.sendmail(sender, [to_email], msg.as_string())
            current_app.logger.debug(f"[EMAIL] Email data sent to server")
        
        current_app.logger.info(f"[EMAIL] ✓ Email sent successfully to {to_email} (Subject: {subject})")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        current_app.logger.error(f"[EMAIL] ✗ SMTP authentication failed: {str(e)}")
        return False
    except smtplib.SMTPException as e:
        current_app.logger.error(f"[EMAIL] ✗ SMTP error: {str(e)}")
        return False
    except Exception as e:
        current_app.logger.error(f"[EMAIL] ✗ Error sending email: {type(e).__name__}: {str(e)}")
        return False


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
    try:
        # Ensure parameters are strings
        to_email = str(to_email) if to_email else ""
        subject = str(subject) if subject else ""
        
        current_app.logger.info(f"[EMAIL] send_email() called - To: {to_email}, Subject: {subject}, Template: {template_name}")
        
        sender = current_app.config.get("MAIL_SENDER", "no-reply@example.com")
        smtp_enabled = current_app.config.get("SMTP_ENABLED", False)
        
        current_app.logger.debug(f"[EMAIL] Config - SMTP_ENABLED: {smtp_enabled}, Sender: {sender}")
        
        if template_name and context is None:
            context = {}
        
        if template_name:
            context.setdefault("support_email", current_app.config.get("MAIL_SENDER"))
            context.setdefault("support_url", f"{current_app.config.get('FRONTEND_BASE_URL')}/support")
            context.setdefault("privacy_url", f"{current_app.config.get('FRONTEND_BASE_URL')}/privacy")
            context.setdefault("terms_url", f"{current_app.config.get('FRONTEND_BASE_URL')}/terms")
            
            current_app.logger.debug(f"[EMAIL] Rendering template with context")
            html_body, txt_body = render_email_template(template_name, context)
        else:
            html_body = None
            txt_body = body
            current_app.logger.debug(f"[EMAIL] Using custom body (no template)")
        
        if smtp_enabled:
            current_app.logger.info(f"[EMAIL] SMTP_ENABLED=true, attempting to send via SMTP")
            success = _send_via_smtp(to_email, subject, html_body, txt_body)
            if not success:
                current_app.logger.warning(f"[EMAIL] Failed to send via SMTP")
        else:
            current_app.logger.info(f"[EMAIL] SMTP_ENABLED=false - Email logged to console/logs instead of sending")
            current_app.logger.info(f"[EMAIL] =========== EMAIL PREVIEW ===========")
            current_app.logger.info(f"[EMAIL] To: {to_email}")
            current_app.logger.info(f"[EMAIL] From: {sender}")
            current_app.logger.info(f"[EMAIL] Subject: {subject}")
            current_app.logger.info(f"[EMAIL] ----- TEXT BODY -----")
            if txt_body:
                current_app.logger.info(f"[EMAIL] {txt_body}")
            else:
                current_app.logger.info(f"[EMAIL] (no text body)")
            current_app.logger.info(f"[EMAIL] ----- HTML BODY -----")
            if html_body:
                current_app.logger.info(f"[EMAIL] {html_body[:500]}..." if len(html_body) > 500 else f"[EMAIL] {html_body}")
            else:
                current_app.logger.info(f"[EMAIL] (no HTML body)")
            current_app.logger.info(f"[EMAIL] =====================================")
    except Exception as e:
        current_app.logger.error(f"[EMAIL] Unexpected error in send_email: {type(e).__name__}: {str(e)}")
        current_app.logger.exception("[EMAIL] Full exception trace:")


