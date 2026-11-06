import hashlib
import os
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from pwdlib import PasswordHash

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

password_hasher = PasswordHash.recommended()


def utc_now():
    return datetime.now(timezone.utc)


def timestamp_after(minutes):
    return (utc_now() + timedelta(minutes=minutes)).isoformat()


def new_token():
    return secrets.token_urlsafe(32)


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password):
    return password_hasher.hash(password)


def verify_password(password, password_hash):
    return password_hasher.verify(password, password_hash)


def encrypt_github_token(access_token):
    key = os.getenv("FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY is not configured")
    return Fernet(key.encode("utf-8")).encrypt(
        access_token.encode("utf-8")
    ).decode("utf-8")


def decrypt_github_token(encrypted_token):
    key = os.getenv("FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY is not configured")
    return Fernet(key.encode("utf-8")).decrypt(
        encrypted_token.encode("utf-8")
    ).decode("utf-8")


def send_email(recipient, subject, body):
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME", "")
    app_password = os.getenv("SMTP_APP_PASSWORD", "")
    sender = os.getenv("MAIL_FROM") or username

    if not username or not app_password or not sender:
        raise RuntimeError(
            "Gmail SMTP is not configured. Set SMTP_USERNAME, "
            "SMTP_APP_PASSWORD, and MAIL_FROM in .env."
        )

    recipient = recipient.strip().lower()
    if not recipient or "@" not in recipient:
        raise ValueError("A valid recipient email is required")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(host, port, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(username, app_password)
        server.send_message(message)


def send_verification_email(recipient, token):
    base_url = os.getenv("APP_BASE_URL", "").rstrip("/")
    if not base_url or "YOUR_DOMAIN" in base_url:
        raise RuntimeError("APP_BASE_URL must be configured before sending email")

    link = f"{base_url}/verify-email?token={token}"
    body = (
        "Welcome to CloudSentinel.\n\n"
        "Verify your email address using this link:\n"
        f"{link}\n\n"
        "This link expires in 30 minutes. If you did not create "
        "this account, you can ignore this email."
    )
    send_email(recipient, "Verify your CloudSentinel account", body)


def send_password_reset_email(recipient, token):
    base_url = os.getenv("APP_BASE_URL", "").rstrip("/")
    if not base_url or "YOUR_DOMAIN" in base_url:
        raise RuntimeError("APP_BASE_URL must be configured before sending email")

    link = f"{base_url}/reset-password?token={token}"
    body = (
        "A password reset was requested for your CloudSentinel account.\n\n"
        "Reset your password using this link:\n"
        f"{link}\n\n"
        "This link expires in 30 minutes. If you did not request this, "
        "you can ignore this email."
    )
    send_email(recipient, "Reset your CloudSentinel password", body)
