import os
import logging
import re
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.auth_db import get_connection
from app.auth_security import (
    decrypt_github_token,
    encrypt_github_token,
    hash_password,
    hash_token,
    new_token,
    send_password_reset_email,
    send_verification_email,
    timestamp_after,
    verify_password,
)

router = APIRouter()
oauth = OAuth()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "")

if GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET:
    oauth.register(
        name="github",
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        authorize_url="https://github.com/login/oauth/authorize",
        access_token_url="https://github.com/login/oauth/access_token",
        api_base_url="https://api.github.com/",
        client_kwargs={
            "scope": "read:user user:email repo",
            "token_endpoint_auth_method": "client_secret_post",
        },
    )


class RegisterRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class ResendVerificationRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)


class TokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    new_password: str = Field(min_length=12, max_length=128)


def current_time():
    return datetime.now(timezone.utc).isoformat()


def validate_email(email):
    email = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Enter a valid email address")
    return email


def get_current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(401, "Please sign in")

    with get_connection() as connection:
        user = connection.execute(
            "SELECT id, email, is_verified FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if not user or not user["is_verified"]:
        request.session.clear()
        raise HTTPException(401, "Please verify your email and sign in")

    return dict(user)


def create_email_token(user_id, purpose):
    token = new_token()
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO email_tokens
                (user_id, token_hash, purpose, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                hash_token(token),
                purpose,
                timestamp_after(30),
                current_time(),
            ),
        )
    return token


def consume_email_token(token, purpose):
    token_digest = hash_token(token)
    now = current_time()

    with get_connection() as connection:
        record = connection.execute(
            """
            SELECT id, user_id, expires_at
            FROM email_tokens
            WHERE token_hash = ? AND purpose = ? AND used_at IS NULL
            """,
            (token_digest, purpose),
        ).fetchone()

        if not record or record["expires_at"] <= now:
            return None

        connection.execute(
            "UPDATE email_tokens SET used_at = ? WHERE id = ?",
            (now, record["id"]),
        )
        return record["user_id"]


@router.post("/api/auth/register")
def register(body: RegisterRequest):
    email = validate_email(body.email)

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id, is_verified FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if existing:
            if existing["is_verified"]:
                raise HTTPException(409, "An account already exists for this email")
            raise HTTPException(
                409,
                "An unverified account already exists. Use resend verification.",
            )

        connection.execute(
            """
            INSERT INTO users (email, password_hash, is_verified, created_at)
            VALUES (?, ?, 1, ?)
            """,
            (email, hash_password(body.password), current_time()),
        )

    return {"message": "Account created successfully. You can now sign in."}


@router.post("/api/auth/login")
def login(body: LoginRequest, request: Request):
    email = validate_email(body.email)

    with get_connection() as connection:
        user = connection.execute(
            "SELECT id, email, password_hash, is_verified FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password")

    request.session.clear()
    request.session["user_id"] = user["id"]
    return {"message": "Signed in successfully", "email": user["email"]}


@router.post("/api/auth/logout")
def logout(request: Request):
    request.session.clear()
    return {"message": "Signed out successfully"}


@router.get("/api/auth/me")
def me(user=Depends(get_current_user)):
    return {"id": user["id"], "email": user["email"], "verified": True}


@router.post("/api/auth/forgot-password")
def forgot_password(body: ForgotPasswordRequest):
    # This endpoint is intentionally generic to avoid revealing registered emails.
    email = validate_email(body.email)

    with get_connection() as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE email = ? AND is_verified = 1",
            (email,),
        ).fetchone()

    if user:
        token = create_email_token(user["id"], "reset_password")
        try:
            send_password_reset_email(email, token)
        except Exception:
            # Do not reveal account existence or email-delivery details.
            pass

    return {"message": "If an account exists, password reset instructions will be sent."}


@router.post("/api/auth/reset-password")
def reset_password(body: ResetPasswordRequest):
    user_id = consume_email_token(body.token, "reset_password")
    if not user_id:
        raise HTTPException(400, "Password reset link is invalid or expired")

    with get_connection() as connection:
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(body.new_password), user_id),
        )
        # Invalidate all outstanding reset and verification links for this user.
        connection.execute(
            "UPDATE email_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
            (current_time(), user_id),
        )

    return {"message": "Password updated. Please sign in again."}


@router.get("/auth/github/login")
async def github_login(request: Request, user=Depends(get_current_user)):
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET or not GITHUB_REDIRECT_URI:
        raise HTTPException(503, "GitHub OAuth is not configured yet")

    request.session["github_connect_user_id"] = user["id"]
    return await oauth.github.authorize_redirect(
        request, GITHUB_REDIRECT_URI
    )


@router.get("/auth/github/callback")
async def github_callback(request: Request):
    user_id = request.session.get("github_connect_user_id")
    if not user_id:
        raise HTTPException(400, "GitHub connection session expired")

    try:
        token = await oauth.github.authorize_access_token(request)
        response = await oauth.github.get("user", token=token)
        response.raise_for_status()
        github_user = response.json()
        access_token = token.get("access_token")

        if not access_token or not github_user.get("id") or not github_user.get("login"):
            raise ValueError("GitHub did not return the required account details")

        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO github_connections
                    (user_id, github_user_id, github_login,
                     encrypted_access_token, connected_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    github_user_id = excluded.github_user_id,
                    github_login = excluded.github_login,
                    encrypted_access_token = excluded.encrypted_access_token,
                    connected_at = excluded.connected_at
                """,
                (
                    user_id,
                    int(github_user["id"]),
                    github_user["login"],
                    encrypt_github_token(access_token),
                    current_time(),
                ),
            )

        request.session.pop("github_connect_user_id", None)
        base_url = os.getenv("APP_BASE_URL", "/")
        return RedirectResponse(base_url.rstrip("/") + "/?github=connected")
    except Exception:
        request.session.pop("github_connect_user_id", None)
        base_url = os.getenv("APP_BASE_URL", "/")
        return RedirectResponse(base_url.rstrip("/") + "/?github=error")


@router.get("/api/github/repos")
async def github_repositories(user=Depends(get_current_user)):
    with get_connection() as connection:
        record = connection.execute(
            """
            SELECT encrypted_access_token, github_login
            FROM github_connections WHERE user_id = ?
            """,
            (user["id"],),
        ).fetchone()

    if not record:
        raise HTTPException(404, "Connect your GitHub account first")

    try:
        access_token = decrypt_github_token(record["encrypted_access_token"])
        response = await oauth.github.get(
            "user/repos",
            token={"access_token": access_token, "token_type": "Bearer"},
            params={
                "visibility": "all",
                "affiliation": "owner,collaborator,organization_member",
                "per_page": 100,
                "sort": "updated",
            },
        )
        response.raise_for_status()
        repositories = response.json()

        return {
            "github_login": record["github_login"],
            "repositories": [
                {
                    "id": repo["id"],
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "private": repo["private"],
                    "default_branch": repo["default_branch"],
                    "html_url": repo["html_url"],
                }
                for repo in repositories
            ],
        }
    except Exception:
        raise HTTPException(502, "Could not retrieve GitHub repositories")
