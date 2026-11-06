import json
import os
import re
import httpx
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent.parent
load_dotenv(BASE / ".env")

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from app.auth_db import init_db, get_connection
from app.auth_routes import router as auth_router
from app.auth_routes import get_current_user
from app.auth_security import decrypt_github_token

from app.scanners.zip_scanner import scan_zip
from app.scanners.code_scanner import scan_code
from app.scanners.project_scanner import scan_project_zip
from app.scanners.url_scanner import scan_url
from app.scanners.image_scanner import scan_image
from app.scanners.terraform_scanner import scan_terraform
from app.scanners.checkov_scanner import scan_checkov
from app.scanners.advanced_scanners import scan_advanced
from app.scanners.sonarqube_scanner import scan_sonarqube

REPORTS = BASE / "data" / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)

SESSION_SECRET = os.getenv("SESSION_SECRET", "")
if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is missing from .env")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

app = FastAPI(title="CloudSentinel", version="1.0.0")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="cloudsentinel_session",
    max_age=12 * 60 * 60,
    same_site="lax",
    https_only=COOKIE_SECURE,
)

app.mount(
    "/static",
    StaticFiles(directory=str(BASE / "app" / "static")),
    name="static",
)

app.include_router(auth_router)
init_db()


class URLRequest(BaseModel):
    url: str


class ImageRequest(BaseModel):
    image: str


def persist(report, user_id):
    report["scan_id"] = str(uuid.uuid4())
    report["created_at"] = datetime.now(timezone.utc).isoformat()
    report["user_id"] = user_id

    report_path = REPORTS / f'{report["scan_id"]}.json'
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    return report


async def upload(file, limit=25 * 1024 * 1024):
    name = Path(file.filename or "upload").name
    data = await file.read(limit + 1)

    if not data:
        raise HTTPException(400, "Empty file")

    if len(data) > limit:
        raise HTTPException(413, "Upload exceeds size limit")

    return name, data


@app.get("/", response_class=HTMLResponse)
@app.get("/reset-password", response_class=HTMLResponse)
def home():
    return (
        BASE / "app" / "static" / "index.html"
    ).read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "CloudSentinel",
        "version": "1.0.0",
    }


@app.get("/api/scans")
def scans(user=Depends(get_current_user)):
    out = []

    for path in sorted(
        REPORTS.glob("*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    ):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            if report.get("user_id") == user["id"]:
                out.append(report)
            if len(out) >= 30:
                break
        except (OSError, json.JSONDecodeError):
            continue

    return {"scans": out}


@app.post("/api/scan/zip")
async def zip_scan(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    name, data = await upload(file)

    if not name.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a ZIP file")

    try:
        return persist(scan_zip(name, data), user["id"])
    except ValueError as error:
        raise HTTPException(400, str(error))


@app.post("/api/scan/project")
async def project_scan(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    name, data = await upload(file)

    if not name.lower().endswith(".zip"):
        raise HTTPException(400, "Project scan expects ZIP")

    try:
        return persist(scan_project_zip(name, data), user["id"])
    except ValueError as error:
        raise HTTPException(400, str(error))


@app.post("/api/scan/code")
async def code_scan(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    name, data = await upload(file, 2 * 1024 * 1024)
    return persist(scan_code(name, data), user["id"])


@app.post("/api/scan/terraform")
async def tf_scan(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    name, data = await upload(file)

    if not name.endswith((".tf", ".tfvars")):
        raise HTTPException(400, "Upload .tf or .tfvars")

    result = scan_terraform(
        name,
        data.decode("utf-8", errors="replace"),
    )
    return persist(result, user["id"])


@app.post("/api/scan/url")
async def web_scan(
    body: URLRequest,
    user=Depends(get_current_user),
):
    try:
        return persist(await scan_url(body.url), user["id"])
    except ValueError as error:
        raise HTTPException(400, str(error))


@app.post("/api/scan/image")
def image_scan(
    body: ImageRequest,
    user=Depends(get_current_user),
):
    try:
        return persist(scan_image(body.image), user["id"])
    except ValueError as error:
        raise HTTPException(400, str(error))


@app.post("/api/scan/checkov")
async def checkov_scan(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    name, data = await upload(file, 5 * 1024 * 1024)

    if not name.lower().endswith((".tf", ".tfvars")):
        raise HTTPException(400, "Upload a .tf or .tfvars file")

    try:
        return persist(scan_checkov(name, data), user["id"])
    except ValueError as error:
        raise HTTPException(400, str(error))



class GitHubGitleaksRequest(BaseModel):
    owner: str
    repo: str
    branch: str


@app.post("/api/scan/github/gitleaks")
async def github_gitleaks_scan(
    body: GitHubGitleaksRequest,
    user=Depends(get_current_user),
):
    owner = body.owner.strip()
    repo = body.repo.strip()
    branch = body.branch.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner):
        raise HTTPException(400, "Invalid GitHub owner")

    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo):
        raise HTTPException(400, "Invalid GitHub repository")

    if (
        not branch
        or len(branch) > 255
        or branch.startswith("-")
        or ".." in branch
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", branch)
    ):
        raise HTTPException(400, "Invalid GitHub branch")

    with get_connection() as connection:
        record = connection.execute(
            """
            SELECT encrypted_access_token
            FROM github_connections
            WHERE user_id = ?
            """,
            (user["id"],),
        ).fetchone()

    if not record:
        raise HTTPException(404, "Connect your GitHub account first")

    try:
        access_token = decrypt_github_token(
            record["encrypted_access_token"]
        )
    except Exception:
        raise HTTPException(500, "Could not access your GitHub connection")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CloudSentinel",
    }

    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    archive_url = (
        f"https://api.github.com/repos/{owner}/{repo}/zipball/"
        f"{quote(branch, safe='')}"
    )

    try:
        archive = bytearray()

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            follow_redirects=True,
        ) as client:

            repo_response = await client.get(api_url, headers=headers)

            if repo_response.status_code in (403, 404):
                raise HTTPException(
                    404,
                    "Repository not found or your GitHub account has no access",
                )

            repo_response.raise_for_status()

            async with client.stream(
                "GET",
                archive_url,
                headers=headers,
            ) as response:
                response.raise_for_status()

                async for chunk in response.aiter_bytes():
                    archive.extend(chunk)

                    if len(archive) > 25 * 1024 * 1024:
                        raise HTTPException(
                            413,
                            "GitHub repository archive exceeds 25 MB",
                        )

        if not archive:
            raise HTTPException(400, "GitHub returned an empty repository")

        target = f"github:{owner}/{repo}@{branch}.zip"

        result = await run_in_threadpool(
            scan_advanced,
            target,
            bytes(archive),
            "gitleaks",
        )

        return persist(result, user["id"])

    except HTTPException:
        raise
    except httpx.HTTPStatusError as error:
        raise HTTPException(
            502,
            f"GitHub archive request failed with HTTP {error.response.status_code}",
        )
    except httpx.RequestError:
        raise HTTPException(502, "Could not connect to GitHub")
    except ValueError as error:
        raise HTTPException(400, str(error))
    except Exception:
        raise HTTPException(500, "GitHub Gitleaks scan failed")


@app.post("/api/scan/advanced/{scanner}")
async def advanced_scan(
    scanner: str,
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    if scanner.lower() not in {"semgrep", "bandit", "gitleaks"}:
        raise HTTPException(400, "Choose semgrep, bandit or gitleaks")

    name, data = await upload(file, 25 * 1024 * 1024)

    if not name.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a project ZIP file")

    try:
        result = scan_advanced(name, data, scanner)
        return persist(result, user["id"])
    except ValueError as error:
        raise HTTPException(400, str(error))


@app.post("/api/scan/sonarqube")
async def sonarqube_scan(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    name, data = await upload(file, 25 * 1024 * 1024)

    if not name.lower().endswith(".zip"):
        raise HTTPException(
            400,
            "SonarQube analysis expects a project ZIP file",
        )

    try:
        result = await run_in_threadpool(scan_sonarqube, name, data)
        return persist(result, user["id"])
    except ValueError as error:
        raise HTTPException(400, str(error))
