import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile

from pathlib import Path, PurePosixPath

import httpx

from app.scanners.common import finding, risk_summary


SONAR_URL = "http://127.0.0.1:9000"
SCANNER_URL = "http://cloudsentinel-sonarqube:9000"
TOKEN_FILE = Path("/etc/cloudsentinel/sonarqube-token")
SCANNER_IMAGE = "sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1"
DOCKER_NETWORK = "cloudsentinel-security"

MAX_UPLOAD = 25 * 1024 * 1024
MAX_FILES = 5000
MAX_UNPACKED = 100 * 1024 * 1024

SEVERITIES = {
    "BLOCKER": "critical",
    "CRITICAL": "critical",
    "MAJOR": "high",
    "MINOR": "medium",
    "INFO": "info",
}


def _extract_project(data, root):
    try:
        archive = zipfile.ZipFile(__import__("io").BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("Invalid project ZIP file")

    with archive:
        entries = archive.infolist()

        if len(entries) > MAX_FILES:
            raise ValueError("Project contains too many files")

        total = 0

        for item in entries:
            path = PurePosixPath(item.filename)

            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Unsafe path found in project ZIP")

            if item.flag_bits & 1:
                raise ValueError("Encrypted ZIP files are not supported")

            mode = item.external_attr >> 16
            if (mode & 0o170000) == 0o120000:
                raise ValueError("Symbolic links are not allowed")

            total += item.file_size

            if total > MAX_UNPACKED:
                raise ValueError("Uncompressed project exceeds 100 MB")

            if item.is_dir():
                continue

            destination = root.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)

            with archive.open(item) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)


def _wait_for_processing(task_url, token):
    with httpx.Client(timeout=15) as client:
        for _ in range(60):
            response = client.get(
                task_url,
                auth=(token, ""),
            )
            response.raise_for_status()

            task = response.json().get("task", {})
            status = task.get("status")

            if status == "SUCCESS":
                return

            if status in {"FAILED", "CANCELED"}:
                raise ValueError(
                    "SonarQube analysis processing failed"
                )

            time.sleep(2)

    raise ValueError("SonarQube analysis timed out while processing")


def _retrieve_issues(project_key, token, root):
    results = []
    page = 1

    with httpx.Client(timeout=30) as client:
        while True:
            response = client.get(
                f"{SONAR_URL}/api/issues/search",
                params={
                    "componentKeys": project_key,
                    "ps": 500,
                    "p": page,
                },
                auth=(token, ""),
            )
            response.raise_for_status()

            payload = response.json()
            issues = payload.get("issues", [])

            for item in issues:
                component = item.get("component", "")
                file_path = (
                    component.split(":", 1)[1]
                    if ":" in component else component
                )

                rule = item.get("rule", "SonarQube issue")
                severity = SEVERITIES.get(
                    item.get("severity", "").upper(),
                    "unknown",
                )

                issue_type = item.get("type", "CODE_SMELL")
                message = item.get("message", "")

                tags = item.get("tags", [])
                cwe = next(
                    (tag.upper() for tag in tags
                     if tag.lower().startswith("cwe-")),
                    None,
                )

                results.append(finding(
                    title=f"{issue_type}: {rule}",
                    severity=severity,
                    detail=message,
                    recommendation=(
                        "Review the SonarQube rule and correct the "
                        "underlying code issue."
                    ),
                    file_path=file_path or None,
                    line=item.get("line"),
                    line_end=item.get("textRange", {}).get("endLine"),
                    column=item.get("textRange", {}).get("startOffset"),
                    cwe=cwe,
                    confidence="medium",
                    evidence=message,
                    impact=(
                        "Potential security, reliability or maintainability "
                        "impact. Validate the finding in its code context."
                    ),
                    root_cause=(
                        f"SonarQube rule {rule} identified this issue."
                    ),
                    remediation=(
                        "Review the rule description and update the "
                        "affected code."
                    ),
                    references=[
                        f"https://rules.sonarsource.com/"
                    ],
                    scanner="SonarQube",
                ))

            total = payload.get("total", len(issues))

            if not issues or page * 500 >= total:
                break

            page += 1

    return results



def _retrieve_hotspots(project_key, token):
    results = []
    page = 1

    probability_map = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }

    with httpx.Client(timeout=30) as client:
        while True:
            response = client.get(
                f"{SONAR_URL}/api/hotspots/search",
                params={
                    "project": project_key,
                    "ps": 500,
                    "p": page,
                },
                auth=(token, ""),
            )
            response.raise_for_status()

            payload = response.json()
            hotspots = payload.get("hotspots", [])

            for item in hotspots:
                component = item.get("component", "")
                file_path = (
                    component.split(":", 1)[1]
                    if ":" in component else component
                )

                rule = item.get("ruleKey", "SonarQube security hotspot")
                message = item.get("message", "")
                probability = item.get(
                    "vulnerabilityProbability", ""
                ).upper()

                review_status = item.get("status", "TO_REVIEW").upper()
                status = (
                    "needs_review"
                    if review_status == "TO_REVIEW"
                    else "reviewed"
                )

                results.append(finding(
                    title=f"Security Hotspot: {rule}",
                    severity=probability_map.get(probability, "unknown"),
                    detail=message,
                    recommendation=(
                        "Review this security hotspot in context. "
                        "Determine whether the code creates an exploitable "
                        "risk before classifying it as a vulnerability."
                    ),
                    file_path=file_path or None,
                    line=item.get("line"),
                    line_end=item.get("textRange", {}).get("endLine"),
                    column=item.get("textRange", {}).get("startOffset"),
                    confidence="medium",
                    evidence=message,
                    impact=(
                        "Potential security exposure identified by "
                        "SonarQube. Exploitability has not yet been confirmed."
                    ),
                    root_cause=(
                        f"SonarQube security rule {rule} identified "
                        "security-sensitive code requiring review."
                    ),
                    remediation=(
                        "Review the hotspot guidance and surrounding code. "
                        "Record whether the code is safe or requires a fix."
                    ),
                    references=["https://rules.sonarsource.com/"],
                    status=status,
                    scanner="SonarQube Security Hotspot",
                ))

            total = payload.get("paging", {}).get(
                "total", payload.get("total", len(hotspots))
            )

            if not hotspots or page * 500 >= total:
                break

            page += 1

    return results


def scan_sonarqube(name, data):
    if not TOKEN_FILE.is_file():
        raise ValueError("SonarQube token file is missing")

    token = TOKEN_FILE.read_text(encoding="utf-8").strip()

    if not token:
        raise ValueError("SonarQube token is empty")

    project_key = "cloudsentinel-" + uuid.uuid4().hex[:16]

    with tempfile.TemporaryDirectory(
        prefix="cloudsentinel-sonar-",
        dir="/opt/cloudsentinel-sonarqube/work",
    ) as temporary:
        root = Path(temporary)
        _extract_project(data, root)

        # The official scanner container runs as UID 1000.
        # Give it ownership of the mounted project directory.
        os.chown(root, 1000, 1000)

        config = root / "sonar-project.properties"
        config.write_text(
            "\n".join([
                f"sonar.projectKey={project_key}",
                "sonar.projectName=CloudSentinel Analysis",
                "sonar.sources=.",
                "sonar.scm.disabled=true",
                "sonar.exclusions=**/.git/**,**/.venv/**,**/venv/**,"
                "**/node_modules/**,**/__pycache__/**,**/dist/**,"
                "**/build/**,**/.terraform/**",
                "",
            ]),
            encoding="utf-8",
        )

        command = [
            "docker", "run", "--rm",
            "--network", DOCKER_NETWORK,
            "-v", f"{root}:/usr/src",
            "-w", "/usr/src",
            "-e", f"SONAR_HOST_URL={SCANNER_URL}",
            "-e", "SONAR_USER_HOME=/tmp/.sonar",
            "-e", "SONAR_TOKEN",
            SCANNER_IMAGE,
            f"-Dsonar.projectKey={project_key}",
            "-Dsonar.sources=.",
            "-Dsonar.scm.disabled=true",
            "-Dsonar.scanner.metadataFilePath=/usr/src/report-task.txt",
        ]

        environment = os.environ.copy()
        environment["SONAR_TOKEN"] = token

        try:
            result = subprocess.run(
                command,
                env=environment,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            raise ValueError("SonarQube scanner exceeded its time limit")

        if result.returncode != 0:
            error = (result.stderr or result.stdout or "")[-1500:]
            raise ValueError(
                "SonarQube scanner failed: " + error
            )

        task_file = root / "report-task.txt"

        if not task_file.is_file():
            diagnostic = (result.stdout or "")[-4000:]
            diagnostic += "\\nSTDERR:\\n" + (result.stderr or "")[-2000:]
            raise ValueError(
                "SonarQube task report missing. Scanner output:\\n"
                + diagnostic
            )

        task_data = {}
        for line in task_file.read_text(
            encoding="utf-8"
        ).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                task_data[key.strip()] = value.strip()

        task_url = task_data.get("ceTaskUrl")

        if not task_url or not task_url.startswith(SCANNER_URL + "/"):
            raise ValueError("Invalid SonarQube task URL")

        task_url = SONAR_URL + task_url[len(SCANNER_URL):]
        _wait_for_processing(task_url, token)
        findings = _retrieve_issues(project_key, token, root)
        findings.extend(_retrieve_hotspots(project_key, token))

        return {
            "tool": "SonarQube",
            "target": name,
            "project_key": project_key,
            "summary": risk_summary(findings),
            "findings": findings,
            "scanner_status": "completed",
        }
