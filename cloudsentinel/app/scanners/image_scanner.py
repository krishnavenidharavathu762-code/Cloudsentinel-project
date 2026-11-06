import json
import re
import shutil
import subprocess

from app.scanners.common import finding, risk_summary


SEVERITIES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
}


def _cvss_score(vulnerability):
    scores = []

    for source in (vulnerability.get("CVSS") or {}).values():
        if not isinstance(source, dict):
            continue

        score = source.get("V3Score") or source.get("V2Score")
        if score is not None:
            try:
                scores.append(float(score))
            except (TypeError, ValueError):
                pass

    return max(scores) if scores else None


def _redact(value):
    if not value:
        return ""

    text = str(value)
    text = re.sub(
        r'(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*["\']?[^"\'\s,;]+',
        r'\1=[REDACTED]',
        text
    )
    return text[:300]


def _add_vulnerabilities(findings, result):
    target = result.get("Target", "Unknown image target")

    for vuln in result.get("Vulnerabilities") or []:
        severity = SEVERITIES.get(
            str(vuln.get("Severity", "UNKNOWN")).upper(), "info"
        )

        cve = vuln.get("VulnerabilityID", "Unknown vulnerability")
        package = vuln.get("PkgName", "Unknown package")
        installed = vuln.get("InstalledVersion", "Unknown")
        fixed = vuln.get("FixedVersion") or "No fixed version reported"

        title = f"{cve}: {package}"

        description = (
            vuln.get("Description")
            or vuln.get("Title")
            or f"{package} has a reported vulnerability."
        )

        remediation = (
            f"Upgrade {package} from {installed} to {fixed}."
            if fixed != "No fixed version reported"
            else f"Review {package} and the vendor advisory for {cve}."
        )

        score = _cvss_score(vuln)

        details = (
            f"Image target: {target}\n"
            f"Package: {package}\n"
            f"Installed version: {installed}\n"
            f"Fixed version: {fixed}\n"
            f"CVSS score: {score if score is not None else 'Not provided'}"
        )

        refs = vuln.get("References") or []
        primary_url = vuln.get("PrimaryURL")

        if primary_url:
            refs = [primary_url] + refs

        findings.append(finding(
            title,
            severity,
            f"{description}\n\n{details}",
            remediation,
            cve=cve,
            confidence="high",
            evidence=details,
            impact=f"An affected package in the image may expose the application to {severity} severity vulnerability risk.",
            root_cause=f"The image contains {package} version {installed}, which is reported as vulnerable.",
            references=refs[:10],
            scanner="Trivy",
        ))


def _add_misconfigurations(findings, result):
    target = result.get("Target", "Unknown configuration")

    for issue in result.get("Misconfigurations") or []:
        severity = SEVERITIES.get(
            str(issue.get("Severity", "UNKNOWN")).upper(), "info"
        )

        cause = issue.get("CauseMetadata") or {}
        resource = cause.get("Resource") or issue.get("ID") or "Unknown resource"

        start_line = cause.get("StartLine")
        end_line = cause.get("EndLine")

        code = cause.get("Code") or {}
        lines = code.get("Lines") or []

        evidence = "\n".join(
            str(item.get("Content", ""))
            for item in lines[:8]
            if isinstance(item, dict)
        )

        description = (
            issue.get("Message")
            or issue.get("Description")
            or "A configuration policy violation was detected."
        )

        remediation = (
            issue.get("Resolution")
            or "Review the failed security policy and update the configuration."
        )

        findings.append(finding(
            issue.get("Title") or issue.get("ID") or "Infrastructure misconfiguration",
            severity,
            f"{description}\nResource: {resource}\nTarget: {target}",
            remediation,
            file_path=target,
            line=start_line,
            line_end=end_line,
            cwe=issue.get("CweIDs", [None])[0]
                if issue.get("CweIDs") else None,
            confidence="high",
            evidence=_redact(evidence),
            impact="The configuration may violate a security policy and expose infrastructure to risk.",
            root_cause=f"Resource {resource} failed policy {issue.get('ID', 'unknown')}.",
            references=(issue.get("References") or [])[:10],
            scanner="Trivy",
        ))


def _add_secrets(findings, result):
    target = result.get("Target", "Unknown image target")

    for secret in result.get("Secrets") or []:
        start_line = secret.get("StartLine")
        end_line = secret.get("EndLine")

        rule = secret.get("RuleID") or "Secret detected"
        category = secret.get("Category") or "Unknown secret type"

        code = secret.get("Code") or {}
        lines = code.get("Lines") or []

        evidence = "[REDACTED - secret evidence withheld]"

        findings.append(finding(
            secret.get("Title") or f"Possible exposed secret: {category}",
            "critical",
            f"Trivy detected a possible {category} secret.\nTarget: {target}",
            "Revoke or rotate the exposed credential, remove it from the image, and store secrets in a secure secret manager.",
            file_path=target,
            line=start_line,
            line_end=end_line,
            confidence="high",
            evidence=_redact(evidence),
            impact="An exposed credential may allow unauthorized access to systems or data.",
            root_cause=f"Secret detection rule {rule} matched content in the scanned target.",
            scanner="Trivy",
        ))


def scan_image(image):
    if not isinstance(image, str) or not re.fullmatch(
        r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,250}', image
    ):
        raise ValueError("Invalid image reference")

    trivy = shutil.which("trivy")

    if not trivy:
        raise ValueError("Trivy is not installed on the CloudSentinel server")

    command = [
        trivy,
        "image",
        "--format", "json",
        "--quiet",
        "--scanners", "vuln,misconfig,secret",
        image,
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=360,
        )

        if process.returncode not in (0, 1):
            error = (process.stderr or "Unknown Trivy error")[-1500:]
            raise ValueError(f"Trivy execution failed: {error}")

        try:
            data = json.loads(process.stdout or "{}")
        except json.JSONDecodeError:
            raise ValueError("Trivy returned invalid JSON output")

        if not isinstance(data, dict):
            raise ValueError("Trivy returned an unexpected report format")

        findings = []

        results = data.get("Results") or []

        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }

        for result in results:
            if not isinstance(result, dict):
                continue

            for vuln in result.get("Vulnerabilities") or []:
                severity = str(vuln.get("Severity", "UNKNOWN")).upper()
                counts[severity if severity in counts else "UNKNOWN"] += 1

            _add_vulnerabilities(findings, result)
            _add_misconfigurations(findings, result)
            _add_secrets(findings, result)

        if not findings:
            findings.append(finding(
                "No security findings detected",
                "info",
                "Trivy did not report vulnerabilities, misconfigurations or secrets in the scanned image.",
                "Continue regular scanning and review the scanner coverage.",
                confidence="high",
                scanner="Trivy",
            ))

        return {
            "tool": "Trivy Container Security Scanner",
            "target": image,
            "summary": risk_summary(findings),
            "metadata": {
                "available": True,
                "execution_status": "completed",
                "scanner": "Trivy",
                "scanner_version": "0.76.1",
                "scanners_enabled": ["vuln", "misconfig", "secret"],
                "vulnerability_counts": counts,
                "result_targets": [
                    result.get("Target")
                    for result in results
                    if result.get("Target")
                ],
                "result_count": len(results),
            },
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        raise ValueError("Trivy scan timed out after 360 seconds")
