import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.scanners.common import finding, risk_summary


def scan_checkov(filename, content):
    if not shutil.which("checkov"):
        raise ValueError("Checkov is not installed or not available in PATH")

    suffix = Path(filename).suffix.lower()
    if suffix not in {".tf", ".tfvars"}:
        raise ValueError("Checkov accepts .tf or .tfvars files")

    with tempfile.TemporaryDirectory(prefix="cloudsentinel-checkov-") as temp:
        target = Path(temp) / Path(filename).name
        target.write_bytes(content)

        command = [
            "checkov",
            "--file", str(target),
            "--framework", "terraform",
            "--output", "json",
            "--quiet",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ValueError("Checkov scan timed out after 180 seconds")

        if result.returncode not in (0, 1):
            raise ValueError(
                "Checkov execution failed: " + result.stderr[-1000:]
            )

        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            raise ValueError("Checkov returned invalid JSON output")

    if isinstance(data, list):
        results = data[0].get("results", {}) if data else {}
    else:
        results = data.get("results", {})

    failed = results.get("failed_checks", [])
    passed = results.get("passed_checks", [])
    skipped = results.get("skipped_checks", [])

    findings = []

    for item in failed:
        line = item.get("file_line_range") or []
        line_start = line[0] if line else None
        line_end = line[1] if len(line) > 1 else line_start

        check_id = item.get("check_id", "Unknown Check")
        title = item.get("check_name") or check_id
        resource = item.get("resource", "Unknown resource")
        guideline = item.get("guideline", "")
        code = item.get("code_block") or []

        evidence = "\n".join(
            str(part[0]) if isinstance(part, (list, tuple)) else str(part)
            for part in code
        )[:1000]

        severity = str(item.get("severity") or "unknown").lower()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "unknown"

        findings.append(finding(
            title=f"{check_id}: {title}",
            severity=severity,
            detail=f"Checkov detected a Terraform policy violation in {resource}.",
            file_path=item.get("file_path") or filename,
            line=line_start,
            line_end=line_end,
            evidence=evidence,
            impact=guideline or "The resource may violate an infrastructure security policy.",
            root_cause=f"Resource: {resource}. Check: {check_id}.",
            recommendation=guideline or "Review the failed Checkov policy and correct the Terraform configuration.",
            confidence="high",
            scanner="Checkov",
        ))

    summary = risk_summary(findings)

    if findings:
        status = "High Risk" if any(
            f.get("severity") in {"critical", "high"} for f in findings
        ) else "Needs Attention"
    else:
        status = "Fine"

    if not findings:
        findings.append(finding(
            title="No Checkov policy violations detected",
            severity="info",
            detail="Checkov did not report failed Terraform checks in this file.",
            scanner="Checkov",
            confidence="medium",
        ))

    return {
        "tool": "Checkov Infrastructure Security Scanner",
        "target": filename,
        "status": status,
        "summary": summary,
        "findings": findings,
        "metadata": {
            "engine": "Checkov",
            "version": "3.4.3",
            "failed_checks": len(failed),
            "passed_checks": len(passed),
            "skipped_checks": len(skipped),
        },
    }
