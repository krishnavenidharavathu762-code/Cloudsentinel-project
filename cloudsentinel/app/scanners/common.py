import re
import hashlib
from collections import Counter


def finding(
    title,
    severity="info",
    detail="",
    recommendation="",
    *,
    file_path=None,
    line=None,
    line_end=None,
    column=None,
    cwe=None,
    cve=None,
    confidence="medium",
    evidence=None,
    impact=None,
    root_cause=None,
    remediation=None,
    fixed_code=None,
    references=None,
    status="open",
    scanner=None,
):
    severity = str(severity or "info").lower()

    if severity not in {"critical", "high", "medium", "low", "info", "unknown"}:
        severity = "info"

    evidence = evidence or ""

    identity = "|".join([
        str(title),
        str(file_path or ""),
        str(line or ""),
        str(detail or ""),
    ])

    finding_id = hashlib.sha256(
        identity.encode("utf-8", errors="replace")
    ).hexdigest()[:16]

    return {
        "id": finding_id,
        "title": str(title),
        "severity": severity,
        "detail": str(detail or ""),
        "recommendation": str(recommendation or ""),
        "location": {
            "file_path": file_path,
            "line": line,
            "line_end": line_end,
            "column": column,
        },
        "cwe": cwe,
        "cve": cve,
        "confidence": confidence,
        "evidence": evidence,
        "impact": impact or "",
        "root_cause": root_cause or "",
        "remediation": remediation or recommendation or "",
        "fixed_code": fixed_code or "",
        "references": references or [],
        "status": status,
        "scanner": scanner,
    }


def risk_summary(findings):
    order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
        "unknown": -1,
    }

    counts = Counter(
        str(item.get("severity", "info")).lower()
        for item in findings
    )

    counts = {
        severity: counts.get(severity, 0)
        for severity in order
    }

    known_findings = [
        item for item in findings
        if str(item.get("severity", "info")).lower() in {
            "critical", "high", "medium", "low", "info"
        }
    ]

    score = max(
        (order[str(item.get("severity", "info")).lower()]
         for item in known_findings),
        default=None,
    )

    risk_names = {
        4: "Critical",
        3: "High",
        2: "Medium",
        1: "Low",
        0: "Informational",
        -1: "Unclassified",
    }

    weighted_score = (
        counts["critical"] * 10
        + counts["high"] * 7
        + counts["medium"] * 4
        + counts["low"] * 1
    )

    return {
        "risk": risk_names[score] if score is not None else "Unclassified",
        "finding_count": len(findings),
        "severity_counts": counts,
        "risk_score": weighted_score if known_findings else None,
    }


SECRET_PATTERNS = [
    (
        "Private key",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    ),
    (
        "AWS access key",
        r"\bAKIA[0-9A-Z]{16}\b",
    ),
    (
        "Credential assignment",
        r"""(?i)(password|passwd|api[_-]?key|secret|token)\s*[:=]\s*['"][^'"]{8,}['"]""",
    ),
]


def detect_secrets_detailed(text):
    results = []

    for label, pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            line = text.count("\n", 0, match.start()) + 1
            last_newline = text.rfind("\n", 0, match.start())
            column = match.start() - last_newline

            results.append({
                "type": label,
                "line": line,
                "column": column,
                "evidence": match.group(0)[:120],
                "confidence": "high",
            })

    return results


def detect_secrets(text):
    return [
        f'{item["type"]} near character '
        f'{item["line"]}:{item["column"]}'
        for item in detect_secrets_detailed(text)
    ]
