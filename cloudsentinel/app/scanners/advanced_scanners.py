import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from app.scanners.common import finding, risk_summary

MAX_FILES = 5000
MAX_UNPACKED = 100 * 1024 * 1024
ALLOWED_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb",
    ".php", ".cs", ".html", ".xml", ".yaml", ".yml", ".json",
    ".tf", ".tfvars", ".sh", ".sql", ".properties", ".toml",
    ".ini", ".cfg", ". Dockerfile"
}

def _extract_zip(name, data, root):
    if not zipfile.is_zipfile(__import__("io").BytesIO(data)):
        raise ValueError("Upload a valid ZIP archive")
    total = 0
    count = 0
    with zipfile.ZipFile(__import__("io").BytesIO(data)) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            count += 1
            total += item.file_size
            if count > MAX_FILES or total > MAX_UNPACKED:
                raise ValueError("ZIP exceeds the file-count or unpacked-size limit")
            target = (root / item.filename).resolve()
            if not target.is_relative_to(root.resolve()):
                raise ValueError("ZIP contains an unsafe file path")
            if item.file_size > MAX_UNPACKED:
                raise ValueError("ZIP contains an oversized file")
        archive.extractall(root)

def _run(command, timeout=240):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=timeout, check=False,
            env={**os.environ, "NO_COLOR": "1"}
        )
        return result
    except subprocess.TimeoutExpired:
        raise ValueError("Scanner timed out. Try a smaller project ZIP.")

def _walk(root):
    ignored = {".git", ".venv", "venv", "node_modules", "__pycache__",
               ".terraform", "dist", "build"}
    for path in root.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue
        if path.is_file():
            yield path

def _tool_report(tool, target, findings, metadata=None):
    return {
        "tool": tool,
        "target": target,
        "status": "completed",
        "summary": risk_summary(findings),
        "findings": findings,
        "metadata": metadata or {},
    }

def scan_advanced(name, data, scanner):
    scanner = scanner.lower()
    if scanner not in {"semgrep", "bandit", "gitleaks"}:
        raise ValueError("Unsupported scanner")
    project_root = Path(__file__).resolve().parents[2]
    executables = {
        "semgrep": Path("/opt/cloudsentinel-semgrep/bin/semgrep"),
        "bandit": project_root / ".venv/bin/bandit",
        "gitleaks": Path("/usr/local/bin/gitleaks"),
    }
    executable_path = executables[scanner]
    if not executable_path.is_file():
        raise ValueError(f"{scanner} executable not found: {executable_path}")
    executable = str(executable_path)

    with tempfile.TemporaryDirectory(prefix="cloudsentinel-") as tmp:
        root = Path(tmp) / "project"
        root.mkdir()
        _extract_zip(name, data, root)
        findings = []

        if scanner == "semgrep":
            result = _run([
                executable, "scan", "--config", "p/default",
                "--json", "--quiet", "--metrics=off", str(root)
            ])
            if result.returncode not in (0, 1):
                raise ValueError("Semgrep failed: " + result.stderr[-1200:])
            try:
                output = json.loads(result.stdout or "{}")
            except json.JSONDecodeError:
                raise ValueError("Semgrep returned invalid JSON")
            for item in output.get("results", []):
                extra = item.get("extra") or {}
                start = item.get("start") or {}
                end = item.get("end") or {}
                path = item.get("path", "")
                metadata = extra.get("metadata") or {}
                raw_severity = str(extra.get("severity", "unknown")).upper()
                severity_map = {
                    "ERROR": "high",
                    "WARNING": "medium",
                    "INFO": "info",
                }
                severity = severity_map.get(raw_severity, "unknown")

                raw_path = Path(item.get("path", ""))
                try:
                    relative_path = str(raw_path.relative_to(root))
                except ValueError:
                    relative_path = str(raw_path)

                findings.append(finding(
                    item.get("check_id", "Semgrep finding"),
                    severity=severity,
                    detail=extra.get("message", "Semgrep detected a matching rule"),
                    recommendation=metadata.get("technology", ["Review the rule guidance and remediate the unsafe pattern"]),
                    file_path=relative_path,
                    line=start.get("line"),
                    line_end=end.get("line"),
                    column=start.get("col"),
                    cwe=(metadata.get("cwe") or [None])[0],
                    confidence=str(extra.get("confidence", "medium")).lower(),
                    evidence=extra.get("lines", ""),
                    scanner="Semgrep",
                    references=metadata.get("references") or [],
                ))
            return _tool_report("Semgrep", name, findings, {
                "engine": "Semgrep CLI", "exit_code": result.returncode
            })

        if scanner == "bandit":
            py_files = [str(p) for p in _walk(root) if p.suffix == ".py"]
            if not py_files:
                return _tool_report("Bandit", name, [], {
                    "engine": "Bandit", "message": "No Python files found"
                })
            result = _run([executable, "-f", "json", "-q", *py_files])
            if result.returncode not in (0, 1):
                raise ValueError("Bandit failed: " + result.stderr[-1200:])
            try:
                output = json.loads(result.stdout or "{}")
            except json.JSONDecodeError:
                raise ValueError("Bandit returned invalid JSON")
            for item in output.get("results", []):
                raw_path = Path(item.get("filename", ""))
                try:
                    relative_path = str(raw_path.relative_to(root))
                except ValueError:
                    relative_path = str(raw_path)

                findings.append(finding(
                    item.get("test_name", "Bandit finding"),
                    severity=str(item.get("issue_severity", "unknown")).lower(),
                    detail=item.get("issue_text", ""),
                    recommendation="Review the flagged Python operation and apply the secure alternative.",
                    file_path=relative_path,
                    line=item.get("line_number"),
                    line_end=item.get("line_number"),
                    column=item.get("col_offset"),
                    confidence=str(item.get("issue_confidence", "medium")).lower(),
                    evidence=item.get("code", ""),
                    scanner="Bandit",
                    references=[item["more_info"]] if item.get("more_info") else [],
                ))
            return _tool_report("Bandit", name, findings, {
                "engine": "Bandit", "python_files": len(py_files)
            })

        report_path = Path(tmp) / "gitleaks-report.json"
        result = _run([
            executable, "detect", "--source", str(root),
            "--report-format", "json", "--report-path", str(report_path),
            "--no-git", "--exit-code", "0"
        ])
        if result.returncode != 0:
            raise ValueError("Gitleaks failed: " + result.stderr[-1200:])
        try:
            output = json.loads(report_path.read_text()) if report_path.exists() else []
        except json.JSONDecodeError:
            raise ValueError("Gitleaks returned invalid JSON")
        for item in output:
            raw_path = Path(item.get("File", ""))
            try:
                relative_path = str(raw_path.relative_to(root))
            except ValueError:
                relative_path = str(raw_path)

            findings.append(finding(
                item.get("RuleID", "Potential secret"),
                severity="high",
                detail="Gitleaks detected a possible exposed secret. The value is intentionally not reproduced in this report.",
                recommendation="Revoke and rotate the credential, remove it from source control history, and use a secrets manager.",
                file_path=relative_path,
                line=item.get("StartLine"),
                line_end=item.get("EndLine"),
                column=item.get("StartColumn"),
                confidence="high",
                evidence="Secret value redacted",
                impact="An exposed credential may allow unauthorized access to connected services.",
                root_cause="A credential-like value was committed or stored in project files.",
                scanner="Gitleaks",
            ))
        return _tool_report("Gitleaks", name, findings, {
            "engine": "Gitleaks"
        })
