import ast
import re
from pathlib import PurePath

from app.scanners.common import (
    finding,
    risk_summary,
    detect_secrets_detailed,
)

LANG = {
    '.py': 'Python',
    '.java': 'Java',
    '.js': 'JavaScript',
    '.ts': 'TypeScript',
    '.go': 'Go',
    '.rb': 'Ruby',
    '.php': 'PHP',
    '.cs': 'C#',
    '.cpp': 'C++',
    '.c': 'C',
    '.sh': 'Shell',
}


def scan_code(name, data):
    text = data.decode('utf-8', errors='replace')
    ext = PurePath(name).suffix.lower()
    lang = LANG.get(ext, 'Unknown')

    findings = []
    funcs = 0
    classes = 0
    imports = []

    def add_finding(
        title,
        severity,
        detail,
        recommendation,
        line,
        column=1,
        confidence='medium',
        evidence='',
        cwe=None,
        impact='',
        root_cause='',
        fixed_code='',
    ):
        findings.append(finding(
            title,
            severity,
            detail,
            recommendation,
            file_path=name,
            line=line,
            column=column,
            confidence=confidence,
            evidence=evidence[:300],
            cwe=cwe,
            impact=impact,
            root_cause=root_cause,
            fixed_code=fixed_code,
            scanner='Source Code Analyzer',
        ))

    # Python syntax and structural analysis
    if lang == 'Python':
        try:
            tree = ast.parse(text, filename=name)

            funcs = sum(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                for node in ast.walk(tree)
            )

            classes = sum(
                isinstance(node, ast.ClassDef)
                for node in ast.walk(tree)
            )

            imports = sorted({
                node.name.split('.')[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
            } | {
                node.module.split('.')[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            })

            add_finding(
                'Python syntax valid',
                'info',
                f'{funcs} functions and {classes} classes detected',
                '',
                1,
                confidence='high',
                evidence='Python AST parsing completed successfully',
            )

        except SyntaxError as error:
            add_finding(
                'Python syntax error',
                'high',
                error.msg,
                'Correct the syntax error and rerun the scan.',
                error.lineno or 1,
                error.offset or 1,
                confidence='high',
                evidence=error.text or '',
                cwe='CWE-1164',
                impact='Invalid syntax can prevent the application from starting.',
                root_cause='The Python parser could not parse the source.',
            )

    elif lang == 'Unknown':
        add_finding(
            'Language not recognized',
            'low',
            ext or 'No file extension detected',
            'Use a supported source file extension.',
            1,
            confidence='high',
        )

    # Detect suspicious patterns with exact line and column
    patterns = [
        {
            'pattern': r'\beval\s*\(',
            'title': 'Potential dynamic code execution using eval',
            'severity': 'high',
            'recommendation': 'Avoid eval. Use a safe parser or explicit allowlisted operations.',
            'cwe': 'CWE-95',
            'impact': 'Untrusted input reaching eval may allow arbitrary code execution.',
            'root_cause': 'Dynamic expression evaluation can execute supplied code.',
            'confidence': 'medium',
        },
        {
            'pattern': r'\bexec\s*\(',
            'title': 'Potential dynamic code execution using exec',
            'severity': 'high',
            'recommendation': 'Avoid exec with untrusted input. Replace it with explicit application logic.',
            'cwe': 'CWE-95',
            'impact': 'Untrusted input reaching exec may allow arbitrary code execution.',
            'root_cause': 'Dynamic statement execution can execute supplied code.',
            'confidence': 'medium',
        },
        {
            'pattern': r'(?i)\bverify\s*=\s*False\b',
            'title': 'TLS certificate verification disabled',
            'severity': 'high',
            'recommendation': 'Enable certificate verification and configure a trusted CA bundle.',
            'cwe': 'CWE-295',
            'impact': 'TLS connections may become vulnerable to man-in-the-middle attacks.',
            'root_cause': 'The client is configured not to verify server certificates.',
            'confidence': 'high',
        },
    ]

    for rule in patterns:
        for match in re.finditer(rule['pattern'], text):
            line = text.count('\n', 0, match.start()) + 1
            last_newline = text.rfind('\n', 0, match.start())
            column = match.start() - last_newline

            source_line = text.splitlines()[line - 1] if text.splitlines() else ''

            add_finding(
                rule['title'],
                rule['severity'],
                'Potentially unsafe source-code pattern detected.',
                rule['recommendation'],
                line,
                column,
                rule['confidence'],
                source_line.strip(),
                rule['cwe'],
                rule['impact'],
                rule['root_cause'],
            )

    # Secret detection with exact source locations
    for secret in detect_secrets_detailed(text):
        add_finding(
            'Possible hardcoded secret',
            'critical',
            f'{secret["type"]} detected in source code.',
            'Remove the secret, rotate the exposed credential, and load it from a secure secret manager.',
            secret['line'],
            secret['column'],
            secret['confidence'],
            secret['evidence'],
            'CWE-798',
            'An exposed credential may allow unauthorized access to systems or data.',
            'A sensitive credential appears to be embedded directly in source code.',
        )

    # Basic brace check for supported brace-based languages
    if lang in ('Java', 'JavaScript', 'TypeScript', 'Go', 'C#', 'C++', 'C'):
        if text.count('{') != text.count('}'):
            add_finding(
                'Possible unmatched braces',
                'medium',
                'Opening and closing brace counts do not match.',
                'Review block boundaries and correct unmatched braces.',
                1,
                confidence='low',
                evidence=f'Opening braces: {text.count("{")}; closing braces: {text.count("}")}',
            )

    if not findings:
        add_finding(
            'No basic static issues detected',
            'info',
            'No issues matched the scanner rules.',
            'Use a dedicated SAST tool and manual security review for deeper coverage.',
            1,
            confidence='low',
            evidence='Built-in heuristic checks only',
        )

    return {
        'tool': 'Source Code Analyzer',
        'target': name,
        'summary': risk_summary(findings),
        'metadata': {
            'language': lang,
            'size_bytes': len(data),
            'lines': len(text.splitlines()),
            'functions': funcs,
            'classes': classes,
            'imports': imports,
        },
        'findings': findings,
    }
