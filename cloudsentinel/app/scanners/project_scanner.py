import json
import re
from pathlib import PurePosixPath

from app.scanners.zip_scanner import inspect_zip
from app.scanners.common import (
    finding,
    risk_summary,
    detect_secrets_detailed,
)
from app.scanners.code_scanner import LANG, scan_code

MANIFESTS = {
    'requirements.txt': 'Python pip',
    'pyproject.toml': 'Python project',
    'Pipfile': 'Pipenv',
    'pom.xml': 'Maven',
    'build.gradle': 'Gradle',
    'package.json': 'Node.js',
    'go.mod': 'Go modules',
    'Gemfile': 'Ruby Bundler',
    'Cargo.toml': 'Rust Cargo',
}

STARTS = [
    'main.py', 'app.py', 'manage.py', 'wsgi.py', 'asgi.py',
    'pom.xml', 'build.gradle', 'package.json', 'main.go',
    'Program.cs', 'Dockerfile',
]

MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024

CONFIG_EXTENSIONS = {
    '.json', '.yaml', '.yml', '.env', '.tf', '.tfvars',
    '.toml', '.ini', '.conf', '.cfg', '.properties',
    '.xml', '.sh',
}


def scan_project_zip(name, data):
    z, files, total, findings = inspect_zip(name, data)

    manifests = []
    starts = []
    languages = {}
    inventory = []
    source_files_scanned = 0
    source_files_skipped = 0
    total_file_findings = 0

    try:
        names = [item['path'] for item in files]

        # Build a complete file inventory.
        for item in files:
            path = item['path']
            pure_path = PurePosixPath(path)
            base = pure_path.name
            ext = pure_path.suffix.lower()

            language = LANG.get(ext, 'Other')

            if ext in LANG:
                languages[language] = languages.get(language, 0) + 1

            entry = {
                **item,
                'file_name': base,
                'extension': ext or 'No extension',
                'file_type': language,
                'analysis_status': 'not_applicable',
                'findings_count': 0,
            }

            inventory.append(entry)

            if base in MANIFESTS:
                manifests.append({
                    'file': path,
                    'type': MANIFESTS[base],
                })

            if base in STARTS:
                starts.append(path)

        # Inspect dependency manifests.
        for manifest in manifests:
            path = manifest['file']
            base = PurePosixPath(path).name

            try:
                raw = z.read(path).decode('utf-8', errors='replace')

                if base == 'requirements.txt':
                    count = len([
                        line for line in raw.splitlines()
                        if line.strip()
                        and not line.lstrip().startswith('#')
                    ])

                    findings.append(finding(
                        'Python dependency manifest inspected',
                        'info',
                        f'{count} dependency entries',
                        file_path=path,
                        confidence='high',
                        evidence=f'Manifest: {path}',
                        scanner='Project Readiness Analyzer',
                    ))

                elif base == 'package.json':
                    obj = json.loads(raw)

                    count = (
                        len(obj.get('dependencies', {}))
                        + len(obj.get('devDependencies', {}))
                    )

                    findings.append(finding(
                        'Node manifest inspected',
                        'info',
                        f'{count} dependencies',
                        file_path=path,
                        confidence='high',
                        evidence=f'Manifest: {path}',
                        scanner='Project Readiness Analyzer',
                    ))

                    if not obj.get('scripts'):
                        findings.append(finding(
                            'No npm scripts defined',
                            'low',
                            'The package manifest does not define npm scripts.',
                            'Review whether build, test and start scripts are required.',
                            file_path=path,
                            confidence='medium',
                            evidence='No scripts property found in package.json',
                            scanner='Project Readiness Analyzer',
                        ))

            except Exception:
                findings.append(finding(
                    'Manifest parse failed',
                    'medium',
                    'The dependency manifest could not be parsed.',
                    'Check the manifest syntax and validate it with its package manager.',
                    file_path=path,
                    confidence='high',
                    evidence=f'File: {path}',
                    scanner='Project Readiness Analyzer',
                ))

        # Analyze individual source and configuration files.
        inventory_by_path = {
            item['path']: item for item in inventory
        }

        for path in names:
            ext = PurePosixPath(path).suffix.lower()
            entry = inventory_by_path[path]

            is_source = ext in LANG
            is_config = ext in CONFIG_EXTENSIONS

            if not is_source and not is_config:
                continue

            if entry['size_bytes'] > MAX_SOURCE_FILE_BYTES:
                entry['analysis_status'] = 'skipped_size_limit'
                source_files_skipped += 1
                continue

            try:
                raw = z.read(path)

                # Avoid interpreting binary content as source code.
                if b'\x00' in raw[:8192]:
                    entry['analysis_status'] = 'skipped_binary'
                    source_files_skipped += 1
                    continue

                text = raw.decode('utf-8', errors='replace')

                file_findings = []

                if is_source:
                    report = scan_code(path, raw)

                    # Exclude success-only messages from the vulnerability list.
                    file_findings.extend([
                        item for item in report.get('findings', [])
                        if item.get('title') not in {
                            'Python syntax valid',
                            'No basic static issues detected',
                        }
                    ])

                    entry['analysis_status'] = 'scanned'
                    source_files_scanned += 1

                elif is_config:
                    for secret in detect_secrets_detailed(text):
                        file_findings.append(finding(
                            'Possible hardcoded secret',
                            'critical',
                            f'{secret["type"]} detected in configuration file.',
                            'Remove the credential, rotate it, and use a secure secret manager.',
                            file_path=path,
                            line=secret['line'],
                            column=secret['column'],
                            cwe='CWE-798',
                            confidence=secret['confidence'],
                            evidence=secret['evidence'],
                            impact='An exposed credential may allow unauthorized access.',
                            root_cause='A sensitive credential appears directly in a configuration file.',
                            scanner='Project Readiness Analyzer',
                        ))

                    entry['analysis_status'] = 'scanned'

                # Add findings from this exact file to the project report.
                findings.extend(file_findings)
                entry['findings_count'] = len(file_findings)
                total_file_findings += len(file_findings)

            except Exception as error:
                entry['analysis_status'] = 'scan_error'
                source_files_skipped += 1

                findings.append(finding(
                    'File analysis failed',
                    'medium',
                    'The scanner could not analyze this file.',
                    'Check file encoding and format, then scan it again.',
                    file_path=path,
                    confidence='high',
                    evidence=type(error).__name__,
                    scanner='Project Readiness Analyzer',
                ))

        # Dockerfile checks with file identification.
        for entry in inventory:
            if entry['file_name'].lower() != 'dockerfile':
                continue

            path = entry['path']

            try:
                content = z.read(path).decode('utf-8', errors='replace')

                if not re.search(r'(?im)^\s*USER\s+', content):
                    findings.append(finding(
                        'Dockerfile has no explicit USER',
                        'medium',
                        'No USER instruction was detected. The image may run as root depending on its base image and runtime.',
                        'Create a dedicated non-root user and add a USER instruction.',
                        file_path=path,
                        confidence='medium',
                        evidence='No Dockerfile USER instruction found',
                        impact='Running containers as root can increase the impact of a container compromise.',
                        root_cause='The Dockerfile does not explicitly select a non-root runtime user.',
                        scanner='Project Readiness Analyzer',
                    ))

            except Exception:
                pass

        if not manifests:
            findings.append(finding(
                'Dependency manifest not found',
                'medium',
                'No supported dependency manifest was found.',
                'Add the appropriate dependency manifest for the project.',
                confidence='high',
                scanner='Project Readiness Analyzer',
            ))

        if not starts:
            findings.append(finding(
                'Startup entry point not obvious',
                'medium',
                'No recognized startup file was found.',
                'Document the application entry point or add a recognized startup file.',
                confidence='low',
                scanner='Project Readiness Analyzer',
            ))

        if not any(
            PurePosixPath(path).name.lower() in ('readme', 'readme.md')
            for path in names
        ):
            findings.append(finding(
                'README missing',
                'low',
                'No README or README.md file was found.',
                'Add project documentation describing setup, usage and deployment.',
                confidence='high',
                scanner='Project Readiness Analyzer',
            ))

        findings.append(finding(
            'Project inventory complete',
            'info',
            f'{len(files)} files inventoried; {source_files_scanned} source files scanned; {source_files_skipped} files skipped; {total_file_findings} file-level findings.',
            confidence='high',
            scanner='Project Readiness Analyzer',
        ))

        return {
            'tool': 'Project Readiness Analyzer',
            'target': name,
            'summary': risk_summary(findings),
            'metadata': {
                'archive_size_bytes': len(data),
                'file_count': len(files),
                'expanded_size_bytes': total,
                'languages': languages,
                'manifests': manifests,
                'startup_candidates': starts,
                'source_files_scanned': source_files_scanned,
                'source_files_skipped': source_files_skipped,
                'file_level_findings': total_file_findings,
                'file_type_counts': {
                    language: count
                    for language, count in languages.items()
                },
            },
            'files': inventory,
            'findings': findings,
            'limitations': [
                'Static pattern analysis only; application code is not executed.',
                'Dependency versions are inventoried but not checked against a vulnerability database.',
                'Unsupported file types are inventoried but not deeply analyzed.',
                'Heuristic findings require manual verification.',
                'Files larger than 2 MB are skipped by the source-file analyzer.',
            ],
        }

    finally:
        z.close()
