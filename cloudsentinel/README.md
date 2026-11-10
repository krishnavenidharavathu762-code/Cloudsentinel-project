# CloudSentinel
### Multi-Engine Application and Infrastructure Security Scanning Platform

CloudSentinel is a web-based security scanning platform built with **Python and FastAPI**. It provides multiple security analysis capabilities for source code, software projects, Terraform configurations, container images, URLs, ZIP archives, and exposed secrets.

The platform integrates external security tools with custom-built scanning modules and provides a centralized dashboard for viewing security findings and scan reports.

---

## 1. Project Overview

### Objectives

- Identify security vulnerabilities in source code.
- Detect exposed credentials and secrets.
- Analyze Terraform and Infrastructure-as-Code configurations.
- Scan container images for vulnerabilities, misconfigurations, and secrets.
- Analyze projects for security and configuration weaknesses.
- Perform URL security checks.
- Integrate SonarQube for code quality and security analysis.
- Support individual user accounts and GitHub repository connections.
- Store and display scan reports through a centralized dashboard.

### Technology Stack

| Category | Technology |
|---|---|
| Backend | Python, FastAPI |
| ASGI server | Uvicorn |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| Validation | Pydantic, email-validator |
| HTTP requests | HTTPX |
| HTML parsing | BeautifulSoup4 |
| Authentication | Session-based authentication |
| GitHub integration | GitHub OAuth |
| Password/security utilities | Python security and cryptographic utilities |
| Container platform | Docker |
| Reverse proxy | Nginx |
| HTTPS | Let's Encrypt, Certbot |
| Cloud hosting | Microsoft Azure Ubuntu VM |
| Environment configuration | python-dotenv |

### Python Dependencies

The project uses the following dependencies from `requirements.txt`:

```text
fastapi>=0.115,<1
uvicorn[standard]>=0.30,<1
python-multipart>=0.0.9
httpx>=0.27,<1
beautifulsoup4>=4.12,<5
pydantic>=2.7,<3
email-validator>=2.3,<3
```

---

## 2. Security Scanning Engines

CloudSentinel contains 12 scanning capabilities, divided into six external security-tool integrations and six built-in scanning modules.

### A. External Security Tools

| No. | Tool | Purpose |
|---|---|---|
| 1 | Bandit | Python source-code security analysis |
| 2 | Semgrep | Static application security testing |
| 3 | Gitleaks | Exposed credentials and secret detection |
| 4 | Checkov | Infrastructure-as-Code security scanning |
| 5 | Trivy | Container image vulnerability and configuration scanning |
| 6 | SonarQube | Code quality, security issues, and security hotspots |

#### 1. Bandit

Bandit identifies common security issues in Python source code.

- Detects insecure Python coding patterns.
- Analyzes Python files.
- Produces structured JSON findings.
- Integrated through `app/scanners/advanced_scanners.py`.

Installed version: `1.9.4`

Installation:

```bash
pip install bandit==1.9.4
```

In this deployment, Bandit is installed inside the project's Python virtual environment:

```bash
.venv/bin/bandit --version
```

#### 2. Semgrep

Semgrep performs static code analysis using security rules.

- Scans source-code files.
- Identifies insecure coding patterns.
- Returns structured JSON findings.
- Integrated through `advanced_scanners.py`.

Installed version: `1.183.0`

This deployment uses a separate Python virtual environment:

```bash
python3 -m venv /opt/cloudsentinel-semgrep

/opt/cloudsentinel-semgrep/bin/pip install semgrep==1.183.0
```

Scanner executable:

```text
/opt/cloudsentinel-semgrep/bin/semgrep
```

#### 3. Gitleaks

Gitleaks detects exposed secrets and credentials.

- Searches for possible API keys, tokens, and passwords.
- Supports repository scanning.
- Produces JSON reports.
- CloudSentinel avoids reproducing detected secret values in findings.

Installed version: `8.30.1`

Executable:

```text
/usr/local/bin/gitleaks
```

Version check:

```bash
gitleaks version
```

#### 4. Checkov

Checkov analyzes Terraform configurations for infrastructure security policy violations.

- Scans `.tf` and `.tfvars` files.
- Identifies insecure infrastructure configurations.
- Converts failed policy checks into CloudSentinel findings.
- Integrated through `checkov_scanner.py`.

Installed version: `3.4.3`

Installation:

```bash
pip install checkov==3.4.3
```

In this deployment, it is installed in the project virtual environment:

```bash
.venv/bin/checkov --version
```

#### 5. Trivy

Trivy is used for container image security scanning.

It identifies:

- Known software vulnerabilities.
- Container image misconfigurations.
- Potential exposed secrets.

Installed version: `0.76.1`

Executable:

```text
/usr/bin/trivy
```

Version check:

```bash
trivy --version
```

Integrated through `app/scanners/image_scanner.py`.

#### 6. SonarQube

SonarQube provides source-code quality and security analysis.

CloudSentinel integrates with SonarQube using:

- SonarQube Community Docker image.
- SonarScanner CLI Docker image.
- SonarQube Web API.
- Security issue retrieval.
- Security hotspot retrieval.

Deployment details:

| Component | Configuration |
|---|---|
| SonarQube image | `sonarqube:community` |
| Scanner image | `sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1` |
| Container | `cloudsentinel-sonarqube` |
| Internal port | 9000 |
| Host binding | 127.0.0.1:9000 |
| Docker network | `cloudsentinel-security` |

SonarQube is not exposed directly to the public internet.

The application uses the following configuration:

```python
SONAR_URL = "http://127.0.0.1:9000"
SCANNER_URL = "http://cloudsentinel-sonarqube:9000"
SCANNER_IMAGE = "sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1"
DOCKER_NETWORK = "cloudsentinel-security"
```

The SonarQube token is stored separately:

```text
/etc/cloudsentinel/sonarqube-token
```

Do not commit the token to GitHub.

### B. Built-in CloudSentinel Scanners

These are application modules developed within CloudSentinel, not separate third-party executables.

| No. | Module | Purpose |
|---|---|---|
| 7 | Source Code Analyzer | Built-in source-code checks |
| 8 | Project Readiness Analyzer | Project configuration and security readiness |
| 9 | Terraform Analyzer | Built-in Terraform pattern checks |
| 10 | URL Security Scanner | URL and network-related security checks |
| 11 | ZIP File Scanner | Uploaded ZIP inspection and scanning |
| 12 | Secret Detection Engine | Built-in secret detection utilities |

Implementation files:

```text
app/scanners/code_scanner.py
app/scanners/project_scanner.py
app/scanners/terraform_scanner.py
app/scanners/url_scanner.py
app/scanners/zip_scanner.py
app/scanners/common.py
```

The built-in Terraform analyzer provides pattern-based checks. Checkov provides deeper policy-based Terraform analysis.

The secret detection utilities are implemented in `common.py` and are also used by scanning workflows.

---

## 3. Project Architecture

```text
CloudSentinel/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── auth_db.py
│   ├── auth_routes.py
│   ├── auth_security.py
│   │
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── advanced_scanners.py
│   │   ├── checkov_scanner.py
│   │   ├── code_scanner.py
│   │   ├── common.py
│   │   ├── image_scanner.py
│   │   ├── project_scanner.py
│   │   ├── sonarqube_scanner.py
│   │   ├── terraform_scanner.py
│   │   ├── url_scanner.py
│   │   └── zip_scanner.py
│   │
│   └── static/
│       ├── index.html
│       ├── app.js
│       └── styles.css
│
├── data/
│   ├── cloudsentinel.db
│   └── reports/
│
├── requirements.txt
├── README.md
├── README-DEPLOY.md
└── .gitignore
```

### Important files

| File | Responsibility |
|---|---|
| `main.py` | FastAPI application and scanning API endpoints |
| `auth_routes.py` | Registration, login, email verification, and GitHub OAuth routes |
| `auth_db.py` | SQLite database operations |
| `auth_security.py` | Authentication and email security utilities |
| `advanced_scanners.py` | Bandit, Semgrep, and Gitleaks integration |
| `checkov_scanner.py` | Checkov integration |
| `image_scanner.py` | Trivy integration |
| `sonarqube_scanner.py` | SonarQube integration |
| `common.py` | Shared finding and secret-detection utilities |
| `static/app.js` | Frontend interactions |
| `static/index.html` | Dashboard and authentication interface |
| `static/styles.css` | Frontend styling |

---

## 4. Application Workflow

### General scanning workflow

1. User registers or logs in.
2. User selects a scanning feature.
3. User submits the required file, project, image, or URL.
4. FastAPI receives the request.
5. The relevant scanner module is selected.
6. External tools or built-in checks perform the analysis.
7. Findings are normalized into CloudSentinel report structures.
8. Reports are saved in the application data directory.
9. The dashboard displays the results.

### GitHub repository scanning workflow

1. User connects their GitHub account through OAuth.
2. GitHub authorizes the requested permissions.
3. CloudSentinel stores the user's encrypted access token.
4. The application retrieves repositories using that user's connection.
5. The selected repository is scanned.
6. Repository scan findings are returned to the dashboard.

Each application member's GitHub connection is associated with their own user ID. Repository access should always use the authenticated member's connection rather than another member's token.

---

## 5. Authentication and Account Security

CloudSentinel includes:

- User registration.
- Email-format validation.
- Case-insensitive duplicate-email protection.
- Email verification.
- Login authentication.
- Password hashing.
- Session-based authentication.
- Password reset support.
- GitHub OAuth integration.

### Email verification

New registrations require email verification before login.

The email verification workflow:

1. Validate the submitted email format.
2. Check whether the email already exists.
3. Create an unverified account.
4. Generate a verification token.
5. Send the verification email through SMTP.
6. Verify the account when the user opens the verification link.

The `email-validator` package validates email format. Actual ownership is checked through the verification email.

### GitHub OAuth

GitHub integration supports:

- Connecting a user's GitHub account.
- Retrieving that user's repositories.
- Scanning selected repositories.
- Keeping GitHub connections associated with individual CloudSentinel users.

OAuth credentials must be configured using environment variables.

---

## 6. Database and Reports

CloudSentinel uses SQLite.

Database:

```text
data/cloudsentinel.db
```

The database supports application user and GitHub connection information, along with authentication-related records.

The application stores scan reports under:

```text
data/reports/
```

Reports are generated in JSON format.

Do not commit production databases, private reports, access tokens, or user-uploaded files to a public repository.

---

## 7. Environment Configuration

CloudSentinel uses environment variables stored in `.env`.

Typical configuration categories include:

| Variable | Purpose |
|---|---|
| `SESSION_SECRET` | Session signing secret |
| `COOKIE_SECURE` | Secure cookie configuration |
| `APP_BASE_URL` | Public application URL |
| `SMTP_HOST` | SMTP server hostname |
| `SMTP_PORT` | SMTP server port |
| `SMTP_USERNAME` | SMTP account username |
| `SMTP_APP_PASSWORD` | SMTP application password |
| `MAIL_FROM` | Sender email address |
| GitHub OAuth client configuration | GitHub authentication |
| SonarQube token file | SonarQube authentication |

Use the exact variable names expected by the application code when configuring the environment.

Example:

```bash
cp .env.example .env
nano .env
```

If an `.env.example` file has not been created, prepare one using the variable names in the application source code. Never copy production secret values into it.

Protect the production environment file:

```bash
chmod 600 .env
```

---

## 8. Local Installation

### Requirements

- Linux, macOS, or Windows with a suitable Python environment.
- Python 3.12 recommended for reproducing this deployment.
- Git.
- Docker for SonarQube and its scanner container.
- Required external scanner executables.

### Step 1: Clone the repository

```bash
git clone https://github.com/krishnavenidharavathu762-code/Cloudsentinel-project.git

cd Cloudsentinel-project/cloudsentinel
```

Adjust the working directory if the repository root already contains the application files.

### Step 2: Create a virtual environment

```bash
python3 -m venv .venv

source .venv/bin/activate
```

### Step 3: Install Python dependencies

```bash
pip install --upgrade pip

pip install -r requirements.txt
```

### Step 4: Install Python security scanners

```bash
pip install bandit==1.9.4
pip install checkov==3.4.3
```

### Step 5: Install Semgrep separately

```bash
python3 -m venv /opt/cloudsentinel-semgrep

/opt/cloudsentinel-semgrep/bin/pip install semgrep==1.183.0
```

The Semgrep executable must be available at the path configured in `advanced_scanners.py`.

### Step 6: Install Gitleaks and Trivy

Install the appropriate Linux binaries using their official release and installation instructions.

- Gitleaks: https://github.com/gitleaks/gitleaks
- Trivy: https://trivy.dev/

For this deployment, the expected executable locations are:

```text
/usr/local/bin/gitleaks
/usr/bin/trivy
```

Verify:

```bash
gitleaks version
trivy --version
```

### Step 7: Configure SonarQube

Docker must be installed and running.

The deployment uses:

```text
sonarqube:community
sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1
```

Create the Docker network if it does not already exist:

```bash
docker network create cloudsentinel-security
```

Configure SonarQube using the application's expected Docker network, host binding, and token-file settings.

The SonarQube service should remain private and accessible to CloudSentinel locally.

### Step 8: Configure environment variables

Create and configure `.env` with the required session, email, application URL, and GitHub OAuth settings.

### Step 9: Start the application

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

---

## 9. Azure VM Deployment

CloudSentinel is deployed on an Ubuntu virtual machine hosted in Microsoft Azure.

### Deployment environment

| Component | Deployment |
|---|---|
| Cloud provider | Microsoft Azure |
| Operating system | Ubuntu Linux |
| Backend | FastAPI |
| Application server | Uvicorn |
| Reverse proxy | Nginx |
| HTTPS | Let's Encrypt |
| Container runtime | Docker |
| Database | SQLite |

### Application directory

```text
/home/kittu/scanmaster-agent/cloudsentinel
```

### Start FastAPI

```bash
cd /home/kittu/scanmaster-agent/cloudsentinel

nohup .venv/bin/uvicorn app.main:app \
  --host 127.0.0.1 \
  --port 8000 \
  > /tmp/cloudsentinel.log 2>&1 &
```

### Verify application health

```bash
curl http://127.0.0.1:8000/api/health
```

Expected response:

```json
{
  "status": "ok",
  "service": "CloudSentinel",
  "version": "1.0.0"
}
```

### Nginx reverse proxy

Nginx receives external HTTP/HTTPS requests and forwards application traffic to:

```text
http://127.0.0.1:8000
```

Uvicorn listens only on localhost rather than being directly exposed to the internet.

### HTTPS configuration

Let's Encrypt provides the HTTPS certificate.

The deployed certificate files are:

```text
/etc/letsencrypt/live/20.58.164.13.nip.io/fullchain.pem
/etc/letsencrypt/live/20.58.164.13.nip.io/privkey.pem
```

Certbot is configured for automatic certificate renewal.

---

## 10. Accessing CloudSentinel

### Production dashboard

https://20.58.164.13.nip.io

### API documentation

https://20.58.164.13.nip.io/docs

### Health endpoint

```bash
curl https://20.58.164.13.nip.io/api/health
```

---

## 11. API Endpoints

The FastAPI application exposes API routes for authentication and security scanning.

Confirmed scanning routes include:

| Endpoint | Purpose |
|---|---|
| `POST /api/scan/checkov` | Terraform Checkov scan |
| `POST /api/scan/github/gitleaks` | GitHub repository Gitleaks scan |
| `POST /api/scan/sonarqube` | SonarQube project scan |
| `POST /api/scan/...` | Other scanner routes defined in `app/main.py` |
| `GET /api/health` | Application health check |

For the complete current API route list, use:

```text
https://20.58.164.13.nip.io/docs
```

---

## 12. Verification and Testing

Verify external scanner installations:

```bash
.venv/bin/bandit --version

/opt/cloudsentinel-semgrep/bin/semgrep --version

/usr/local/bin/gitleaks version

.venv/bin/checkov --version

trivy --version

docker ps
```

Verify application health:

```bash
curl http://127.0.0.1:8000/api/health
```

Verify HTTPS:

```bash
curl -I https://20.58.164.13.nip.io
```

Verify Nginx:

```bash
sudo systemctl status nginx
```

Verify Docker:

```bash
docker ps -a
```

---

## 13. Troubleshooting

### Application is not responding

Check the application logs:

```bash
tail -n 100 /tmp/cloudsentinel.log
```

Check whether Uvicorn is running:

```bash
pgrep -af uvicorn
```

### Scanner executable not found

Verify the scanner's configured path.

For example:

```bash
ls -l .venv/bin/bandit

ls -l .venv/bin/checkov

ls -l /opt/cloudsentinel-semgrep/bin/semgrep

ls -l /usr/local/bin/gitleaks

ls -l /usr/bin/trivy
```

The external scanner paths must match those expected by the application code.

### SonarQube is unavailable

Check its container:

```bash
docker ps -a
```

Inspect logs:

```bash
docker logs --tail 100 cloudsentinel-sonarqube
```

Check its local port:

```bash
curl http://127.0.0.1:9000
```

### Email verification problems

Check the SMTP configuration in `.env` without sharing passwords or tokens.

Inspect the application logs for SMTP errors.

### Nginx or HTTPS problems

```bash
sudo nginx -t

sudo systemctl status nginx

sudo certbot certificates
```

---

## 14. Security Best Practices

- Never commit `.env` files.
- Never expose SMTP passwords or OAuth secrets.
- Keep GitHub access tokens encrypted.
- Use individual GitHub connections for each member.
- Keep the SonarQube service private.
- Run Uvicorn behind Nginx.
- Use HTTPS for public application access.
- Restrict Azure inbound network rules.
- Keep scanner databases and tools updated.
- Back up the SQLite database securely.
- Avoid storing exposed secret values in scan reports.
- Validate uploaded files and enforce suitable size limits.
- Review authentication and authorization for all protected endpoints.

---

## 15. Future Enhancements

Potential future improvements include:

- Automated background scanning.
- Scheduled repository scans.
- PDF and downloadable security reports.
- Role-based access control.
- More detailed vulnerability prioritization.
- CI/CD integration.
- Scan history and trend analysis.
- Notifications for critical vulnerabilities.
- Multi-user administrative reporting.

---

## 16. Project Repository

GitHub:

https://github.com/krishnavenidharavathu762-code/Cloudsentinel-project

---

## 17. Conclusion

CloudSentinel combines six external security tools with six built-in scanning capabilities to provide centralized security analysis for source code, infrastructure, container images, URLs, projects, and secrets.

Built using FastAPI, Python, SQLite, Docker, and a modern web interface, the platform is deployed on an Azure Ubuntu virtual machine with Nginx reverse proxy and HTTPS.

The project demonstrates the integration of multiple security engines into a centralized web-based security scanning platform.
