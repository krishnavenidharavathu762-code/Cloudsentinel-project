# CloudSentinel

Cloud security analysis MVP built with FastAPI and a browser dashboard.

## Run

```bash
cd cloudsentinel
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. API docs: http://127.0.0.1:8000/docs.

Includes ZIP/project inventory, source-code checks, dependency manifest inspection, URL and webpage inspection, optional Trivy image scanning, Terraform checks, secret detection, and startup-readiness heuristics. Uploaded code is inspected as data and never executed. This is an MVP, not a guarantee of malware-free files or sites.
