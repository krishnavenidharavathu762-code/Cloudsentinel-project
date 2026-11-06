# CloudSentinel basic dark dashboard

This package refreshes the current dashboard without changing the existing FastAPI backend, API endpoints, scanners, or report storage.

## Package contents
- `app/static/index.html`
- `app/static/styles.css`
- `app/static/app.js`

## Deploy on your Azure VM

Transfer this ZIP to `/home/kittu/` on your VM, then run:

```bash
cd /home/kittu/scanmaster-agent/cloudsentinel

# Back up the current frontend
cp -a app/static "app/static.backup-$(date +%Y%m%d-%H%M%S)"

# Extract replacement frontend files
unzip -o /home/kittu/cloudsentinel-basic-dark.zip -d .
```

Restart Uvicorn. If it is running in the foreground, press Ctrl+C, then:

```bash
cd /home/kittu/scanmaster-agent/cloudsentinel
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

For a temporary test from the public internet, you would need to bind to `0.0.0.0`, but do not expose port 8000 broadly. Restrict the Azure NSG rule to your own public IP. Prefer Nginx + HTTPS for normal use, with Uvicorn bound to `127.0.0.1`.

Open the dashboard at `http://YOUR_VM_PUBLIC_IP:8000/` only while using your restricted test setup. Hard-refresh with Ctrl+Shift+R if the browser shows cached CSS/JS.

## Existing API paths preserved
- `GET /`
- `GET /api/health`
- `GET /api/scans`
- `POST /api/scan/zip`
- `POST /api/scan/project`
- `POST /api/scan/code`
- `POST /api/scan/terraform`
- `POST /api/scan/url`
- `POST /api/scan/image`

The dashboard calls these same-origin endpoints; no CORS or frontend build step is needed.

## Security
The API shown in the project currently has no authentication. Do not expose it to the public internet without adding authentication and hardening the URL scanner against SSRF/private-network access, including Azure instance metadata.
