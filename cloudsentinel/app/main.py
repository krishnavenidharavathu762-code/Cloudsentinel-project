from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
from datetime import datetime, timezone
import json, uuid
from app.scanners.zip_scanner import scan_zip
from app.scanners.code_scanner import scan_code
from app.scanners.project_scanner import scan_project_zip
from app.scanners.url_scanner import scan_url
from app.scanners.image_scanner import scan_image
from app.scanners.terraform_scanner import scan_terraform

BASE=Path(__file__).resolve().parent.parent
REPORTS=BASE/"data"/"reports"
REPORTS.mkdir(parents=True,exist_ok=True)
app=FastAPI(title="CloudSentinel",version="1.0.0")
app.mount("/static",StaticFiles(directory=str(BASE/"app"/"static")),name="static")
class URLRequest(BaseModel): url:str
class ImageRequest(BaseModel): image:str

def persist(report):
    report["scan_id"]=str(uuid.uuid4())
    report["created_at"]=datetime.now(timezone.utc).isoformat()
    (REPORTS/f'{report["scan_id"]}.json').write_text(json.dumps(report,indent=2),encoding="utf-8")
    return report

async def upload(file,limit=25*1024*1024):
    name=Path(file.filename or "upload").name
    data=await file.read(limit+1)
    if not data: raise HTTPException(400,"Empty file")
    if len(data)>limit: raise HTTPException(413,"Upload exceeds size limit")
    return name,data

@app.get("/",response_class=HTMLResponse)
def home(): return (BASE/"app"/"static"/"index.html").read_text(encoding="utf-8")
@app.get("/api/health")
def health(): return {"status":"ok","service":"CloudSentinel","version":"1.0.0"}
@app.get("/api/scans")
def scans():
    out=[]
    for p in sorted(REPORTS.glob("*.json"),key=lambda x:x.stat().st_mtime,reverse=True)[:30]:
        try: out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception: pass
    return {"scans":out}
@app.post("/api/scan/zip")
async def zip_scan(file:UploadFile=File(...)):
    name,data=await upload(file)
    if not name.lower().endswith(".zip"): raise HTTPException(400,"Upload a ZIP file")
    try: return persist(scan_zip(name,data))
    except ValueError as e: raise HTTPException(400,str(e))
@app.post("/api/scan/project")
async def project_scan(file:UploadFile=File(...)):
    name,data=await upload(file)
    if not name.lower().endswith(".zip"): raise HTTPException(400,"Project scan expects ZIP")
    try: return persist(scan_project_zip(name,data))
    except ValueError as e: raise HTTPException(400,str(e))
@app.post("/api/scan/code")
async def code_scan(file:UploadFile=File(...)):
    name,data=await upload(file,2*1024*1024)
    return persist(scan_code(name,data))
@app.post("/api/scan/terraform")
async def tf_scan(file:UploadFile=File(...)):
    name,data=await upload(file)
    if not name.endswith((".tf",".tfvars")): raise HTTPException(400,"Upload .tf or .tfvars")
    return persist(scan_terraform(name,data.decode("utf-8",errors="replace")))
@app.post("/api/scan/url")
async def web_scan(body:URLRequest):
    try: return persist(await scan_url(body.url))
    except ValueError as e: raise HTTPException(400,str(e))
@app.post("/api/scan/image")
def image_scan(body:ImageRequest):
    try: return persist(scan_image(body.image))
    except ValueError as e: raise HTTPException(400,str(e))
