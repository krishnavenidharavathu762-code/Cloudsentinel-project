import shutil,subprocess,json,re
from app.scanners.common import finding,risk_summary
def scan_image(image):
 if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,250}',image):raise ValueError('Invalid image reference')
 trivy=shutil.which('trivy');findings=[]
 if not trivy:
  findings.append(finding('Trivy is not installed','medium','Image scan was not performed','Install Trivy'))
  return {'tool':'Container Image Scanner','target':image,'summary':risk_summary(findings),'metadata':{'available':False},'findings':findings}
 try:
  p=subprocess.run([trivy,'image','--format','json','--quiet',image],capture_output=True,text=True,timeout=300)
  if p.returncode not in (0,1):raise RuntimeError(p.stderr[-500:])
  data=json.loads(p.stdout or '{}');counts={k:0 for k in ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')}
  for result in data.get('Results',[]) or []:
   for v in result.get('Vulnerabilities',[]) or []:counts[v.get('Severity','UNKNOWN').upper()]+=1
  for sev,n in counts.items():
   if n:findings.append(finding(f'{sev} vulnerabilities: {n}',sev.lower() if sev!='UNKNOWN' else 'info'))
  if not findings:findings.append(finding('No vulnerabilities reported','info'))
  return {'tool':'Container Image Scanner','target':image,'summary':risk_summary(findings),'metadata':{'available':True,'counts':counts},'findings':findings}
 except subprocess.TimeoutExpired:raise ValueError('Trivy scan timed out')
