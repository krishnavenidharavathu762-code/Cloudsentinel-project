import re,json
from app.scanners.zip_scanner import inspect_zip
from app.scanners.common import finding,risk_summary,detect_secrets
from app.scanners.code_scanner import LANG
MANIFESTS={'requirements.txt':'Python pip','pyproject.toml':'Python project','Pipfile':'Pipenv','pom.xml':'Maven','build.gradle':'Gradle','package.json':'Node.js','go.mod':'Go modules','Gemfile':'Ruby Bundler','Cargo.toml':'Rust Cargo'}
STARTS=['main.py','app.py','manage.py','wsgi.py','asgi.py','pom.xml','build.gradle','package.json','main.go','Program.cs','Dockerfile']
def scan_project_zip(name,data):
 z,files,total,findings=inspect_zip(name,data);names=[f['path'] for f in files];manifests=[{'file':p,'type':MANIFESTS[p.rsplit('/',1)[-1]]} for p in names if p.rsplit('/',1)[-1] in MANIFESTS];starts=[p for p in names if p.rsplit('/',1)[-1] in STARTS];languages={}
 for p in names:
  ext='.'+p.rsplit('.',1)[-1].lower() if '.' in p.rsplit('/',1)[-1] else ''
  if ext in LANG:languages[LANG[ext]]=languages.get(LANG[ext],0)+1
 if not manifests:findings.append(finding('Dependency manifest not found','medium'))
 else:
  for m in manifests:
   try:
    raw=z.read(m['file']).decode('utf-8',errors='replace');base=m['file'].rsplit('/',1)[-1]
    if base=='requirements.txt':findings.append(finding('Python dependency manifest inspected','info',f'{len([x for x in raw.splitlines() if x.strip() and not x.lstrip().startswith("#")])} entries'))
    elif base=='package.json':
     obj=json.loads(raw);findings.append(finding('Node manifest inspected','info',f'{len(obj.get("dependencies",{}))+len(obj.get("devDependencies",{}))} dependencies'))
     if not obj.get('scripts'):findings.append(finding('No npm scripts defined','low'))
   except Exception as e:findings.append(finding('Manifest parse failed','medium',str(e)[:150]))
 if not starts:findings.append(finding('Startup entry point not obvious','medium'))
 if not any(p.endswith(('README.md','README')) for p in names):findings.append(finding('README missing','low'))
 secrets=0
 for p in names:
  if p.endswith(('.py','.java','.js','.ts','.json','.yml','.yaml','.tf','.sh','.env')):
   try:
    raw=z.read(p)
    if len(raw)<1000000:secrets+=len(detect_secrets(raw.decode('utf-8',errors='ignore')))
   except Exception:pass
 if secrets:findings.append(finding('Possible secrets in project','critical',f'{secrets} matches'))
 for df in [p for p in names if p.rsplit('/',1)[-1].lower()=='dockerfile']:
  content=z.read(df).decode('utf-8',errors='replace')
  if not re.search(r'(?im)^\\s*USER\\s+',content):findings.append(finding('Dockerfile has no explicit USER','medium',df))
 findings.append(finding('Project inventory complete','info',f'{len(files)} files; {len(manifests)} manifests; {len(starts)} startup candidates'))
 return {'tool':'Project Readiness Analyzer','target':name,'summary':risk_summary(findings),'metadata':{'archive_size_bytes':len(data),'file_count':len(files),'expanded_size_bytes':total,'languages':languages,'manifests':manifests,'startup_candidates':starts},'files':files,'findings':findings,'limitations':['Application code is not executed','Dependency resolution and integration tests are not performed','Startup issues are heuristic predictions']}
