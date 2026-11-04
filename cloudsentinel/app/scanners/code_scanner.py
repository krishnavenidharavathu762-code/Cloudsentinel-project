import ast,re
from pathlib import PurePath
from app.scanners.common import finding,risk_summary,detect_secrets
LANG={'.py':'Python','.java':'Java','.js':'JavaScript','.ts':'TypeScript','.go':'Go','.rb':'Ruby','.php':'PHP','.cs':'C#','.cpp':'C++','.c':'C','.sh':'Shell'}
def scan_code(name,data):
 text=data.decode('utf-8',errors='replace');ext=PurePath(name).suffix.lower();lang=LANG.get(ext,'Unknown');findings=[];funcs=classes=0;imports=[]
 if lang=='Python':
  try:
   tree=ast.parse(text);funcs=sum(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) for n in ast.walk(tree));classes=sum(isinstance(n,ast.ClassDef) for n in ast.walk(tree));imports=sorted({n.name.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.Import)}|{n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n,ast.ImportFrom) and n.module});findings.append(finding('Python syntax valid','info',f'{funcs} functions, {classes} classes'))
  except SyntaxError as e:findings.append(finding('Python syntax error','high',f'Line {e.lineno}: {e.msg}'))
 elif lang=='Unknown':findings.append(finding('Language not recognized','low',ext or 'No extension'))
 if lang in ('Java','JavaScript','TypeScript','Go','C#','C++','C') and text.count('{')!=text.count('}'):findings.append(finding('Possible unmatched braces','medium'))
 for hit in detect_secrets(text):findings.append(finding('Possible hardcoded secret','critical',hit,'Rotate exposed credentials'))
 for pat,label in [(r'\\beval\\s*\\(','Use of eval'),(r'\\bexec\\s*\\(','Use of exec'),(r'(?i)verify\\s*=\\s*False','TLS verification disabled')]:
  if re.search(pat,text):findings.append(finding(label,'high','Potentially unsafe code pattern'))
 if not findings:findings.append(finding('No basic static issues detected','info','Not a full SAST or malware scan'))
 return {'tool':'Source Code Analyzer','target':name,'summary':risk_summary(findings),'metadata':{'language':lang,'size_bytes':len(data),'lines':len(text.splitlines()),'functions':funcs,'classes':classes,'imports':imports},'findings':findings}
