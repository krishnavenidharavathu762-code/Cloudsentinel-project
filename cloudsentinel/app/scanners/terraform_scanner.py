import re
from app.scanners.common import finding,risk_summary,detect_secrets
def scan_terraform(name,text):
 findings=[]
 checks=[(r'0\\.0\\.0\\.0/0','Public IPv4 range','high','Restrict CIDR'),(r'::/0','Public IPv6 range','high','Restrict IPv6 CIDR'),(r'(?i)acl\\s*=\\s*"public-read"','Public object ACL','critical','Avoid public ACL'),(r'(?i)encrypted\\s*=\\s*false','Encryption disabled','high','Enable encryption'),(r'(?i)force_destroy\\s*=\\s*true','Destructive force_destroy','medium','Review intent'),(r'(?i)iam:\\*|"\\*"','Wildcard IAM permission','high','Apply least privilege')]
 for pat,title,sev,rec in checks:
  if re.search(pat,text):findings.append(finding(title,sev,'Potentially insecure Terraform configuration',rec))
 for hit in detect_secrets(text):findings.append(finding('Possible hardcoded secret','critical',hit,'Rotate credential'))
 if text.count('{')!=text.count('}'):findings.append(finding('Unbalanced braces','high'))
 if not findings:findings.append(finding('No built-in Terraform pattern issues detected','info','Use Checkov/tfsec for deeper policy checks'))
 return {'tool':'Terraform Security Scanner','target':name,'summary':risk_summary(findings),'metadata':{'size_bytes':len(text.encode()),'lines':len(text.splitlines())},'findings':findings}
