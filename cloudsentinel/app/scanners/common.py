import re

def finding(title, severity='info', detail='', recommendation=''):
    return {'title':title,'severity':severity,'detail':detail,'recommendation':recommendation}

def risk_summary(findings):
    order={'critical':4,'high':3,'medium':2,'low':1,'info':0}; score=max((order.get(x.get('severity','info'),0) for x in findings),default=0)
    return {'risk':{4:'Critical',3:'High',2:'Medium',1:'Low',0:'Informational'}[score],'finding_count':len(findings)}

def detect_secrets(text):
    patterns=[('Private key',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),('AWS access key',r'\\bAKIA[0-9A-Z]{16}\\b'),('Credential assignment',r'''(?i)(password|passwd|api[_-]?key|secret|token)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]''')]
    return [f'{label} near character {m.start()}' for label,pat in patterns for m in re.finditer(pat,text)]
