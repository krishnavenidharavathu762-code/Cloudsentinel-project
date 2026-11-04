import socket,ipaddress,httpx
from urllib.parse import urlparse,urljoin
from bs4 import BeautifulSoup
from app.scanners.common import finding,risk_summary
async def scan_url(url):
 def validate(u):
  p=urlparse(u)
  if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:raise ValueError('Only absolute HTTP(S) URLs without embedded credentials are allowed')
  try:addrs=socket.getaddrinfo(p.hostname,p.port or (443 if p.scheme=='https' else 80),type=socket.SOCK_STREAM)
  except socket.gaierror:raise ValueError('Hostname could not be resolved')
  if any(not ipaddress.ip_address(a[4][0]).is_global for a in addrs):raise ValueError('Local, private and reserved hosts are blocked')
 validate(url);current=url
 async with httpx.AsyncClient(follow_redirects=False,timeout=12,verify=True,headers={'User-Agent':'CloudSentinel/1.0'}) as client:
  for _ in range(6):
   validate(current);response=await client.get(current)
   if response.status_code in (301,302,303,307,308) and response.headers.get('location'):current=urljoin(current,response.headers['location']);continue
   break
  else:raise ValueError('Too many redirects')
 findings=[];headers=response.headers
 if urlparse(str(response.url)).scheme!='https':findings.append(finding('Website uses HTTP','medium'))
 for h in ('content-security-policy','strict-transport-security','x-content-type-options','x-frame-options'):
  if h not in headers:findings.append(finding(f'Missing security header: {h}','low'))
 if response.status_code>=400:findings.append(finding('HTTP error response','medium',str(response.status_code)))
 links=[];scripts=[];popup=[];ctype=headers.get('content-type','')
 if 'html' in ctype:
  html=response.text[:2000000];soup=BeautifulSoup(html,'html.parser');links=[urljoin(str(response.url),a['href']) for a in soup.find_all('a',href=True)][:300];scripts=[urljoin(str(response.url),s['src']) for s in soup.find_all('script',src=True)][:100];lower=html.lower();popup=[x for x in ('window.open(','beforeunload','notification.requestpermission','popunder') if x in lower]
  if popup:findings.append(finding('Popup script indicators','medium',', '.join(popup)))
 if not findings:findings.append(finding('No basic HTTP security issues detected','info','Not a malware-free guarantee'))
 return {'tool':'URL & Webpage Security Scanner','target':url,'summary':risk_summary(findings),'metadata':{'final_url':str(response.url),'status_code':response.status_code,'content_type':ctype,'redirected':str(response.url)!=url,'link_count':len(links),'script_count':len(scripts),'popup_indicators':popup,'links':links[:100],'scripts':scripts[:50]},'findings':findings,'limitations':['JavaScript was not executed','Downloads were not opened','No threat intelligence feed is queried']}
