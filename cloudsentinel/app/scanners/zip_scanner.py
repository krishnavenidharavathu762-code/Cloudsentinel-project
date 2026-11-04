from zipfile import ZipFile, BadZipFile
from io import BytesIO
from pathlib import PurePosixPath
from app.scanners.common import finding,risk_summary
MAX_FILES=5000; MAX_EXPANDED=100*1024*1024

def inspect_zip(name,data):
    try:z=ZipFile(BytesIO(data))
    except BadZipFile:raise ValueError('Invalid or corrupted ZIP archive')
    infos=z.infolist()
    if len(infos)>MAX_FILES:raise ValueError('Archive has too many entries')
    total=sum(i.file_size for i in infos)
    if total>MAX_EXPANDED:raise ValueError('Expanded archive exceeds 100 MB')
    files=[]; findings=[]
    for i in infos:
        p=PurePosixPath(i.filename)
        if p.is_absolute() or '..' in p.parts or (p.parts and ':' in p.parts[0]):findings.append(finding('Unsafe archive path','high',i.filename))
        if not i.is_dir():files.append({'path':i.filename,'size_bytes':i.file_size,'compressed_bytes':i.compress_size})
    return z,files,total,findings

def scan_zip(name,data):
    z,files,total,findings=inspect_zip(name,data);findings.append(finding('Archive inventory complete','info',f'{len(files)} files; {total} expanded bytes'))
    return {'tool':'ZIP Analyzer','target':name,'summary':risk_summary(findings),'metadata':{'archive_size_bytes':len(data),'file_count':len(files),'expanded_size_bytes':total},'files':files,'findings':findings}
