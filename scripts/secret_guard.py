from pathlib import Path
import re, sys
root=Path(sys.argv[1])
patterns = [
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'(?i)(password|passwd|secret)\s*[:=]\s*["\']?[^\s"\']{12,}'),
]
allow_names={'.env.example'}
findings=[]
for p in root.rglob('*'):
    if not p.is_file() or '.git' in p.parts or p.name in allow_names:
        continue
    if p.stat().st_size > 2_000_000:
        continue
    try: text=p.read_text(encoding='utf-8')
    except UnicodeDecodeError: continue
    for i,line in enumerate(text.splitlines(),1):
        if 'example-only-secret' in line or 'changeme-development-only' in line:
            continue
        if re.search(r'(?i)variable\s+["\'][^"\']*(secret|password)[^"\']*["\']', line):
            continue
        if re.search(r'(?i)^[A-Za-z0-9_]*(secret|password)[A-Za-z0-9_]*\s*\{', line.strip()):
            continue
        if re.search(r'(?i)(secret|password)[A-Za-z0-9_]*\s*=\s*(var\.|os\.environ|\$\{|getenv\()', line):
            continue
        if any(rx.search(line) for rx in patterns):
            findings.append(f'{p.relative_to(root)}:{i}: possible credential material')
if findings:
    print('\n'.join(findings))
    raise SystemExit(1)
print('secret-pattern guard passed')
