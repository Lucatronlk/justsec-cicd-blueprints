from pathlib import Path
import sys, yaml
root = Path(sys.argv[1])
files = list(root.rglob('*.yml')) + list(root.rglob('*.yaml'))
errors=[]
for p in files:
    try:
        list(yaml.safe_load_all(p.read_text(encoding='utf-8')))
    except Exception as e:
        errors.append(f'{p}: {e}')
if errors:
    print('\n'.join(errors))
    raise SystemExit(1)
print(f'validated {len(files)} YAML files')
