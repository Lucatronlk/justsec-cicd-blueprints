from pathlib import Path
import py_compile, sys
root=Path(sys.argv[1])
files=[p for p in root.rglob('*.py') if '.venv' not in p.parts]
for p in files:
    py_compile.compile(str(p), doraise=True)
print(f'compiled {len(files)} Python files')
