#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-all}"

log() { printf '\n==> %s\n' "$*"; }

run_test() {
  log "YAML validation"
  python /workspace/scripts/validate_yaml.py /workspace
  log "Python syntax validation"
  python /workspace/scripts/compile_python.py /workspace
  if [ -d /workspace/tests ]; then (cd /workspace && pytest -q); fi
}

run_security() {
  log "Secret-pattern guard"
  python /workspace/scripts/secret_guard.py /workspace
}

case "$MODE" in
  test) run_test ;;
  security) run_security ;;
  all)
    run_test
    run_security
    ;;
  *)
    echo "usage: $0 [test|security|all]" >&2
    exit 2
    ;;
esac
