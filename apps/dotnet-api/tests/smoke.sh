#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
command -v dotnet >/dev/null || { echo 'dotnet SDK required' >&2; exit 1; }
command -v curl >/dev/null || { echo 'curl required' >&2; exit 1; }

# Loopback only: smoke test never opens an external listener.
ASPNETCORE_URLS=http://127.0.0.1:18080 dotnet run --no-launch-profile > /dev/null 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT

for attempt in {1..60}; do
  if response=$(curl --silent --show-error --fail --max-time 1 http://127.0.0.1:18080/health 2>/dev/null); then
    [[ "$response" == '{"status":"ok"}' ]] || { echo "unexpected health response: $response" >&2; exit 1; }
    echo 'health smoke test passed'
    exit 0
  fi
  kill -0 "$pid" 2>/dev/null || { echo 'API exited before health check passed' >&2; exit 1; }
  sleep 1
done

echo 'API did not become healthy within 60 seconds' >&2
exit 1
