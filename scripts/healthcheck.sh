#!/usr/bin/env bash
set -euo pipefail

SERVICES=(
  "http://gateway-api:8000/health"
  "http://risk-manager:8070/health"
  "http://execution-ib:8071/health"
  "http://execution-crypto:8072/health"
)

for svc in "${SERVICES[@]}"; do
  if ! curl -fsS "${svc}" >/dev/null; then
    echo "$(date -u "+%Y-%m-%dT%H:%M:%SZ") SERVICE DOWN ${svc}" >&2
  fi
  sleep 1
 done
