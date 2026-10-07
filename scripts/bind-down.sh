#!/usr/bin/env bash
set -euo pipefail
docker rm -f cheti-bind >/dev/null 2>&1 || true
echo "BIND stopped"
