#!/usr/bin/env bash
set -euo pipefail
docker rm -f cheti-pebble cheti-challtestsrv >/dev/null 2>&1 || true
docker network rm cheti-pebble >/dev/null 2>&1 || true
echo "Pebble stack stopped"
