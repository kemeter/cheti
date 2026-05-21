#!/usr/bin/env bash
# Start Pebble + challtestsrv for the e2e test suite.
#
#   ./scripts/pebble-up.sh
#   cargo test --test pebble_e2e -- --ignored
#   ./scripts/pebble-down.sh
set -euo pipefail

NETWORK="cheti-pebble"
PEBBLE_IMAGE="ghcr.io/letsencrypt/pebble:latest"
CHALLTESTSRV_IMAGE="ghcr.io/letsencrypt/pebble-challtestsrv:latest"

docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK"

docker rm -f cheti-challtestsrv cheti-pebble >/dev/null 2>&1 || true

docker run -d --rm --name cheti-challtestsrv --network "$NETWORK" \
  -p 8053:8053/udp -p 8055:8055 \
  "$CHALLTESTSRV_IMAGE" \
  -defaultIPv4 "" -defaultIPv6 "" -dnsserver ":8053" -management ":8055"

docker run -d --rm --name cheti-pebble --network "$NETWORK" \
  -p 14000:14000 -p 15000:15000 \
  -e PEBBLE_VA_NOSLEEP=1 \
  "$PEBBLE_IMAGE" \
  -dnsserver cheti-challtestsrv:8053

# Wait for Pebble's directory endpoint.
for _ in $(seq 1 30); do
  if curl -k -s -o /dev/null -w "%{http_code}" https://localhost:14000/dir | grep -q "^200$"; then
    echo "Pebble is up on https://localhost:14000/dir"
    exit 0
  fi
  sleep 0.3
done

echo "Pebble did not become ready in time" >&2
exit 1
