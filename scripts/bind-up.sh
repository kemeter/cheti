#!/usr/bin/env bash
# Start a BIND primary accepting TSIG-signed updates for the RFC 2136 tests.
#
#   ./scripts/bind-up.sh
#   cargo test --test rfc2136_bind -- --ignored
#   ./scripts/bind-down.sh
set -euo pipefail

BIND_IMAGE="internetsystemsconsortium/bind9:9.20"
DATA_DIR="$(cd "$(dirname "$0")/../tests/data/bind" && pwd)"

docker rm -f cheti-bind >/dev/null 2>&1 || true

docker create --name cheti-bind \
  -p 127.0.0.1:5300:53/tcp -p 127.0.0.1:5300:53/udp \
  "$BIND_IMAGE" -g -c /etc/bind/named.conf >/dev/null
docker cp "$DATA_DIR/named.conf" cheti-bind:/etc/bind/named.conf
docker cp "$DATA_DIR/example.com.zone" cheti-bind:/var/lib/bind/example.com.zone
docker start cheti-bind >/dev/null

# Wait for the zone to be loaded.
for _ in $(seq 1 30); do
  if docker logs cheti-bind 2>&1 | grep -q "zone example.com/IN: loaded"; then
    echo "BIND is up on 127.0.0.1:5300"
    exit 0
  fi
  sleep 0.3
done

echo "BIND did not become ready in time" >&2
docker logs cheti-bind >&2
exit 1
