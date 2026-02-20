#!/bin/sh
set -e

# ── Go runtime tuning (respects env from docker-compose) ────────────
export GOMAXPROCS="${GOMAXPROCS:-2}"
export GOMEMLIMIT="${GOMEMLIMIT:-200MiB}"

# fix hidden service directory permissions — Tor requires 700
mkdir -p /var/lib/tor/proxy_hidden_service
chown root:root /var/lib/tor/proxy_hidden_service
chmod 700 /var/lib/tor/proxy_hidden_service

echo "[entrypoint] starting Tor..."
tor -f /etc/tor/torrc &
TOR_PID=$!

# wait for Tor to initialize and generate the .onion address
echo "[entrypoint] waiting for Tor hostname..."
until [ -f /var/lib/tor/proxy_hidden_service/hostname ]; do
  sleep 1
done

ONION_ADDR=$(cat /var/lib/tor/proxy_hidden_service/hostname)
echo "[entrypoint] proxy .onion: $ONION_ADDR"
echo "[entrypoint] GOMAXPROCS=$GOMAXPROCS  GOMEMLIMIT=$GOMEMLIMIT"

export PROXY_ONION="$ONION_ADDR"

echo "[entrypoint] starting proxy..."
exec /app/proxy
