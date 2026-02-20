#!/bin/sh
set -e

# corrige permissões do diretório do hidden service — Tor exige 700 + dono = usuário que executa tor
mkdir -p /var/lib/tor/proxy_hidden_service
chown root:root /var/lib/tor/proxy_hidden_service
chmod 700 /var/lib/tor/proxy_hidden_service

echo "iniciando Tor..."
tor -f /etc/tor/torrc &
TOR_PID=$!

# aguarda o Tor inicializar e gerar o endereço .onion
echo "aguardando Tor..."
until [ -f /var/lib/tor/proxy_hidden_service/hostname ]; do
  sleep 2
done

ONION_ADDR=$(cat /var/lib/tor/proxy_hidden_service/hostname)
echo "endereço público do proxy: $ONION_ADDR"

# injeta o endereço público no proxy para reescrever redirects
export PROXY_ONION="$ONION_ADDR"

echo "iniciando proxy..."
exec /app/proxy

# cleanup
kill $TOR_PID
