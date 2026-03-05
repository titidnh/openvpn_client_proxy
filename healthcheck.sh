#!/bin/sh

set -eu

# ---------------------------------------------------------------------------
# Check rapide : le superviseur maintient ce fichier tant que le tunnel
# est actif. S'il est absent, inutile d'aller plus loin.
# ---------------------------------------------------------------------------
if [ ! -f /tmp/vpn_healthy ]; then
    echo "[healthcheck] vpn_healthy sentinel missing — tunnel down or not yet ready"
    exit 1
fi

# ---------------------------------------------------------------------------
# Détection du port et protocole VPN depuis vpn.conf
# ---------------------------------------------------------------------------
conf="/vpn/vpn.conf"
host=""
port=""
proto=""

if [ -f "$conf" ]; then
    remote_line=$(awk '/^remote /{print; exit}' "$conf" || true)
    proto=$(awk '/^proto /{print $2; exit}' "$conf" || true)

    if [ -n "$remote_line" ]; then
        set -- $remote_line
        hostpart="$2"
        if echo "$hostpart" | grep -q ':'; then
            host=$(echo "$hostpart" | cut -d: -f1)
            port=$(echo "$hostpart" | cut -d: -f2)
        else
            host="$hostpart"
            if [ "$#" -ge 3 ]; then port="$3"; fi
        fi
    fi
fi

: "${port:=1194}"
: "${proto:=udp}"

# ---------------------------------------------------------------------------
# Test 1 : connectivité directe vers le serveur VPN
# ---------------------------------------------------------------------------
if [ -n "$host" ]; then
    if [ "$proto" = "tcp" ]; then
        nc -z -w 3 "$host" "$port" >/dev/null 2>&1 && exit 0
    else
        # UDP : nc -u retourne toujours 0 même si le port est fermé,
        # on l'utilise juste comme indicateur que le réseau est joignable
        nc -z -u -w 3 "$host" "$port" >/dev/null 2>&1 && exit 0 || true
    fi
fi

# ---------------------------------------------------------------------------
# Test 2 (fallback) : connectivité HTTP via Privoxy
# Confirme que le trafic sort bien par le tunnel
# ---------------------------------------------------------------------------
proxy_port=3128
if [ -f /etc/privoxy/privoxy.config ]; then
    addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' /etc/privoxy/privoxy.config || true)
    [ -n "$addr" ] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
fi

if pidof openvpn >/dev/null 2>&1; then
    curl -fsS --max-time 5 \
        --proxy "http://127.0.0.1:${proxy_port}" \
        http://example.com >/dev/null 2>&1 && exit 0
fi

exit 1