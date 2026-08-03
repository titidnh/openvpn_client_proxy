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

# Route effective obligatoire via tun/tap pour éviter les faux positifs.
ROUTE_TEST_IP="${ROUTE_TEST_IP:-9.9.9.9}"
check_openvpn_routing() {
    out=$(ip route get "$ROUTE_TEST_IP" 2>/dev/null || true)
    dev=$(echo "$out" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [ -n "$dev" ] || return 1
    case "$dev" in
        tun*|tap*) return 0 ;;
        *) return 1 ;;
    esac
}

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
# Test connectivité HTTP via Privoxy
# Vérifie que le trafic sort effectivement par le tunnel VPN.
# ---------------------------------------------------------------------------
# Test : connectivité HTTP via Privoxy (ou nginx auth proxy)
# Le port public est toujours 3128. Si PROXY_USER/PROXY_PASS sont définis,
# les credentials sont passés au proxy.
# ---------------------------------------------------------------------------
proxy_port=3128
proxy_url="http://127.0.0.1:${proxy_port}"
if [ -n "${PROXY_USER:-}" ] && [ -n "${PROXY_PASS:-}" ]; then
    proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${proxy_port}"
fi

# 1) OpenVPN doit être vivant
pidof openvpn >/dev/null 2>&1 || exit 1

# 2) Le routage doit passer par tun/tap
check_openvpn_routing || exit 1

# 3) Requête HTTP via proxy avec fallback d'endpoints
curl -fsS --max-time 5 --proxy "$proxy_url" http://connectivitycheck.gstatic.com/generate_204 >/dev/null 2>&1 && exit 0
curl -fsS --max-time 5 --proxy "$proxy_url" http://example.com >/dev/null 2>&1 && exit 0

exit 1