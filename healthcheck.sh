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

ROUTE_TEST_IP="${ROUTE_TEST_IP:-9.9.9.9}"
PROXY_TEST_HOST="${PROXY_TEST_HOST:-connectivitycheck.gstatic.com}"
PROXY_TEST_URL="${PROXY_TEST_URL:-http://connectivitycheck.gstatic.com/generate_204}"

check_openvpn_routing() {
    out=$(ip route get "$ROUTE_TEST_IP" 2>/dev/null || true)
    dev=$(echo "$out" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [ -n "$dev" ] || return 1
    case "$dev" in
        tun*|tap*) return 0 ;;
        *) return 1 ;;
    esac
}

check_dns_local() {
    if command -v getent >/dev/null 2>&1; then
        if getent ahosts "$PROXY_TEST_HOST" >/dev/null 2>&1; then
            return 0
        fi
    fi

    if command -v nslookup >/dev/null 2>&1; then
        if nslookup "$PROXY_TEST_HOST" 127.0.0.1 >/dev/null 2>&1; then
            return 0
        fi
    elif command -v dig >/dev/null 2>&1; then
        if dig @127.0.0.1 "$PROXY_TEST_HOST" +short >/dev/null 2>&1; then
            return 0
        fi
    fi

    return 1
}

check_http_proxy() {
    proxy_port=3128
    proxy_url="http://127.0.0.1:${proxy_port}"
    if [ -n "${PROXY_USER:-}" ] && [ -n "${PROXY_PASS:-}" ]; then
        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${proxy_port}"
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "[healthcheck] curl is not available"
        return 1
    fi

    for test_url in "$PROXY_TEST_URL" "http://example.com"; do
        if curl -fsS --connect-timeout 3 --max-time 5 --proxy "$proxy_url" "$test_url" >/dev/null 2>&1; then
            return 0
        fi
    done

    return 1
}

# 1) OpenVPN doit être vivant
if ! pidof openvpn >/dev/null 2>&1; then
    echo "[healthcheck] openvpn process not running"
    rm -f /tmp/vpn_healthy
    exit 1
fi

# 2) Le routage doit passer par tun/tap
if ! check_openvpn_routing; then
    echo "[healthcheck] routing is not active on tun/tap"
    rm -f /tmp/vpn_healthy
    exit 1
fi

# 3) Le DNS local doit fonctionner pour resolver les sites de test
if ! check_dns_local; then
    echo "[healthcheck] local DNS resolution failed"
    rm -f /tmp/vpn_healthy
    exit 1
fi

# 4) Le proxy doit pouvoir sortir vers un endpoint fiable
if ! check_http_proxy; then
    echo "[healthcheck] proxy connectivity test failed"
    rm -f /tmp/vpn_healthy
    exit 1
fi

exit 0