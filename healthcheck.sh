#!/bin/sh

set -euo pipefail

# --- Variables par défaut (configurables via Docker) ---
: "${ROUTE_TEST_IP:=9.9.9.9}"
: "${PROXY_TEST_HOST:=connectivitycheck.gstatic.com}"
: "${PROXY_TEST_URL:=http://connectivitycheck.gstatic.com/generate_204}"
: "${PROXY_PORT:=3128}"
: "${MAX_RETRIES:=1}"  # Réduit pour éviter les timeouts Docker
: "${TIMEOUT_SEC:=2}"  # Timeout court pour Docker

# --- Vérification des dépendances critiques ---
for cmd in ip curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: $cmd is missing" >&2
        exit 1
    fi
done

# --- Fonctions ---
find_vpn_interface() {
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | while read -r dev; do
        case "$dev" in
            tun*|tap*)
                if ip -4 addr show dev "$dev" up scope global 2>/dev/null | grep -q 'inet '; then
                    printf '%s\n' "$dev"
                    return 0
                fi
                ;;
        esac
    done
    return 1
}

check_openvpn_routing() {
    local dev
    dev=$(find_vpn_interface) || return 1
    [[ -n "$dev" ]]
}

check_dns_local() {
    # Utilise `getent` (plus léger que `nslookup` ou `dig` dans un conteneur)
    if getent ahosts "$PROXY_TEST_HOST" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

check_http_proxy() {
    local proxy_url="http://127.0.0.1:$PROXY_PORT"
    local test_url

    # Ajoute l'authentification si nécessaire
    if [[ -n "${PROXY_USER:-}" && -n "${PROXY_PASS:-}" ]]; then
        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:$PROXY_PORT"
    fi

    # Teste les URLs une par une avec un timeout court
    for test_url in "$PROXY_TEST_URL" "http://example.com"; do
        if curl -fsS --connect-timeout "$TIMEOUT_SEC" --max-time "$TIMEOUT_SEC" --proxy "$proxy_url" "$test_url" >/dev/null 2>&1; then
            return 0
        fi
    done

    return 1
}

# --- Vérification du fichier sentinelle (optionnel) ---
if [[ ! -f /tmp/vpn_healthy ]]; then
    exit 1
fi

# --- 1) Vérification du processus OpenVPN ---
if ! pidof openvpn >/dev/null 2>&1; then
    exit 1
fi

# --- 2) Vérification du routage via tun/tap ---
if ! check_openvpn_routing; then
    exit 1
fi

# --- 3) Vérification du DNS local ---
if ! check_dns_local; then
    exit 1
fi

# --- 4) Vérification du proxy HTTP ---
if ! check_http_proxy; then
    exit 1
fi

exit 0