#!/bin/bash

set -euo pipefail

# ===========================================================================
# healthcheck.sh - Vérification de santé pour openvpn_client_proxy
# 
# Ce script vérifie que tous les services sont opérationnels :
# 1. OpenVPN est en cours d'exécution
# 2. Le routage passe par tun/tap
# 3. Le DNS local fonctionne
# 4. Le proxy peut sortir vers un endpoint fiable
# 
# Auteur: Vibe Code (amélioration 2026)
# Licence: MIT
# Version: 2.0.0
# ===========================================================================


# Charger les fonctions communes
source "/usr/local/lib/common.sh"

# Initialiser l'environnement
init_environment

# ===========================================================================
# Configuration
# ===========================================================================

# Variables d'environnement avec valeurs par défaut
ROUTE_TEST_IP="${ROUTE_TEST_IP:-$DEFAULT_ROUTE_TEST_IP}"
PROXY_TEST_HOST="${PROXY_TEST_HOST:-$DEFAULT_PROXY_TEST_HOST}"
PROXY_TEST_URL="${PROXY_TEST_URL:-$DEFAULT_PROXY_TEST_URL}"

# ===========================================================================
# Fonctions locales
# ===========================================================================

# Vérifie que le routage OpenVPN est actif
# Usage: check_openvpn_routing
check_openvpn_routing() {
    local dev
    dev=$(find_vpn_interface || true)
    [ -n "$dev" ]
}

# Vérifie que le DNS local fonctionne
# Usage: check_dns_local
check_dns_local() {
    test_dns_resolution "$PROXY_TEST_HOST" "127.0.0.1"
}

# Vérifie que le proxy HTTP fonctionne avec un test réel via une URL externe
# Usage: check_http_proxy
check_http_proxy() {
    local proxy_port
    proxy_port=$(get_privoxy_port)
    
    # 1) Vérifier que le proxy écoute
    if ! nc -z -w 2 127.0.0.1 "$proxy_port" 2>/dev/null; then
        log_json ERROR "healthcheck" "privoxy not listening on $proxy_port"
        return 1
    fi
    
    # 2) Test reel via proxy avec PROXY_TEST_URL (204 attendu). Aucun
    # fallback : Privoxy repond lui-meme 502/503 en page d'erreur quand le
    # tunnel est mort, donc un grep sur "HTTP" validerait a tort (H1).
    if timeout 8 curl -s -f \
        -x "http://127.0.0.1:${proxy_port}" \
        --connect-timeout 3 \
        --max-time 6 \
        -o /dev/null \
        "$PROXY_TEST_URL" 2>/dev/null; then
        return 0
    fi

    log_json ERROR "healthcheck" \
        "external connectivity via proxy failed" \
        "url=$PROXY_TEST_URL"
    return 1
}

# ===========================================================================
# Vérifications principales
# ===========================================================================

main() {
    # Note: We don't fail if vpn_healthy sentinel is missing because there's a race condition
    # where the supervisor loop might remove it while healthcheck is running.
    # Instead, we validate the system ourselves.
    
    # 1) Le processus VPN doit être vivant (openvpn ou wireguard)
    case "${VPN_TYPE:-openvpn}" in
        wireguard)
            if ! ip link show wg0 >/dev/null 2>&1; then
                log_json ERROR "healthcheck" "wg0 interface not present"
                exit 1
            fi
            ;;
        *)
            if ! pidof openvpn >/dev/null 2>&1; then
                log_json ERROR "healthcheck" "openvpn process not running"
                exit 1
            fi
            ;;
    esac

    # 2) Le routage doit passer par tun/tap
    if ! check_openvpn_routing; then
        log_json ERROR "healthcheck" "routing is not active on tunnel interface"
        exit 1
    fi

    # 3) Le DNS local doit fonctionner pour resolver les sites de test
    if ! check_dns_local; then
        log_json ERROR "healthcheck" "local DNS resolution failed"
        exit 1
    fi

    # 4) Le proxy doit pouvoir sortir vers un endpoint fiable
    if ! check_http_proxy; then
        log_json ERROR "healthcheck" "proxy connectivity test failed"
        exit 1
    fi

    log_json INFO "healthcheck" "All checks passed - system healthy"
    exit 0
}

# Exécuter le programme principal
main "$@"
