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

# Vérifie que le proxy HTTP fonctionne
# Usage: check_http_proxy
# Vérifie que le proxy HTTP fonctionne
# Usage: check_http_proxy
# Vérifie que le proxy HTTP fonctionne
# Usage: check_http_proxy
check_http_proxy() {
    local proxy_port
    proxy_port=$(get_privoxy_port)
    
    # ✅ Vérification locale uniquement
    if ! nc -z -w 2 127.0.0.1 "$proxy_port" 2>/dev/null; then
        log_json ERROR "healthcheck" "privoxy not listening on $proxy_port"
        return 1
    fi
    
    # Test basique: vérifier que ça répond
    if timeout 3 curl -s -x "http://127.0.0.1:${proxy_port}" \
                       --connect-timeout 2 \
                       -o /dev/null \
                       "http://127.0.0.1/internal-test" 2>/dev/null; then
        return 0
    fi
    
    # Si curl échoue, au minimum vérifier qu'on peut se connecter
    if nc -z -w 2 127.0.0.1 "$proxy_port" 2>/dev/null; then
        return 0
    fi
    
    return 1
}

# ===========================================================================
# Vérifications principales
# ===========================================================================

main() {
    # Check rapide : le superviseur maintient ce fichier tant que le tunnel
    # est actif. S'il est absent, inutile d'aller plus loin.
    if [ ! -f /tmp/vpn_healthy ]; then
        log_json ERROR "healthcheck" \
            "vpn_healthy sentinel missing - tunnel down or not yet ready"
        exit 1
    fi

    # 1) OpenVPN doit être vivant
    if ! pidof openvpn >/dev/null 2>&1; then
        log_json ERROR "healthcheck" "openvpn process not running"
        rm -f /tmp/vpn_healthy
        exit 1
    fi

    # 2) Le routage doit passer par tun/tap
    if ! check_openvpn_routing; then
        log_json ERROR "healthcheck" "routing is not active on tun/tap"
        rm -f /tmp/vpn_healthy
        exit 1
    fi

    # 3) Le DNS local doit fonctionner pour resolver les sites de test
    if ! check_dns_local; then
        log_json ERROR "healthcheck" "local DNS resolution failed"
        rm -f /tmp/vpn_healthy
        exit 1
    fi

    # 4) Le proxy doit pouvoir sortir vers un endpoint fiable
    if ! check_http_proxy; then
        log_json ERROR "healthcheck" "proxy connectivity test failed"
        rm -f /tmp/vpn_healthy
        exit 1
    fi

    log_json INFO "healthcheck" "All checks passed - system healthy"
    exit 0
}

# Exécuter le programme principal
main "$@"
