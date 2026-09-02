#!/bin/bash

# ===========================================================================
# vpn-startup.sh - Démarrage du VPN (OpenVPN ou WireGuard)
#
# Ce script démarre le type de VPN sélectionné et gère les
# reconexions en cas d'échec.
#
# Licence: MIT
# ===========================================================================

set -euo pipefail

source "/usr/local/lib/common.sh"

VPN_DIR="${VPN_DIR:-/vpn}"
VPN_TYPE="${VPN_TYPE:-openvpn}"
MAX_RESTART_ATTEMPTS=5
RESTART_DELAY=5

# ===========================================================================
# Démarrer OpenVPN
# ===========================================================================
start_openvpn() {
    local config="${VPN_DIR}/vpn.conf"
    
    if [ ! -f "$config" ]; then
        log_json ERROR "start_openvpn" \
            "Config file not found" \
            "path=${config}"
        return 1
    fi
    
    log_json INFO "start_openvpn" "Starting OpenVPN"
    
    openvpn \
        --config "$config" \
        --user vpn \
        --group vpn \
        --daemon \
        --log "/tmp/openvpn.log" \
        --status "/tmp/openvpn-status.log" 10
    
    log_json INFO "start_openvpn" "OpenVPN started"
    return 0
}

# ===========================================================================
# Démarrer WireGuard
# ===========================================================================
start_wireguard() {
    local config="${VPN_DIR}/wg0.conf"
    
    if [ ! -f "$config" ]; then
        log_json ERROR "start_wireguard" \
            "Config file not found" \
            "path=${config}"
        return 1
    fi
    
    log_json INFO "start_wireguard" "Starting WireGuard"
    
    # Ensure clean state - remove any existing wg0 interface
    if ip link show wg0 2>/dev/null; then
        log_json INFO "start_wireguard" "Cleaning up existing wg0 interface"
        ip link del dev wg0 2>/dev/null || wg-quick down wg0 2>/dev/null || true
        sleep 1
    fi
    
    # Bring up the interface using wg-quick (it will create the interface)
    if wg-quick up "$config"; then
        sleep 1
        # Verify that the interface is up
        if ip link show wg0 2>/dev/null | grep -q "UP"; then
            log_json INFO "start_wireguard" \
                "WireGuard interface is UP" \
                "interface=wg0"
            return 0
        fi
    fi
    
    log_json ERROR "start_wireguard" \
        "WireGuard interface failed to come UP"
    return 1
}

# ===========================================================================
# Arrêter OpenVPN
# ===========================================================================
stop_openvpn() {
    log_json INFO "stop_openvpn" "Stopping OpenVPN"
    killall openvpn 2>/dev/null || true
    sleep 2
}

# ===========================================================================
# Arrêter WireGuard
# ===========================================================================
stop_wireguard() {
    log_json INFO "stop_wireguard" "Stopping WireGuard"
    wg-quick down wg0 2>/dev/null || true
    ip link del dev wg0 2>/dev/null || true
}

# ===========================================================================
# Vérifier la connexion VPN
# ===========================================================================
check_vpn_connection() {
    local vpn_type="$1"
    
    case "$vpn_type" in
        openvpn)
            if ip link show | grep -qE "tun|tap"; then
                return 0
            fi
            ;;
        wireguard)
            if ip link show wg0 2>/dev/null | grep -q "UP"; then
                return 0
            fi
            ;;
    esac
    
    return 1
}

# ===========================================================================
# Redémarrer VPN avec retry
# ===========================================================================
restart_vpn_with_retry() {
    local vpn_type="$1"
    local attempt=1
    
    while [ $attempt -le $MAX_RESTART_ATTEMPTS ]; do
        log_json INFO "restart_vpn" \
            "Restart attempt" \
            "attempt=${attempt}/${MAX_RESTART_ATTEMPTS}" \
            "vpn_type=${vpn_type}"
        
        # Arrêter le VPN existant
        case "$vpn_type" in
            openvpn)
                stop_openvpn
                start_openvpn && break
                ;;
            wireguard)
                stop_wireguard
                start_wireguard && break
                ;;
        esac
        
        if [ $attempt -lt $MAX_RESTART_ATTEMPTS ]; then
            log_json WARN "restart_vpn" \
                "Restart failed, retrying..." \
                "wait_seconds=${RESTART_DELAY}"
            sleep $RESTART_DELAY
        fi
        
        ((attempt++))
    done
    
    if [ $attempt -gt $MAX_RESTART_ATTEMPTS ]; then
        log_json ERROR "restart_vpn" \
            "Failed to restart VPN after max attempts" \
            "max_attempts=${MAX_RESTART_ATTEMPTS}"
        return 1
    fi
}

# ===========================================================================
# Point d'entrée principal
# ===========================================================================
main() {
    log_json INFO "main" "Starting VPN" "vpn_type=${VPN_TYPE}"
    
    case "${VPN_TYPE}" in
        openvpn)
            start_openvpn
            ;;
        wireguard)
            start_wireguard
            ;;
        *)
            log_json ERROR "main" \
                "Unknown VPN type" \
                "vpn_type=${VPN_TYPE}"
            return 1
            ;;
    esac
}

# Exécuter si appelé directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
