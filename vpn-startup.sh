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
    local private_key
    local address
    local allowed_ips
    local endpoint
    local peer_public_key
    local persistent_keepalive
    
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
        ip link del dev wg0 2>/dev/null || true
        sleep 1
    fi
    
    # Parse configuration file (skip DNS lines to avoid resolvconf issues in container)
    private_key=$(grep "^PrivateKey" "$config" | awk '{print $3}')
    address=$(grep "^Address" "$config" | awk '{print $3}')
    # PublicKey under [Peer] section is after the [Peer] marker
    peer_public_key=$(awk '/^\[Peer\]/,EOF {if (/^PublicKey/) {print $3; exit}}' "$config")
    allowed_ips=$(awk '/^\[Peer\]/,EOF {if (/^AllowedIPs/) {print $3; exit}}' "$config")
    endpoint=$(awk '/^\[Peer\]/,EOF {if (/^Endpoint/) {print $3; exit}}' "$config")
    persistent_keepalive=$(awk '/^\[Peer\]/,EOF {if (/^PersistentKeepalive/) {print $3; exit}}' "$config")
    
    if [ -z "$private_key" ] || [ -z "$address" ] || [ -z "$peer_public_key" ]; then
        log_json ERROR "start_wireguard" \
            "Missing required config parameters" \
            "has_key=${private_key:+yes} has_addr=${address:+yes} has_peer=${peer_public_key:+yes}"
        return 1
    fi
    
    # Resolve endpoint hostname to IP if needed
    local endpoint_ip
    local endpoint_host
    local endpoint_port
    local resolve_attempts=3
    local resolve_attempt=0
    
    # Split endpoint into host:port
    endpoint_host="${endpoint%:*}"
    endpoint_port="${endpoint##*:}"
    
    # Check if endpoint_host is already an IP
    if echo "$endpoint_host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        endpoint_ip="$endpoint_host"
    else
        # Resolve hostname to IP using getent (works via dnsmasq)
        log_json INFO "start_wireguard" "Resolving endpoint hostname" "host=$endpoint_host"
        
        while [ $resolve_attempt -lt $resolve_attempts ]; do
            endpoint_ip=$(getent hosts "$endpoint_host" 2>/dev/null | awk '{print $1; exit}')
            
            if [ -n "$endpoint_ip" ]; then
                break
            fi
            
            resolve_attempt=$((resolve_attempt + 1))
            
            if [ $resolve_attempt -lt $resolve_attempts ]; then
                log_json WARN "start_wireguard" "DNS resolution attempt failed, retrying..." "attempt=$resolve_attempt" "host=$endpoint_host"
                sleep 1
            fi
        done
        
        if [ -z "$endpoint_ip" ]; then
            log_json ERROR "start_wireguard" "Failed to resolve endpoint hostname after $resolve_attempts attempts" "host=$endpoint_host"
            return 1
        fi
    fi
    
    log_json INFO "start_wireguard" "Endpoint resolved" "host=$endpoint_host" "ip=$endpoint_ip" "port=$endpoint_port"
    endpoint="${endpoint_ip}:${endpoint_port}"
    
    # Create and configure WireGuard interface using direct commands (avoid wg-quick DNS management)
    if ! ip link add dev wg0 type wireguard 2>/dev/null; then
        log_json ERROR "start_wireguard" "Failed to create wg0 interface"
        return 1
    fi
    
    # Set private key
    if ! echo "$private_key" | wg set wg0 private-key /dev/stdin 2>/dev/null; then
        log_json ERROR "start_wireguard" "Failed to set private key"
        ip link del dev wg0 2>/dev/null || true
        return 1
    fi
    
    # Set peer configuration
    if ! wg set wg0 peer "$peer_public_key" allowed-ips "$allowed_ips" endpoint "$endpoint" persistent-keepalive "${persistent_keepalive:-0}" 2>/dev/null; then
        log_json ERROR "start_wireguard" "Failed to set peer configuration"
        ip link del dev wg0 2>/dev/null || true
        return 1
    fi
    
    # Assign IP address and bring up interface
    if ! ip addr add "$address" dev wg0 2>/dev/null; then
        log_json ERROR "start_wireguard" "Failed to assign address"
        ip link del dev wg0 2>/dev/null || true
        return 1
    fi
    
    # Set MTU (WireGuard typical is 1420)
    if ! ip link set mtu 1420 dev wg0 2>/dev/null; then
        log_json WARN "start_wireguard" "Failed to set MTU - continuing anyway"
    fi
    
    if ! ip link set up dev wg0 2>/dev/null; then
        log_json ERROR "start_wireguard" "Failed to bring up interface"
        ip link del dev wg0 2>/dev/null || true
        return 1
    fi
    
    sleep 1
    
    # Configure routes based on AllowedIPs from peer config
    # Split 0.0.0.0/0 into two /1 routes to avoid blocking return path through eth0
    if [ "$allowed_ips" = "0.0.0.0/0" ]; then
        log_json INFO "start_wireguard" "Configuring routes for all traffic"
        if ! ip route add 0.0.0.0/1 dev wg0 2>/dev/null; then
            log_json WARN "start_wireguard" "Failed to add route 0.0.0.0/1"
        fi
        if ! ip route add 128.0.0.0/1 dev wg0 2>/dev/null; then
            log_json WARN "start_wireguard" "Failed to add route 128.0.0.0/1"
        fi
    else
        # Add specific routes for custom AllowedIPs
        log_json INFO "start_wireguard" "Configuring routes for AllowedIPs" "ips=$allowed_ips"
        if ! ip route add "$allowed_ips" dev wg0 2>/dev/null; then
            log_json WARN "start_wireguard" "Failed to add route" "ips=$allowed_ips"
        fi
    fi
    
    # Verify that the interface is up
    if ip link show wg0 2>/dev/null | grep -q "UP"; then
        log_json INFO "start_wireguard" \
            "WireGuard interface is UP" \
            "interface=wg0" \
            "address=$address"
        return 0
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
    
    # Remove routes
    ip route del 0.0.0.0/1 dev wg0 2>/dev/null || true
    ip route del 128.0.0.0/1 dev wg0 2>/dev/null || true
    
    # Remove interface
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
