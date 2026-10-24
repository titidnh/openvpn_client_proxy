#!/bin/bash

# ===========================================================================
# vpn-selector.sh - Détection et configuration du type VPN
#
# Ce script détermine quel type de VPN utiliser (OpenVPN ou WireGuard)
# basé sur la variable d'environnement VPN_TYPE et configure les
# paramètres nécessaires pour les iptables et les interfaces.
#
# Licence: MIT
# ===========================================================================

set -euo pipefail

# Source les fonctions communes
source "/usr/local/lib/common.sh"

# ===========================================================================
# Validation du type VPN
# ===========================================================================
validate_vpn_type() {
    local vpn_type="${1:-openvpn}"
    
    case "${vpn_type,,}" in
        openvpn|ovpn)
            echo "openvpn"
            return 0
            ;;
        wireguard|wg)
            echo "wireguard"
            return 0
            ;;
        *)
            log_json ERROR "validate_vpn_type" \
                "Invalid VPN type. Use: openvpn or wireguard" \
                "provided=${vpn_type}"
            return 1
            ;;
    esac
}

# ===========================================================================
# Exporter les variables de configuration VPN
# ===========================================================================
export_vpn_config() {
    local vpn_type="$1"
    
    case "$vpn_type" in
        openvpn)
            export VPN_TYPE="openvpn"
            export VPN_INTERFACE_PATTERN="tun\|tap"
            export VPN_CONF="/vpn/vpn.conf"
            export OPENVPN_ENABLED="true"
            export WIREGUARD_ENABLED="false"
            
            log_json INFO "export_vpn_config" \
                "OpenVPN configuration loaded" \
                "interface_pattern=${VPN_INTERFACE_PATTERN}"
            ;;
        wireguard)
            export VPN_TYPE="wireguard"
            export VPN_INTERFACE_PATTERN="wg0"
            export VPN_CONF="/vpn/wg0.conf"
            export OPENVPN_ENABLED="false"
            export WIREGUARD_ENABLED="true"
            
            log_json INFO "export_vpn_config" \
                "WireGuard configuration loaded" \
                "interface_pattern=${VPN_INTERFACE_PATTERN}"
            ;;
    esac
}

# ===========================================================================
# Vérifier les fichiers de configuration requis
# ===========================================================================
check_vpn_config_files() {
    local vpn_type="$1"
    local vpn_dir="${2:-/vpn}"
    
    case "$vpn_type" in
        openvpn)
            if [ ! -f "${vpn_dir}/vpn.conf" ]; then
                log_json ERROR "check_vpn_config_files" \
                    "OpenVPN config file not found" \
                    "path=${vpn_dir}/vpn.conf"
                return 1
            fi
            log_json INFO "check_vpn_config_files" \
                "OpenVPN config file found" \
                "path=${vpn_dir}/vpn.conf"
            ;;
        wireguard)
            if [ ! -f "${vpn_dir}/wg0.conf" ]; then
                log_json WARN "check_vpn_config_files" \
                    "WireGuard config file not found" \
                    "path=${vpn_dir}/wg0.conf"
                log_json INFO "check_vpn_config_files" \
                    "Expected format - see skill documentation"
                return 1
            fi
            log_json INFO "check_vpn_config_files" \
                "WireGuard config file found" \
                "path=${vpn_dir}/wg0.conf"
            ;;
    esac
}

# ===========================================================================
# Point d'entrée principal
# ===========================================================================
main() {
    local vpn_type="${VPN_TYPE:-openvpn}"
    
    log_json INFO "main" "Starting VPN selector" "vpn_type=${vpn_type}"
    
    # Valider le type VPN
    if ! vpn_type=$(validate_vpn_type "$vpn_type"); then
        return 1
    fi
    
    # Exporter la configuration
    export_vpn_config "$vpn_type"
    
    # Vérifier les fichiers de configuration
    if ! check_vpn_config_files "$vpn_type"; then
        log_json WARN "main" \
            "Configuration file check failed, continuing anyway"
    fi
    
    log_json INFO "main" "VPN selector completed successfully"
    return 0
}

# Exécuter si appelé directement (pas en source)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
