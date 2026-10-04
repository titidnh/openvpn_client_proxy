#!/bin/bash
# ============================================================================
# lib/wireguard.sh - WireGuard client management
# ============================================================================
# Corrige C4 : start_wireguard n'etait defini que dans vpn-startup.sh, jamais
# source par start.sh -> "command not found" et superviseur mort.
# Parsing robuste : gere "Cle = valeur" ET "Cle=valeur" (sans espaces),
# AllowedIPs multi-valeurs avec virgules, Endpoint hostname ou IP.
# ============================================================================

# Extrait une valeur d'une section WireGuard (gestion des espaces optionnels
# autour du "="). Emet la valeur brute.
# Usage: wg_get_value CONFIG_FILE KEY
wg_get_value() {
    local conf="$1"
    local key="$2"

    awk -F'=' -v key="$key" '
        {
            k = $1
            gsub(/[[:space:]]/, "", k)
            if (tolower(k) == tolower(key)) {
                v = $0
                sub(/^[^=]*=/, "", v)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
                print v
                exit
            }
        }' "$conf"
}

# Demarre le tunnel WireGuard a partir de $VPN_DIR/wg0.conf.
# Retourne 0 si l'interface wg0 est montee avec une adresse IP.
start_wireguard() {
    local conf="${VPN_DIR}/wg0.conf"

    log_json INFO "start_wireguard" "Starting WireGuard" "conf=${conf}"

    if [ ! -f "$conf" ]; then
        log_json ERROR "start_wireguard" "config not found" "conf=${conf}"
        return 1
    fi

    if ! command_exists wg; then
        log_json ERROR "start_wireguard" "wg not installed (wireguard-tools)"
        return 1
    fi

    # Nettoyage d'une interface residuelle
    if ip link show wg0 >/dev/null 2>&1; then
        log_json INFO "start_wireguard" "removing existing wg0 interface"
        ip link del dev wg0 2>/dev/null || true
    fi

    local address
    address=$(wg_get_value "$conf" "Address")
    if [ -z "$address" ]; then
        log_json ERROR "start_wireguard" "no Address in WireGuard config"
        return 1
    fi
    # Address peut contenir plusieurs adresses separees par des virgules
    local addr
    local first_addr=""
    for addr in ${address//,/ }; do
        [ -n "$addr" ] || continue
        if [ -z "$first_addr" ]; then
            first_addr="$addr"
        fi
    done
    if [ -z "$first_addr" ]; then
        log_json ERROR "start_wireguard" "no usable Address in WireGuard config"
        return 1
    fi

    local private_key
    private_key=$(wg_get_value "$conf" "PrivateKey")
    if [ -z "$private_key" ]; then
        log_json ERROR "start_wireguard" "no PrivateKey in WireGuard config"
        return 1
    fi

    # Endpoint
    local endpoint
    endpoint=$(wg_get_value "$conf" "Endpoint")
    if [ -z "$endpoint" ]; then
        log_json ERROR "start_wireguard" "no Endpoint in WireGuard config"
        return 1
    fi

    local endpoint_host="${endpoint%:*}"
    local endpoint_port="${endpoint##*:}"

    # Interface
    if ! ip link add dev wg0 type wireguard 2>/dev/null; then
        log_json ERROR "start_wireguard" "failed to create wg0 interface"
        return 1
    fi

    if ! printf '%s\n' "$private_key" | wg set wg0 private-key /dev/stdin 2>/dev/null; then
        log_json ERROR "start_wireguard" "failed to set private key"
        ip link del dev wg0 2>/dev/null || true
        return 1
    fi

    # Peer
    local peer_pubkey
    local allowed_ips
    peer_pubkey=$(wg_get_value "$conf" "PublicKey")
    allowed_ips=$(wg_get_value "$conf" "AllowedIPs")

    if [ -n "$peer_pubkey" ]; then
        local wg_peer_args
        wg_peer_args="peer ${peer_pubkey} endpoint ${endpoint}"
        if [ -n "$allowed_ips" ]; then
            wg_peer_args="$wg_peer_args allowed-ips ${allowed_ips// /}"
        else
            wg_peer_args="$wg_peer_args allowed-ips 0.0.0.0/0,::/0"
        fi
        # shellcheck disable=SC2086
        if ! wg set wg0 $wg_peer_args 2>/dev/null; then
            log_json ERROR "start_wireguard" "failed to configure peer"
            ip link del dev wg0 2>/dev/null || true
            return 1
        fi
    fi

    # Adresse + MTU
    ip -4 address add "$first_addr" dev wg0 2>/dev/null || true

    local mtu
    mtu=$(wg_get_value "$conf" "MTU")
    if [ -n "$mtu" ]; then
        ip link set dev wg0 mtu "$mtu" 2>/dev/null || true
    fi

    if ! ip link set dev wg0 up 2>/dev/null; then
        log_json ERROR "start_wireguard" "failed to bring up wg0"
        ip link del dev wg0 2>/dev/null || true
        return 1
    fi

    # Routes par defaut : AllowedIPs = 0.0.0.0/0 (avec ou sans virgule,
    # avec ou sans espace) doit etre reconnu - l'ancien parsing awk '{print $3}'
    # echouait sur "0.0.0.0/0, ::/0" (C4-5).
    local has_default=0
    local aip
    for aip in ${allowed_ips//,/ }; do
        if [ "$aip" = "0.0.0.0/0" ]; then
            has_default=1
        fi
    done

    if [ "$has_default" -eq 1 ]; then
        # Route vers l'endpoint via la passerelle physique, puis 0.0.0.0/1+128.0.0.0/1
        local gw
        local phys
        phys=$(get_physical_iface)
        if [ -n "$phys" ]; then
            gw=$(ip -4 route show dev "$phys" 2>/dev/null | awk '/^default/{print $3; exit}')

            if [ -n "$gw" ]; then
                ip route add "$endpoint_host" via "$gw" dev "$phys" 2>/dev/null || true
            fi
        fi

        ip route add 0.0.0.0/1 dev wg0 2>/dev/null || true
        ip route add 128.0.0.0/1 dev wg0 2>/dev/null || true
        log_json INFO "start_wireguard" "default routes via wg0 installed"
    else
        for aip in ${allowed_ips//,/ }; do
            [ -n "$aip" ] || continue
            ip route add "$aip" dev wg0 2>/dev/null || true
        done
        log_json INFO "start_wireguard" "AllowedIPs routes via wg0 installed"
    fi

    log_json INFO "start_wireguard" \\
        "WireGuard tunnel up" \\
        "endpoint=${endpoint}" \\
        "address=${first_addr}"

    return 0
}

# Verifie que le tunnel WireGuard a eu un handshake recent (< 180 s).
# Sonde reelle utilisable par le superviseur et le healthcheck (C4-2/C4-3).
# Usage: wireguard_handshake_ok [MAX_AGE_SECONDS]
wireguard_handshake_ok() {
    local max_age="${1:-180}"
    local latest

    command_exists wg || return 1
    ip link show wg0 >/dev/null 2>&1 || return 1

    latest=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2; exit}')
    [ -n "$latest" ] || return 1
    [ "$latest" -eq 0 ] && return 1

    local now
    now=$(date +%s)
    [ $((now - latest)) -le "$max_age" ]
}
