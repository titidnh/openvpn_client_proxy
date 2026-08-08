#!/bin/bash
# ===========================================================================
# common.sh - Fonctions communes pour openvpn_client_proxy
# 
# Ce fichier contient les fonctions partagées entre start.sh et healthcheck.sh
# pour éviter la duplication de code et améliorer la maintenabilité.
# 
# Auteur: Vibe Code (amélioration 2026)
# Licence: MIT (même licence que le projet parent)
# ===========================================================================

set -euo pipefail

# ===========================================================================
# Constantes globales
# ===========================================================================

# Version du script pour suivi
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_DATE="2026-01-01"

# Chemins par défaut
readonly DEFAULT_VPN_DIR="/vpn"
readonly DEFAULT_VPN_CONF="${DEFAULT_VPN_DIR}/vpn.conf"
readonly DEFAULT_RESOLV_CONF="/etc/resolv.conf"
readonly DEFAULT_DNSMASQ_CONF="/etc/dnsmasq.conf"
readonly DEFAULT_PRIVOXY_CONF="/etc/privoxy/privoxy.config"

# DNS par défaut (AdGuard DNS - toujours valide en 2026)
readonly DEFAULT_DNS_SERVER_1="94.140.14.14"
readonly DEFAULT_DNS_SERVER_2="94.140.15.15"

# IPs de test par défaut
readonly DEFAULT_HEALTHCHECK_IP="9.9.9.9"      # Quad9
readonly DEFAULT_ROUTE_TEST_IP="9.9.9.9"        # Quad9
readonly DEFAULT_PROXY_TEST_HOST="connectivitycheck.gstatic.com"
readonly DEFAULT_PROXY_TEST_URL="http://connectivitycheck.gstatic.com/generate_204"

# Ports par défaut
readonly DEFAULT_VPN_PORT="1194"
readonly DEFAULT_VPN_PROTO="udp"
readonly DEFAULT_PROXY_PORT="3128"
readonly DEFAULT_DNS_PORT="53"
readonly DEFAULT_DOT_PORT="853"
readonly DEFAULT_METRICS_PORT="9100"

# ===========================================================================
# Validation des variables d'environnement
# ===========================================================================

# Valide qu'une variable est un nombre
# Usage: validate_number VAR_NAME VAR_VALUE
validate_number() {
    local var_name="$1"
    local var_value="$2"
    
    if [[ ! "$var_value" =~ ^[0-9]+$ ]]; then
        log_json WARN "validate_environment" \
            "Invalid ${var_name}: must be a number, got '${var_value}'" \
            "expected=number" "actual=${var_value}"
        return 1
    fi
    return 0
}

# Valide qu'une variable est un booléen
# Usage: validate_boolean VAR_NAME VAR_VALUE
validate_boolean() {
    local var_name="$1"
    local var_value="$2"
    
    case "$var_value" in
        true|false|True|False|TRUE|FALSE|1|0|yes|no|Yes|No|YES|NO)
            return 0
            ;;
        *)
            log_json WARN "validate_environment" \
                "Invalid ${var_name}: must be boolean, got '${var_value}'" \
                "expected=boolean" "actual=${var_value}"
            return 1
            ;;
    esac
}

# Valide qu'une variable est une IP valide (IPv4 ou IPv6)
# Usage: validate_ip VAR_NAME VAR_VALUE
validate_ip() {
    local var_name="$1"
    local var_value="$2"
    
    if [[ "$var_value" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    fi
    
    if [[ "$var_value" =~ ^[0-9a-fA-F:]+$ ]]; then
        return 0
    fi
    
    log_json WARN "validate_environment" \
        "Invalid ${var_name}: must be valid IP, got '${var_value}'" \
        "expected=IPv4 or IPv6" "actual=${var_value}"
    return 1
}

# Valide qu'une variable est un port valide (1-65535)
# Usage: validate_port VAR_NAME VAR_VALUE
validate_port() {
    local var_name="$1"
    local var_value="$2"
    
    if [[ "$var_value" =~ ^[0-9]+$ ]] && [ "$var_value" -ge 1 ] && [ "$var_value" -le 65535 ]; then
        return 0
    fi
    
    log_json WARN "validate_environment" \
        "Invalid ${var_name}: must be valid port (1-65535), got '${var_value}'" \
        "expected=1-65535" "actual=${var_value}"
    return 1
}

# ===========================================================================
# Logging JSON structuré (compatible avec start.sh)
# ===========================================================================

# Log un message au format JSON
# Usage: log_json LEVEL COMPONENT MESSAGE [key1=value1 key2=value2 ...]
log_json() {
    local level="$1"
    local component="$2"
    local message="$3"
    shift 3

    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local extra=""
    for kv in "$@"; do
        local k v
        k="${kv%%=*}"
        v="${kv#*=}"
        # Échapper les caractères spéciaux pour JSON
        v="${v//\\/\\\\}"
        v="${v//\"/\\\"}"
        v="${v//$'\n'/\\n}"
        v="${v//$'\t'/\\t}"
        extra="${extra}, \"${k}\": \"${v}\""
    done

    printf '{"ts":"%s","level":"%s","component":"%s","msg":"%s"%s}\n' \
        "$ts" "$level" "$component" "$message" "$extra"
}

# ===========================================================================
# Fonctions réseau
# ===========================================================================

# Trouve l'interface VPN (tun ou tap) active
# Retourne le nom de l'interface ou vide si non trouvée
# Usage: find_vpn_interface
find_vpn_interface() {
    local dev

    while read -r dev; do
        case "$dev" in
            tun*|tap*)
                # Vérifier que l'interface a une adresse IP valide
                if ip -4 addr show dev "$dev" up scope global 2>/dev/null | grep -q 'inet '; then
                    printf '%s\n' "$dev"
                    return 0
                fi
                ;;
        esac
    done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)

    return 1
}

# Vérifie si le tunnel VPN est prêt
# Usage: vpn_tunnel_ready
vpn_tunnel_ready() {
    local dev
    dev=$(find_vpn_interface) || return 1
    ip -4 addr show dev "$dev" up scope global 2>/dev/null | grep -q 'inet '
}

# Attend que le tunnel VPN soit prêt
# Usage: wait_for_vpn_tunnel TIMEOUT_SECONDS
wait_for_vpn_tunnel() {
    local timeout_s="$1"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout_s" ]; do
        if vpn_tunnel_ready; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    return 1
}

# ===========================================================================
# Fonctions DNS
# ===========================================================================

# Résout un nom d'hôte en IP en utilisant plusieurs serveurs DNS de fallback
# Usage: resolve_hostname HOSTNAME [DNS_SERVER_1 DNS_SERVER_2 ...]
resolve_hostname() {
    local hostname="$1"
    shift
    local dns_servers=("$@")
    
    # Si aucun serveur DNS fourni, utiliser les serveurs par défaut
    if [ ${#dns_servers[@]} -eq 0 ]; then
        dns_servers=("$DEFAULT_DNS_SERVER_1" "$DEFAULT_DNS_SERVER_2")
    fi

    local ip=""
    
    # Essayer avec dig d'abord
    for dns in "${dns_servers[@]}"; do
        ip=$(dig +short "$hostname" @"$dns" A 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    done
    
    # Essayer avec nslookup
    for dns in "${dns_servers[@]}"; do
        ip=$(nslookup "$hostname" "$dns" 2>/dev/null | awk '/^Address: /{ if ($2 !~ /:/) {print $2; exit} }' || true)
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    done
    
    return 1
}

# ===========================================================================
# Fonctions de gestion de processus
# ===========================================================================

# Tue un processus s'il est en cours d'exécution
# Usage: kill_if_running PID
kill_if_running() {
    local pid="$1"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
}

# Vérifie si un processus est en cours d'exécution
# Usage: is_process_running PID
is_process_running() {
    local pid="$1"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

# Attend qu'un processus se termine
# Usage: wait_for_process PID [TIMEOUT]
wait_for_process() {
    local pid="$1"
    local timeout="${2:-60}"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        if ! is_process_running "$pid"; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    return 1
}

# ===========================================================================
# Fonctions de configuration OpenVPN
# ===========================================================================

# Extrait le port et le protocole depuis la configuration OpenVPN
# Usage: get_vpn_port_proto [CONFIG_FILE]
get_vpn_port_proto() {
    local conf="${1:-$DEFAULT_VPN_CONF}"
    
    VPN_PORT="$DEFAULT_VPN_PORT"
    VPN_PROTO="$DEFAULT_VPN_PROTO"
    
    if [ -f "$conf" ]; then
        # Extraire le port depuis la directive remote
        VPN_PORT=$(awk '
            /^remote / {
                for (i=1; i<=NF; i++)
                    if ($i ~ /:/) { split($i, a, ":"); print a[2]; exit }
                if (NF >= 3) { print $3; exit }
            }' "$conf" | head -1)
        VPN_PORT=${VPN_PORT:-$DEFAULT_VPN_PORT}
        
        # Extraire le protocole
        VPN_PROTO=$(awk '/^proto /{print $2; exit}' "$conf")
        VPN_PROTO=${VPN_PROTO:-$DEFAULT_VPN_PROTO}
    fi
}

# ===========================================================================
# Fonctions de configuration dnsmasq
# ===========================================================================

# Extrait les serveurs DNS upstream depuis la configuration dnsmasq
# Usage: get_dns_upstreams [CONFIG_FILE]
get_dns_upstreams() {
    local conf="${1:-$DEFAULT_DNSMASQ_CONF}"
    [ -f "$conf" ] || return 0
    
    grep -E '^[[:space:]]*server=' "$conf" \
        | sed 's/.*server=\([^#]*\).*/\1/' \
        | awk -F'[#@]' '{print $1}'
}

# ===========================================================================
# Fonctions de configuration Privoxy
# ===========================================================================

# Extrait le port d'écoute de Privoxy depuis sa configuration
# Usage: get_privoxy_port [CONFIG_FILE]
get_privoxy_port() {
    local conf="${1:-$DEFAULT_PRIVOXY_CONF}"
    local port="$DEFAULT_PROXY_PORT"
    
    if [ -f "$conf" ]; then
        local addr
        addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' "$conf" || true)
        [ -n "$addr" ] && port=$(echo "$addr" | awk -F: '{print $NF}')
    fi
    
    echo "$port"
}

# ===========================================================================
# Fonctions de test de connectivité
# ===========================================================================

# Teste la connectivité HTTP via le proxy
# Usage: test_http_proxy [PROXY_URL] [TEST_URL]
test_http_proxy() {
    local proxy_url="${1:-http://127.0.0.1:$DEFAULT_PROXY_PORT}"
    local test_url="${2:-$DEFAULT_PROXY_TEST_URL}"
    
    if ! command -v curl >/dev/null 2>&1; then
        log_json WARN "test_http_proxy" "curl not available"
        return 1
    fi
    
    if curl -fsS --connect-timeout 3 --max-time 5 --proxy "$proxy_url" "$test_url" >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

# Teste la résolution DNS locale
# Usage: test_dns_resolution [HOSTNAME] [DNS_SERVER]
test_dns_resolution() {
    local hostname="${1:-$DEFAULT_PROXY_TEST_HOST}"
    local dns_server="${2:-127.0.0.1}"
    
    if command -v getent >/dev/null 2>&1; then
        if getent ahosts "$hostname" >/dev/null 2>&1; then
            return 0
        fi
    fi

    if command -v nslookup >/dev/null 2>&1; then
        if nslookup "$hostname" "$dns_server" >/dev/null 2>&1; then
            return 0
        fi
    elif command -v dig >/dev/null 2>&1; then
        if dig @"$dns_server" "$hostname" +short >/dev/null 2>&1; then
            return 0
        fi
    fi

    return 1
}

# ===========================================================================
# Fonctions utilitaires
# ===========================================================================

# Vérifie si une commande existe
# Usage: command_exists COMMAND
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Génère un nom de fichier temporaire unique
# Usage: temp_file [PREFIX]
temp_file() {
    local prefix="${1:-tmp}"
    mktemp "/tmp/${prefix}.XXXXXX"
}

# Lit un fichier et retourne son contenu
# Usage: read_file FILE
read_file() {
    local file="$1"
    [ -f "$file" ] && cat "$file" || echo ""
}

# Écrit dans un fichier de manière atomique
# Usage: write_file FILE CONTENT
write_file() {
    local file="$1"
    local content="$2"
    local tmp
    
    tmp=$(temp_file "write_file")
    echo "$content" > "$tmp"
    mv -f "$tmp" "$file"
}

# ===========================================================================
# Initialisation
# ===========================================================================

# Initialise les variables d'environnement avec des valeurs par défaut
# Usage: init_environment
init_environment() {
    # DNS
    : "${DNS_SERVER_1:=$DEFAULT_DNS_SERVER_1}"
    : "${DNS_SERVER_2:=$DEFAULT_DNS_SERVER_2}"
    : "${HEALTHCHECK_IP:=$DEFAULT_HEALTHCHECK_IP}"
    : "${ROUTE_TEST_IP:=$DEFAULT_ROUTE_TEST_IP}"
    
    # DoT
    : "${DOT_DNS_SERVERS:=tls://dns.adguard-dns.com,tls://dns.quad9.net}"
    : "${DOT_IP_REFRESH_INTERVAL:=3600}"
    
    # Healthcheck
    : "${SKIP_HEALTHCHECK_FIRST_MINUTES:=2}"
    
    # Chemins
    : "${conf:=$DEFAULT_VPN_CONF}"
    : "${TAILSCALE_RUN_DIR:=/var/run/tailscale}"
}

# ===========================================================================
# Fin du fichier
# ===========================================================================

# Message de fin de chargement
if [ "${COMMON_SH_LOADED:-false}" != "true" ]; then
    COMMON_SH_LOADED=true
    log_json DEBUG "common.sh" "Common functions loaded" "version=${SCRIPT_VERSION}" "date=${SCRIPT_DATE}"
fi
