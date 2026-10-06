#!/bin/bash
# ===========================================================================
# common.sh - Fonctions communes pour openvpn_client_proxy
# 
# Ce fichier contient les fonctions partagÃƒÂ©es entre start.sh et healthcheck.sh
# pour ÃƒÂ©viter la duplication de code et amÃƒÂ©liorer la maintenabilitÃƒÂ©.
# 
# Auteur: Vibe Code (amÃƒÂ©lioration 2026)
# Licence: MIT (mÃƒÂªme licence que le projet parent)
# ===========================================================================

# ===========================================================================
# Guard contre le double sourcing
# ===========================================================================
if [ -n "${COMMON_SH_LOADED+x}" ]; then
    return 0
fi
COMMON_SH_LOADED=true

# NOTE: pas de "set -e" ici : common.sh est source par le superviseur
# long-vivant, qui ne doit pas mourir sur l'echec d'une commande. Les
# scripts one-shot (healthcheck.sh) activent eux-memes le mode strict.

# ===========================================================================
# Constantes globales
# ===========================================================================

# Version du script pour suivi
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_DATE="2026-01-01"

# Chemins par dÃƒÂ©faut
readonly DEFAULT_VPN_DIR="/vpn"
readonly DEFAULT_VPN_CONF="${DEFAULT_VPN_DIR}/vpn.conf"
readonly DEFAULT_RESOLV_CONF="/etc/resolv.conf"
readonly DEFAULT_DNSMASQ_CONF="/etc/dnsmasq.conf"
readonly DEFAULT_PRIVOXY_CONF="/etc/privoxy/privoxy.config"
readonly DEFAULT_METRICS_DIR="/var/tmp/metrics"

# DNS par dÃƒÂ©faut (AdGuard DNS - toujours valide en 2026)
readonly DEFAULT_DNS_SERVER_1="94.140.14.14"
readonly DEFAULT_DNS_SERVER_2="94.140.15.15"

# IPs de test par dÃƒÂ©faut
readonly DEFAULT_HEALTHCHECK_IP="9.9.9.9"      # Quad9
readonly DEFAULT_ROUTE_TEST_IP="9.9.9.9"        # Quad9
readonly DEFAULT_PROXY_TEST_HOST="connectivitycheck.gstatic.com"
readonly DEFAULT_PROXY_TEST_URL="http://connectivitycheck.gstatic.com/generate_204"

# Ports par dÃƒÂ©faut
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

# Valide qu'une variable est un boolÃƒÂ©en
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

# Valide l'ensemble des variables d'environnement critiques
# Usage: validate_environment
validate_environment() {
    local validation_failed=0

    # Valider les ports
    validate_number "PROXY_PORT" "${PROXY_PORT:-3128}" || validation_failed=1
    validate_port "PROXY_PORT" "${PROXY_PORT:-3128}" || validation_failed=1

    # Valider les serveurs DNS
    if [ -n "${DNS_SERVER_1:-}" ]; then
        validate_ip "DNS_SERVER_1" "$DNS_SERVER_1" || validation_failed=1
    fi
    
    if [ -n "${DNS_SERVER_2:-}" ]; then
        validate_ip "DNS_SERVER_2" "$DNS_SERVER_2" || validation_failed=1
    fi

    # Valider les boolÃƒÂ©ens
    validate_boolean "ENABLE_DOT" "${ENABLE_DOT:-false}" || validation_failed=1
    validate_boolean "ENABLE_DNS_BLOCKLIST" "${ENABLE_DNS_BLOCKLIST:-false}" || validation_failed=1
    validate_boolean "ENABLE_DNSSEC" "${ENABLE_DNSSEC:-false}" || validation_failed=1

    if [ "$validation_failed" -eq 1 ]; then
        log_json WARN "validate_environment" \
            "Some environment variables are invalid - check logs above"
        return 1
    fi

    log_json INFO "validate_environment" \
        "All environment variables validated successfully"
    return 0
}

# ===========================================================================
# Logging JSON structurÃƒÂ© (compatible avec start.sh)
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
        # Ãƒâ€°chapper les caractÃƒÂ¨res spÃƒÂ©ciaux pour JSON
        v="${v//\\/\\\\}"
        v="${v//\"/\\\"}"
        v="${v//$'\n'/\\n}"
        v="${v//$'\t'/\\t}"
        extra="${extra}, \"${k}\": \"${v}\""
    done

    local escaped_message
    escaped_message="${message//\\/\\\\}"
    escaped_message="${escaped_message//\"/\\\"}"
    escaped_message="${escaped_message//$'\n'/\\n}"
    escaped_message="${escaped_message//$'\t'/\\t}"

    # stderr : stdout est parfois capte par l'appelant (build_tailscale_up_flags)
    printf '{"ts":"%s","level":"%s","component":"%s","msg":"%s"%s}\n' \
        "$ts" "$level" "$component" "$escaped_message" "$extra" >&2
}

# ===========================================================================
# Fonctions rÃƒÂ©seau
# ===========================================================================

# Trouve l'interface VPN (tun ou tap) active
# Retourne le nom de l'interface ou vide si non trouvÃƒÂ©e
# Usage: find_vpn_interface
find_vpn_interface() {
    local dev

    while read -r dev; do
        case "$dev" in
            tun*|tap*|wg*)
                # VÃƒÂ©rifier que l'interface a une adresse IP valide
                if ip -4 addr show dev "$dev" up scope global 2>/dev/null | grep -q 'inet '; then
                    printf '%s\n' "$dev"
                    return 0
                fi
                ;;
        esac
    done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)

    return 1
}

# VÃƒÂ©rifie si le tunnel VPN est prÃƒÂªt
# Usage: vpn_tunnel_ready
vpn_tunnel_ready() {
    local dev
    dev=$(find_vpn_interface) || return 1
    ip -4 addr show dev "$dev" up scope global 2>/dev/null | grep -q 'inet '
}

# Attend que le tunnel VPN soit prÃƒÂªt
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

# RÃƒÂ©sout un nom d'hÃƒÂ´te en IP en utilisant plusieurs serveurs DNS de fallback
# Retourne SEULEMENT la premiÃƒÂ¨re IP
# Usage: resolve_hostname HOSTNAME [DNS_SERVER_1 DNS_SERVER_2 ...]
resolve_hostname() {
    local hostname="$1"
    shift
    local dns_servers=("$@")
    
    # Si aucun serveur DNS fourni, utiliser les serveurs par dÃƒÂ©faut
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

# RÃƒÂ©sout un nom d'hÃƒÂ´te en TOUTES les IPs (retourne une IP par ligne)
# FIX STABILITÃƒâ€° #10 (suite): RÃƒÂ©sout TOUTES les IPs pour un hostname
# Usage: resolve_hostname_all HOSTNAME [DNS_SERVER_1 DNS_SERVER_2 ...]
resolve_vpn_ips() {
    local hostname="$1"
    shift
    local dns_servers=("$@")

    if [ ${#dns_servers[@]} -eq 0 ]; then
        dns_servers=("$DEFAULT_DNS_SERVER_1" "$DEFAULT_DNS_SERVER_2")
    fi

    local dns ips
    if command -v dig >/dev/null 2>&1; then
        # B1 : "dig host A AAAA" est invalide - seul le dernier type est
        # pris en compte (seule l'IPv6 revenait). Deux requetes explicites
        # par serveur. +time=2 +tries=1 : sinon ~4 s par serveur muet,
        # plusieurs minutes pour un .ovpn a une dizaine de remotes.
        for dns in "${dns_servers[@]}"; do
            ips=$(dig +short +time=2 +tries=1 @"$dns" "$hostname" A "$hostname" AAAA 2>/dev/null |
                grep -E '^[0-9a-fA-F.:]+$' || true)
            if [ -n "$ips" ]; then
                echo "$ips"
                return 0
            fi
        done
        return 1
    fi

    # Repli nslookup : seulement si dig est absent (3.1 - sinon on double
    # l'attente sur un DNS muet). Gerer les formats busybox ("Address 1: ip
    # host"), classic ("Addresses:  ip, ip") et ignorer le serveur lui-meme.
    # busybox nslookup n'a pas -timeout= ; on borne avec timeout(1).
    for dns in "${dns_servers[@]}"; do
        ips=$(timeout 5 nslookup "$hostname" "$dns" 2>/dev/null |
            awk -v srv="$dns" '
                /^Name:/ { inans = 1 }
                inans && /Address/ {
                    for (i = 1; i <= NF; i++) {
                        ip = $i
                        sub(/^Addresses?:?/, "", ip)
                        sub(/^[0-9]+:/, "", ip)
                        sub(/,$/, "", ip)
                        if (ip != srv && ip != "" && ip ~ /^[0-9a-fA-F.:]+$/ && ip !~ /#/) print ip
                    }
                }' || true)
        if [ -n "$ips" ]; then
            echo "$ips"
            return 0
        fi
    done

    return 1
}

resolve_hostname_all() {
    local hostname="$1"
    shift
    local dns_servers=("$@")
    
    # Si aucun serveur DNS fourni, utiliser les serveurs par dÃƒÂ©faut
    if [ ${#dns_servers[@]} -eq 0 ]; then
        dns_servers=("$DEFAULT_DNS_SERVER_1" "$DEFAULT_DNS_SERVER_2")
    fi

    local ips=""
    
    # Essayer avec dig d'abord - retourne TOUTES les IPs
    for dns in "${dns_servers[@]}"; do
        ips=$(dig +short "$hostname" @"$dns" A 2>/dev/null | grep -E '^[0-9.]+$' || true)
        if [ -n "$ips" ]; then
            echo "$ips"
            return 0
        fi
    done
    
    # Essayer avec nslookup - retourne TOUTES les IPs
    for dns in "${dns_servers[@]}"; do
        ips=$(nslookup "$hostname" "$dns" 2>/dev/null | awk '/^Address: /{ if ($2 !~ /:/) print $2 }' || true)
        if [ -n "$ips" ]; then
            echo "$ips"
            return 0
        fi
    done
    
    return 1
}

# ===========================================================================
# Fonctions de gestion de processus
# ===========================================================================

# Tue un processus s'il est en cours d'exÃƒÂ©cution
# Usage: kill_if_running PID
kill_if_running() {
    local pid="${1:-}"
    # Refuse vide, 0 et non numerique : "kill 0" tuerait tout le groupe
    # de processus de l'appelant (superviseur) et arreterait le conteneur.
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0
    kill "$pid" 2>/dev/null || true
}

# VÃƒÂ©rifie si un processus est en cours d'exÃƒÂ©cution
# Usage: is_process_running PID
is_process_running() {
    local pid="${1:-}"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null
}

# Attend qu'un processus se termine
# Usage: wait_for_process PID [TIMEOUT]
wait_for_process() {
    local pid="${1:-}"
    local timeout="${2:-60}"

    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0
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

# Extract port and protocol from VPN configuration (OpenVPN or WireGuard)
# Usage: get_vpn_port_proto [CONFIG_FILE]
get_vpn_port_proto() {
    local conf="${1:-$DEFAULT_VPN_CONF}"
    
    VPN_PORT="$DEFAULT_VPN_PORT"
    VPN_PROTO="$DEFAULT_VPN_PROTO"
    
    # If VPN_TYPE is wireguard, set WireGuard-specific values
    if [ "${VPN_TYPE:-openvpn}" = "wireguard" ]; then
        VPN_PORT="51820"
        VPN_PROTO="udp"
        return 0
    fi
    
    # Otherwise, extract from OpenVPN configuration
    if [ -f "$conf" ]; then
        # Extract port from remote directive
        VPN_PORT=$(awk '
            /^remote / {
                for (i=1; i<=NF; i++)
                    if ($i ~ /:/) { split($i, a, ":"); print a[2]; exit }
                if (NF >= 3) { print $3; exit }
            }' "$conf" | head -1)
        VPN_PORT=${VPN_PORT:-$DEFAULT_VPN_PORT}
        
        # Extract protocol
        VPN_PROTO=$(awk '/^proto /{print $2; exit}' "$conf")
        VPN_PROTO=${VPN_PROTO:-$DEFAULT_VPN_PROTO}
    fi

    # Normalisation pour iptables : udp4/tcp4/udp6/tcp6/tcp-client/-server
    case "$VPN_PROTO" in
        udp*) VPN_PROTO="udp" ;;
        tcp*) VPN_PROTO="tcp" ;;
        *) VPN_PROTO="$DEFAULT_VPN_PROTO" ;;
    esac
}

# Extrait les endpoints (remote) d'une configuration OpenVPN.
# Robuste (R3) : ignore les CR (fichiers .ovpn Windows), gere la directive
# "port", un remote sans port explicite (port par defaut de la conf, sinon
# 1194), et normalise le protocole (udp/tcp, suffixes 4/6/-client/-server).
# Emets "ip port proto" par remote (port jamais vide).
# Usage: parse_vpn_remotes [CONFIG_FILE]
parse_vpn_remotes() {
    local conf="${1:-$DEFAULT_VPN_CONF}"
    [ -f "$conf" ] || return 0

    # B5 : deux passes - la 1re memorise les valeurs par defaut (port/proto)
    # quel que soit leur ordre par rapport aux remote. Les valeurs portees
    # par la ligne remote elle-meme ont toujours priorite (norme OpenVPN).
    # 3.3 : les blocs <connection> portent leurs propres port/proto -
    # memoriser les valeurs PAR BLOC en 1re passe et les restituer en 2e,
    # sinon le 1er bloc herite des valeurs du dernier (regle fausse ->
    # remote bloque par le kill switch).
    awk '
        function emit(host, port, proto) {
            if (port == "") port = "1194"
            if (proto == "") proto = "udp"
            # Normalisation : udp4/udp6/tcp4/tcp6/tcp-client/tcp-server -> udp/tcp
            if (proto ~ /^udp/) proto = "udp"
            else if (proto ~ /^tcp/) proto = "tcp"
            else return
            print host, port, proto
        }
        # v6-3.2 : BOM UTF-8 - sinon la 1re directive du fichier
        # nest pas reconnue. Le sub est inconditionnel et sans effet
        # sur les lignes suivantes.
        { sub(/^\xef\xbb\xbf/, ""); sub(/\r$/, "") }
        FNR == NR {
            if ($1 == "<connection>") { inblock = 1; bport = ""; bproto = ""; brport = ""; blkstart = nblk + 1 }
            if ($1 == "</connection>") {
                for (i = blkstart; i <= nblk; i++) { blkport[i] = bport; blkproto[i] = bproto; blkrport[i] = brport }
                inblock = 0
            }
            if ($1 == "port" && $2 != "") {
                if (inblock) bport = $2; else dport = $2
            }
            # v6-3.1 : rport fixe le port DISTANT (prioritaire sur port)
            if ($1 == "rport" && $2 != "") {
                if (inblock) brport = $2; else drport = $2
            }
            if ($1 == "proto" && $2 != "") {
                if (inblock) bproto = $2; else dproto = $2
            }
            if ($1 == "remote" && inblock) { nblk++ }
            next
        }
        $1 == "<connection>" { inblock2 = 1; next }
        $1 == "</connection>" { inblock2 = 0; next }
        $1 == "remote" {
            host = $2
            if (inblock2) {
                # v5-3.2 : une option absente du bloc herite de la valeur
                # globale (norme OpenVPN) - sinon proto tcp global + bloc
                # sans proto donnait udp (regle fausse, VPN bloque).
                k = ++blkseen
                proto = blkproto[k]
                if (proto == "") proto = dproto
                # v7 : resolution du port PAR PORTEE, la plus locale lemporte
                # (rport = port distant explicite, prioritaire sur port dans
                # la meme portee). v6 applait rport global en fin de calcul
                # et ecrasait le port propre au bloc.
                if (blkrport[k] != "") port = blkrport[k]
                else if (blkport[k] != "") port = blkport[k]
                else if (drport != "") port = drport
                else port = dport
            } else {
                proto = dproto
                if (drport != "") port = drport
                else port = dport
            }
            # Un port explicite sur la ligne remote reste au-dessus de tout
            # (norme OpenVPN).
            if ($3 ~ /^[0-9]+$/) {
                port = $3
                if ($4 != "") proto = $4
            } else if ($3 != "") {
                proto = $3
            }
            emit(host, port, proto)
        }' "$conf" "$conf"
}

# Extrait le port et protocole de l'Endpoint WireGuard (wg0.conf)
# Usage: get_wireguard_endpoint [CONFIG_FILE]
get_wireguard_endpoint() {
    local conf="${1:-${VPN_DIR}/wg0.conf}"
    [ -f "$conf" ] || return 1

    awk -F'=' '
        /^[[:space:]]*Endpoint[[:space:]]*=/ {
            ep = $2
            gsub(/[[:space:]]/, "", ep)
            # B4/§4-4 : "host:port" pour IPv4/hostname, "[v6]:port" pour IPv6.
            # L ancien split(:) cassait sur les adresses IPv6.
            if (ep ~ /^\[/) {
                match(ep, /^\[[^]]*\]/)
                host = substr(ep, 2, RLENGTH - 2)
                port = substr(ep, RLENGTH + 2)
            } else {
                n = split(ep, a, ":")
                host = a[1]
                port = (n > 1) ? a[n] : ""
            }
            print host, port
            exit
        }' "$conf"
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

# Extrait le port d'ÃƒÂ©coute de Privoxy depuis sa configuration
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
# Fonctions de test de connectivitÃƒÂ©
# ===========================================================================

# Teste la connectivitÃƒÂ© HTTP via le proxy
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

# Teste la rÃƒÂ©solution DNS locale
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

# VÃƒÂ©rifie si une commande existe
# Usage: command_exists COMMAND
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# GÃƒÂ©nÃƒÂ¨re un nom de fichier temporaire unique
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

# Ãƒâ€°crit dans un fichier de maniÃƒÂ¨re atomique
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

# Initialise les variables d'environnement avec des valeurs par dÃƒÂ©faut
# Usage: init_environment
init_environment() {
    # VPN configuration
    : "${VPN_TYPE:=openvpn}"
    : "${OPENVPN_ENABLED:=true}"
    : "${WIREGUARD_ENABLED:=false}"
    : "${VPN_PROTO:=$DEFAULT_VPN_PROTO}"
    : "${VPN_PORT:=$DEFAULT_VPN_PORT}"
    : "${VPN_TYPE_SELECTED:=${VPN_TYPE}}"
    
    # Proxy configuration
    : "${PROXY_PORT:=$DEFAULT_PROXY_PORT}"
    : "${PROXY_USER:=}"
    : "${PROXY_PASS:=}"
    : "${PROXY_PROFILE:=normal}"
    : "${ALLOW_EXTERNAL_PROXY_ACCESS:=false}"
    : "${PROXY_TEST_HOST:=$DEFAULT_PROXY_TEST_HOST}"
    : "${PROXY_TEST_URL:=$DEFAULT_PROXY_TEST_URL}"
    
    # DNS
    : "${DNS_SERVER_1:=$DEFAULT_DNS_SERVER_1}"
    : "${DNS_SERVER_2:=$DEFAULT_DNS_SERVER_2}"
    : "${DNS_PORT:=$DEFAULT_DNS_PORT}"
    : "${HEALTHCHECK_IP:=$DEFAULT_HEALTHCHECK_IP}"
    : "${ROUTE_TEST_IP:=$DEFAULT_ROUTE_TEST_IP}"
    
    # DoT
    : "${ENABLE_DOT:=false}"
    : "${DOT_DNS_SERVERS:=tls://dns.adguard-dns.com,tls://dns.quad9.net}"
    : "${DOT_IP_REFRESH_INTERVAL:=3600}"
    : "${DOT_PORT:=$DEFAULT_DOT_PORT}"
    : "${ENABLE_DNSSEC:=false}"
    : "${DOT_TLS_CERT_BUNDLE:=}"
    : "${DNS_SPLIT:=}"

    # Blocage DNS pub/tracking
    : "${ENABLE_DNS_BLOCKLIST:=false}"
    : "${DNS_BLOCKLIST_URLS:=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts}"
    : "${DNS_BLOCKLIST_REFRESH_INTERVAL:=86400}"
    : "${DNS_BLOCKLIST_MIN_AGE:=3600}"
    : "${DNS_BLOCKLIST_ALLOWLIST:=}"
    
    # Healthcheck
    : "${SKIP_HEALTHCHECK_FIRST_MINUTES:=2}"
    
    # Tailscale
    : "${ENABLE_TAILSCALE:=false}"
    : "${TAILSCALE_AUTHKEY:=}"
    : "${TAILSCALE_FLAGS:=}"
    : "${TAILSCALE_ACCEPT_ROUTES:=false}"
    : "${TAILSCALE_HOSTNAME:=openvpn-client-proxy}"
    : "${TAILSCALE_ADVERTISE_EXIT_NODE:=false}"
    
    # Metrics
    : "${ENABLE_METRICS:=false}"
    : "${METRICS_PORT:=$DEFAULT_METRICS_PORT}"
    : "${METRIC_VPN_UP:=0}"
    : "${METRIC_RESTART_COUNT:=0}"
    : "${METRIC_DOT_ACTIVE:=0}"
    : "${METRIC_START_TS:=$(date +%s)}"
    : "${METRIC_LAST_RESTART_TS:=0}"
    
    # Security
    : "${DROP_CAPS:=false}"
    : "${PROXY_RUN_USER:=vpn}"
    : "${PROXY_ALLOW_PRIVATE_NETWORKS:=false}"
    
    # Directories and file paths
    : "${VPN_DIR:=$DEFAULT_VPN_DIR}"
    : "${VPN_CONF:=$DEFAULT_VPN_CONF}"
    : "${conf:=$VPN_CONF}"
    : "${TAILSCALE_RUN_DIR:=/var/run/tailscale}"
    : "${METRICS_DIR:=$DEFAULT_METRICS_DIR}"
    : "${VPN_HEALTHY_FILE:=/tmp/vpn_healthy}"
    : "${RESOLV_CONF:=$DEFAULT_RESOLV_CONF}"
    : "${DNSMASQ_CONF:=$DEFAULT_DNSMASQ_CONF}"
    : "${PRIVOXY_CONF:=$DEFAULT_PRIVOXY_CONF}"
    : "${DOT_IP_MAP_FILE:=/tmp/dot_ip_map}"
    : "${DOT_FORWARD_ADDRS_FILE:=/tmp/dot_forward_addrs}"
    : "${UNBOUND_CONF:=/etc/unbound/unbound.conf}"
    : "${DNS_BLOCKLIST_COMPILED_UNBOUND:=/tmp/dns_blocklist_unbound.conf}"
    : "${DNS_BLOCKLIST_COMPILED_DNSMASQ:=/tmp/dns_blocklist_dnsmasq.conf}"
    : "${DNS_BLOCKLIST_RAW_DIR:=/tmp/dns_blocklist_raw}"
    : "${DNS_BLOCKLIST_STATE_FILE:=/tmp/dns_blocklist_last_download}"

    # Global maps/counters must be initialized for strict mode (set -u).
    declare -gA SERVICE_PIDS
    declare -gA DOT_HOST_IP_MAP

    : "${DOT_RESOLVED_IPS:=}"

    SERVICE_PIDS[vpn]="${SERVICE_PIDS[vpn]:-0}"
    SERVICE_PIDS[privoxy]="${SERVICE_PIDS[privoxy]:-0}"
    SERVICE_PIDS[nginx]="${SERVICE_PIDS[nginx]:-0}"
    SERVICE_PIDS[dnsmasq]="${SERVICE_PIDS[dnsmasq]:-0}"
    SERVICE_PIDS[unbound]="${SERVICE_PIDS[unbound]:-0}"
    SERVICE_PIDS[tailscaled]="${SERVICE_PIDS[tailscaled]:-0}"
    SERVICE_PIDS[metrics]="${SERVICE_PIDS[metrics]:-0}"
    SERVICE_PIDS[dot_refresh]="${SERVICE_PIDS[dot_refresh]:-0}"
    SERVICE_PIDS[blocklist_refresh]="${SERVICE_PIDS[blocklist_refresh]:-0}"
}

# ===========================================================================
# Fin du fichier
# ===========================================================================

# Message de fin de chargement
if [ "${COMMON_SH_LOADED+x}" != "true" ]; then
    COMMON_SH_LOADED=true
    log_json DEBUG "common.sh" "Common functions loaded" "version=${SCRIPT_VERSION}" "date=${SCRIPT_DATE}"
fi
