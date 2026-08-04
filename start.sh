#!/bin/bash
set -euo pipefail

# =============================================================================
# Superviseur VPN + Proxy + DNS (DoT) + Tailscale
# ----------------------------------------------------------------------------
# Variables d'environnement principales :
#   - ENABLE_DOT=true/false          : Active DNS-over-TLS (Unbound)
#   - DOT_DNS_SERVERS="tls://dns.adguard-dns.com" : Serveurs DoT (séparés par ",")
#   - DOT_IP_REFRESH_INTERVAL=3600   : Intervalle de rafraîchissement des IPs DoT (s)
#   - ENABLE_DNSSEC=true/false       : Active la validation DNSSEC (Unbound)
#   - DOT_TLS_CERT_BUNDLE="/chemin/ca-certificates.crt" : Bundle de certs TLS
#   - DNS_SERVER_1="9.9.9.9"          : Serveur DNS primaire (mode non-DoT)
#   - DNS_SERVER_2="149.112.112.112" : Serveur DNS secondaire (mode non-DoT)
#   - DNS_SPLIT="corp.local=10.0.0.53" : Split DNS (domaine=resolver, séparé par ",")
#   - PROXY_USER="user"              : Utilisateur pour l'auth proxy (optionnel)
#   - PROXY_PASS="pass"              : Mot de passe pour l'auth proxy (optionnel)
#   - ENABLE_TAILSCALE=true/false    : Active Tailscale
#   - TAILSCALE_AUTHKEY="tskey-..."  : Clé d'authentification Tailscale
#   - TAILSCALE_ACCEPT_ROUTES=true   : Accepte les routes Tailscale
#   - TAILSCALE_HOSTNAME="mon-host"  : Nom d'hôte Tailscale
#   - ENABLE_METRICS=true/false      : Active l'endpoint Prometheus (127.0.0.1:9100)
#   - DROP_CAPS=true/false           : Supprime les capabilities Linux inutiles
#   - ROUTE_TEST_IP="9.9.9.9"        : IP pour tester la connectivité VPN
#   - TAILSCALE_RUN_DIR="/var/run/tailscale" : Répertoire de runtime Tailscale
# =============================================================================

# --- Constantes ----------------------------------------------------------------
readonly DEFAULT_VPN_PORT=1194
readonly DEFAULT_VPN_PROTO="udp"
readonly DEFAULT_DNS_SERVER_1="94.140.14.14"
readonly DEFAULT_DNS_SERVER_2="94.140.15.15"
readonly DEFAULT_DOT_DNS_SERVERS="tls://dns.adguard-dns.com"
readonly DEFAULT_ROUTE_TEST_IP="9.9.9.9"
readonly DEFAULT_DOT_IP_REFRESH_INTERVAL=3600

# --- Chemins ----------------------------------------------------------------
readonly CONF_VPN="/vpn/vpn.conf"
readonly TAILSCALE_RUN_DIR="${TAILSCALE_RUN_DIR:-/var/run/tailscale}"
readonly DOT_IP_MAP_FILE="/tmp/dot_ip_map"          # Persistance des IPs DoT
readonly DOT_FORWARD_ADDRS_FILE="/tmp/dot_forward_addrs" # Forwarders Unbound
readonly METRICS_DIR="/tmp"                        # Fichiers de métriques

# --- PIDs des services (initialisés à vide) --------------------------------------
vpn_pid=""
privoxy_pid=""
nginx_pid=""
dnsmasq_pid=""
tailscaled_pid=""
unbound_pid=""
metrics_pid=""
dot_refresh_pid=""

# --- Métriques Prometheus --------------------------------------------------------
METRIC_RESTART_COUNT=0
METRIC_VPN_UP=0
METRIC_DOT_ACTIVE=0
METRIC_LAST_RESTART_TS=0
METRIC_START_TS=$(date +%s)

# --- Variables DoT --------------------------------------------------------------
DOT_RESOLVED_IPS=""
declare -A DOT_HOST_IP_MAP  # Map host → IP (IPv4 uniquement)

# =============================================================================
# Fonctions utilitaires
# =============================================================================

# --- Logging JSON structuré ------------------------------------------------------
# Usage: log_json LEVEL component "message" [key=value ...]
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
        # Échappement des caractères spéciaux pour JSON
        v="${v//\\/\\\\}"
        v="${v//\"/\\\"}"
        v="${v//$'\n'/\\n}"
        extra="${extra}, \"${k}\": \"${v}\""
    done

    # Suppression de la virgule initiale si aucun extra
    extra="${extra#, }"
    printf '{"ts":"%s","level":"%s","component":"%s","msg":"%s"%s}\n' \
        "$ts" "$level" "$component" "$message" "$extra"
}

# --- Vérification des dépendances ------------------------------------------------
require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_json ERROR "dependencies" "command not found: ${cmd}" "required_by=${2:-global}"
        return 1
    fi
    return 0
}

# --- Validation d'une IP (IPv4 ou IPv6) --------------------------------------------
is_ipv4() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

is_ipv6() {
    [[ "$1" =~ ^[0-9a-fA-F:]+: ]]
}

# --- Gestion des PIDs ------------------------------------------------------------
kill_if_running() {
    local pid="$1"
    if [[ -n "$pid" && -e "/proc/$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

# --- Récupération du port/protocole VPN depuis la config OpenVPN ------------------
get_vpn_port_proto() {
    local port="${DEFAULT_VPN_PORT}"
    local proto="${DEFAULT_VPN_PROTO}"

    if [[ -f "$CONF_VPN" ]]; then
        # Extraction du port (supporte les formats: "remote host:port" ou "remote host port")
        port=$(awk '
            /^remote / {
                for (i=1; i<=NF; i++) {
                    if ($i ~ /:/) {
                        split($i, a, ":");
                        print a[2];
                        exit;
                    }
                }
                if (NF >= 3) {
                    print $3;
                    exit;
                }
            }' "$CONF_VPN" | head -1) || true

        port="${port:-$DEFAULT_VPN_PORT}"

        # Extraction du protocole
        proto=$(awk '/^proto /{print $2; exit}' "$CONF_VPN") || true
        proto="${proto:-$DEFAULT_VPN_PROTO}"
    fi

    echo "$port $proto"
}

# --- Récupération des upstreams DNS depuis dnsmasq.conf --------------------------
get_dns_upstreams() {
    [[ -f /etc/dnsmasq.conf ]] || return 0
    grep -E '^[[:space:]]*server=' /etc/dnsmasq.conf | \
        sed 's/.*server=\([^#]*\).*/\1/' | \
        awk -F'[#@]' '{print $1}'
}

# --- Vérification de la connectivité VPN (IP publique) ---------------------------
check_vpn_ip() {
    require_command curl || return 0

    local proxy_port=3128
    if [[ -f /etc/privoxy/privoxy.config ]]; then
        local addr
        addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' /etc/privoxy/privoxy.config || true)
        [[ -n "$addr" ]] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
    fi

    local public_ip
    local proxy_url="http://127.0.0.1:${proxy_port}"
    if [[ -n "${PROXY_USER:-}" && -n "${PROXY_PASS:-}" ]]; then
        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${proxy_port}"
    fi

    public_ip=$(curl -fsS --max-time 10 --proxy "$proxy_url" \
        https://api.ipify.org 2>/dev/null || true)

    if [[ -n "$public_ip" ]]; then
        log_json INFO check_vpn_ip "public IP via VPN confirmed" "ip=${public_ip}"
        METRIC_VPN_UP=1
    else
        log_json WARN check_vpn_ip "could not determine public IP (tunnel may still be initializing)"
        METRIC_VPN_UP=0
    fi
}

# =============================================================================
# Firewall (IPv4)
# =============================================================================

# --- Ajout/Suppression de règles pour le port 853 (DoT) --------------------------
ipt6() {
    command -v ip6tables >/dev/null 2>&1 || return 0
    ip6tables "$@" 2>/dev/null || true
}

ipt_add_853() {
    local ip="$1"
    if [[ "$ip" =~ : ]]; then
        ipt6 -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
    else
        iptables -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
    fi
}

ipt_del_853() {
    local ip="$1"
    if [[ "$ip" =~ : ]]; then
        ipt6 -D OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
    else
        iptables -D OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
    fi
}

# --- Configuration complète d'iptables -----------------------------------------
setup_iptables() {
    local docker_network
    docker_network=$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet"{print $4}' || true)

    local vpn_port vpn_proto
    read -r vpn_port vpn_proto <<< "$(get_vpn_port_proto)"

    # Réinitialisation des règles
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Règles INPUT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    [[ -n "$docker_network" ]] && iptables -A INPUT -s "$docker_network" -j ACCEPT

    # Règles FORWARD
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i lo -j ACCEPT
    [[ -n "$docker_network" ]] && iptables -A FORWARD -s "$docker_network" -j ACCEPT
    [[ -n "$docker_network" ]] && iptables -A FORWARD -d "$docker_network" -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i tap+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Règles OUTPUT (interfaces)
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tun+ -j ACCEPT
    iptables -A OUTPUT -o tap+ -j ACCEPT
    iptables -A OUTPUT -o tailscale+ -j ACCEPT
    [[ -n "$docker_network" ]] && iptables -A OUTPUT -d "$docker_network" -j ACCEPT

    # OUTPUT: Métriques locales (loopback)
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 9100 -j ACCEPT

    # OUTPUT: DNS local (dnsmasq/unbound)
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 5053 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 5053 -j ACCEPT

    # OUTPUT: DoT (TCP/853)
    if [[ "${ENABLE_DOT:-false}" = "true" ]]; then
        if [[ -n "$DOT_RESOLVED_IPS" ]]; then
            for dot_ip in $DOT_RESOLVED_IPS; do
                ipt_add_853 "$dot_ip"
                log_json INFO setup_iptables "DoT: allowing TCP 853" "ip=${dot_ip}"
            done
        else
            log_json WARN setup_iptables "DoT: no resolved IPs — TCP 853 not explicitly allowed"
        fi
        # Kill switch DoT: bloquer tout DNS externe (port 53)
        iptables -A OUTPUT -p udp ! -d 127.0.0.0/8 --dport 53 -j DROP
        iptables -A OUTPUT -p tcp ! -d 127.0.0.0/8 --dport 53 -j DROP
        log_json INFO setup_iptables "DoT DNS leak prevention: external port 53 blocked"
    else
        # Mode non-DoT: autoriser DNS_SERVER_1/2 + upstreams dnsmasq
        for dns in "${DNS_SERVER_1:-$DEFAULT_DNS_SERVER_1}" "${DNS_SERVER_2:-$DEFAULT_DNS_SERVER_2}"; do
            [[ "$dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
            log_json INFO setup_iptables "allowing port 53" "ip=${dns}"
        done
        # Autoriser les upstreams dnsmasq (si différents de DNS_SERVER_1/2)
        while read -r dns; do
            [[ "$dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams)
    fi

    # OUTPUT: DNS Docker interne (127.0.0.11)
    if grep -Fq "127.0.0.11" /etc/resolv.conf 2>/dev/null; then
        iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT
        iptables -A OUTPUT -p udp -d 127.0.0.11 --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d 127.0.0.11 --dport 53 -j ACCEPT
    fi

    # OUTPUT: OpenVPN
    iptables -A OUTPUT -p "$vpn_proto" --dport "$vpn_port" -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true

    # NAT
    iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    log_json INFO setup_iptables "IPv4 configured — kill switch active" \
        "vpn_proto=${vpn_proto}" "vpn_port=${vpn_port}"
}

# =============================================================================
# Firewall (IPv6)
# =============================================================================

setup_ip6tables() {
    if ! command -v ip6tables >/dev/null 2>&1; then
        log_json WARN setup_ip6tables "ip6tables not installed, skipping"
        return 0
    fi
    if [[ ! -f /proc/net/if_inet6 ]]; then
        log_json WARN setup_ip6tables "IPv6 not available, skipping"
        return 0
    fi

    local docker6_network
    docker6_network=$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet6"{print $4; exit}' || true)

    local vpn_port vpn_proto
    read -r vpn_port vpn_proto <<< "$(get_vpn_port_proto)"

    ipt6 -F
    ipt6 -X
    ipt6 -t nat -F
    ipt6 -P INPUT DROP
    ipt6 -P FORWARD DROP
    ipt6 -P OUTPUT DROP

    # Règles INPUT
    ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A INPUT -p icmpv6 -j ACCEPT
    ipt6 -A INPUT -i lo -j ACCEPT
    [[ -n "$docker6_network" ]] && ipt6 -A INPUT -s "$docker6_network" -j ACCEPT

    # Règles FORWARD
    ipt6 -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -p icmpv6 -j ACCEPT
    ipt6 -A FORWARD -i lo -j ACCEPT
    [[ -n "$docker6_network" ]] && ipt6 -A FORWARD -s "$docker6_network" -j ACCEPT
    [[ -n "$docker6_network" ]] && ipt6 -A FORWARD -d "$docker6_network" -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    ipt6 -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i tap+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Règles OUTPUT
    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A OUTPUT -o lo -j ACCEPT
    ipt6 -A OUTPUT -o tun+ -j ACCEPT
    ipt6 -A OUTPUT -o tap+ -j ACCEPT
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT
    [[ -n "$docker6_network" ]] && ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT

    # OUTPUT: Métriques locales (loopback IPv6)
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 9100 -j ACCEPT

    # OUTPUT: DNS local (loopback IPv6)
    ipt6 -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p udp -d ::1 --dport 5053 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 5053 -j ACCEPT

    # OUTPUT: DoT (kill switch)
    if [[ "${ENABLE_DOT:-false}" = "true" ]]; then
        ipt6 -A OUTPUT -p udp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true
        ipt6 -A OUTPUT -p tcp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true
        log_json INFO setup_ip6tables "DoT DNS leak prevention: IPv6 port 53 blocked"
    else
        # Autoriser les upstreams DNS (IPv6)
        while read -r dns; do
            [[ "$dns" =~ : ]] || continue
            ipt6 -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            ipt6 -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams)
    fi

    # OUTPUT: OpenVPN
    ipt6 -A OUTPUT -p "$vpn_proto" --dport "$vpn_port" -j ACCEPT
    ipt6 -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT
    ipt6 -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT

    # NAT
    ipt6 -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    ipt6 -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    log_json INFO setup_ip6tables "IPv6 configured — kill switch active"
}

# =============================================================================
# Routes retour (pour éviter les fuites DNS)
# =============================================================================

setup_return_routes() {
    local iface gw gw6 ips ip6s
    iface=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}' || true)

    if [[ -z "$iface" ]]; then
        log_json WARN setup_return_routes "no default interface found, skipping"
        return 0
    fi

    gw=$(ip -4 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}' || true)
    gw6=$(ip -6 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}' || true)
    ips=$(ip -4 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet /{print $3}' || true)
    ip6s=$(ip -6 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet6.*global/{print $3}' || true)

    # IPv4
    for ip in $ips; do
        if ! ip -4 rule show table 10 2>/dev/null | grep -q "$ip"; then
            ip rule add from "$ip" lookup 10 2>/dev/null || true
        fi
        if ! iptables -C INPUT -d "$ip" -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -d "$ip" -j ACCEPT
        fi
    done
    if [[ -n "$gw" && ! $(ip -4 route show table 10 2>/dev/null | grep -q "default") ]]; then
        ip route add default via "$gw" table 10 2>/dev/null || true
    fi

    # IPv6
    for ip6 in $ip6s; do
        if ! ip -6 rule show table 10 2>/dev/null | grep -q "$ip6"; then
            ip -6 rule add from "$ip6" lookup 10 2>/dev/null || true
        fi
        if ! ipt6 -C INPUT -d "$ip6" -j ACCEPT 2>/dev/null; then
            ipt6 -A INPUT -d "$ip6" -j ACCEPT
        fi
    done
    if [[ -n "$gw6" && ! $(ip -6 route show table 10 2>/dev/null | grep -q "default") ]]; then
        ip -6 route add default via "$gw6" table 10 2>/dev/null || true
    fi

    log_json INFO setup_return_routes "return routes configured" "iface=${iface}"
}

# =============================================================================
# DNS-over-TLS (Unbound)
# =============================================================================

# --- Gestion de la map host → IP (DoT) ------------------------------------------
dot_ip_map_set() {
    local host="$1"
    local ip="$2"
    DOT_HOST_IP_MAP["$host"]="$ip"
    # Écriture atomique (tmp + mv)
    local tmp
    tmp=$(mktemp /tmp/dot_ip_map.XXXXXX)
    [[ -f "$DOT_IP_MAP_FILE" ]] && grep -v "^${host}=" "$DOT_IP_MAP_FILE" > "$tmp" || true
    echo "${host}=${ip}" >> "$tmp"
    mv -f "$tmp" "$DOT_IP_MAP_FILE"
}

dot_ip_map_get() {
    local host="$1"
    # Priorité: mémoire (process courant) > fichier (subshells)
    if [[ -n "${DOT_HOST_IP_MAP[$host]:-}" ]]; then
        echo "${DOT_HOST_IP_MAP[$host]}"
    elif [[ -f "$DOT_IP_MAP_FILE" ]]; then
        grep "^${host}=" "$DOT_IP_MAP_FILE" | cut -d= -f2- | tail -1
    fi
}

# --- Résolution des serveurs DoT (avant que dnsmasq ne modifie resolv.conf) -----
parse_dot_servers() {
    local servers="${DOT_DNS_SERVERS:-$DEFAULT_DOT_DNS_SERVERS}"
    servers=$(echo "$servers" | tr ',' ' ')
    local tmp_map tmp_forward
    tmp_map=$(mktemp /tmp/dot_ip_map.XXXXXX)
    tmp_forward=$(mktemp /tmp/dot_forward_addrs.XXXXXX)

    DOT_RESOLVED_IPS=""
    DOT_HOST_IP_MAP=()

    for entry in $servers; do
        local proto host ip
        proto=$(echo "$entry" | awk -F'://' '{print $1}')
        host=$(echo "$entry" | sed 's|^[a-z]*://||' | awk -F'[:/]' '{print $1}')
        [[ -z "$host" ]] && continue

        # Résolution IPv4 uniquement (Unbound a do-ip6:no)
        ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '/STREAM/{print $1; exit}' || true)
        if [[ -z "$ip" ]]; then
            ip=$(nslookup "$host" 2>/dev/null | awk '/^Address: /{ if ($2 !~ /:/) {print $2; exit} }' || true)
        fi

        # Fallback: résolution via DNS_SERVER_1/2 (si dnsmasq n'est pas encore lancé)
        if [[ -z "$ip" ]]; then
            for dns in "${DNS_SERVER_1:-$DEFAULT_DNS_SERVER_1}" "${DNS_SERVER_2:-$DEFAULT_DNS_SERVER_2}"; do
                [[ -z "$dns" ]] && continue
                ip=$(nslookup "$host" "$dns" 2>/dev/null | awk '/^Address: /{ if ($2 !~ /:/) {print $2; exit} }' || true)
                if [[ -n "$ip" ]]; then
                    log_json WARN parse_dot_servers "resolved via fallback DNS_SERVER (IPv4)" "host=${host}" "ip=${ip}" "via=${dns}"
                    break
                fi
            done
        fi

        if [[ -n "$ip" ]]; then
            DOT_RESOLVED_IPS="${DOT_RESOLVED_IPS}${ip} "
            DOT_HOST_IP_MAP["$host"]="$ip"
            echo "${host}=${ip}" >> "$tmp_map"
            if [[ "$proto" = "https" ]]; then
                echo "        forward-addr: ${ip}@443#${host}" >> "$tmp_forward"
            else
                echo "        forward-addr: ${ip}@853#${host}" >> "$tmp_forward"
            fi
            log_json INFO parse_dot_servers "resolved" "host=${host}" "ip=${ip}" "proto=${proto}"
        else
            log_json WARN parse_dot_servers "could not resolve, skipping" "host=${host}"
        fi
    done

    # Persistance des résultats
    [[ -s "$tmp_map" ]] && mv -f "$tmp_map" "$DOT_IP_MAP_FILE" || rm -f "$tmp_map"
    [[ -s "$tmp_forward" ]] && mv -f "$tmp_forward" "$DOT_FORWARD_ADDRS_FILE" || rm -f "$tmp_forward"
}

# --- Configuration d'Unbound ----------------------------------------------------
configure_unbound() {
    [[ "${ENABLE_DOT:-false}" = "true" ]] || return 0

    if ! command -v unbound >/dev/null 2>&1; then
        log_json ERROR configure_unbound "unbound binary not found — DoT disabled"
        return 1
    fi

    # Résolution des IPs DoT (appel direct pour peupler DOT_RESOLVED_IPS)
    parse_dot_servers

    if [[ ! -s "$DOT_FORWARD_ADDRS_FILE" ]]; then
        log_json ERROR configure_unbound "no valid DoT servers parsed — DoT disabled"
        return 1
    fi

    local forward_addrs
    forward_addrs=$(cat "$DOT_FORWARD_ADDRS_FILE")

    # DNSSEC: permissif par défaut, strict si ENABLE_DNSSEC=true
    local dnssec_mode="val-permissive-mode: yes"
    if [[ "${ENABLE_DNSSEC:-false}" = "true" ]]; then
        dnssec_mode="val-permissive-mode: no"
        mkdir -p /var/lib/unbound
        chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true
        unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
        log_json INFO configure_unbound "DNSSEC strict validation enabled"
    fi

    # Bundle de certificats TLS (par défaut: système)
    local tls_cert_bundle="/etc/ssl/certs/ca-certificates.crt"
    if [[ -n "${DOT_TLS_CERT_BUNDLE:-}" && -f "${DOT_TLS_CERT_BUNDLE}" ]]; then
        tls_cert_bundle="${DOT_TLS_CERT_BUNDLE}"
        log_json INFO configure_unbound "TLS cert bundle (pinning)" "bundle=${tls_cert_bundle}"
    fi

    # Split DNS: zones forwardées vers un resolver interne (sans TLS)
    local split_zones=""
    if [[ -n "${DNS_SPLIT:-}" ]]; then
        local split_entries
        split_entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')
        for entry in $split_entries; do
            local domain resolver res_ip res_port
            domain="${entry%%=*}"
            resolver="${entry#*=}"
            res_ip="${resolver%%:*}"
            res_port="${resolver##*:}"
            [[ "$res_port" = "$res_ip" ]] && res_port="53"
            [[ -z "$domain" || -z "$res_ip" ]] && continue
            split_zones+="
forward-zone:
    name: \"${domain}\"
    forward-tls-upstream: no
    forward-addr: ${res_ip}@${res_port}"
            log_json INFO configure_unbound "split DNS zone" "domain=${domain}" "resolver=${res_ip}:${res_port}"
        done
    fi

    # Génération de la config Unbound
    mkdir -p /etc/unbound /var/lib/unbound
    chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true

    local conf_file
    conf_file=$(mktemp /tmp/unbound.conf.XXXXXX)

    cat > "$conf_file" <<EOF
server:
    interface: 127.0.0.1
    port: 5053
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    do-not-query-localhost: no

    verbosity: 1
    logfile: ""

    # Masquage d'identité
    hide-identity: yes
    hide-version: yes

    # Durcissement
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    use-caps-for-id: yes
    unwanted-reply-threshold: 10000000

    # Cache
    cache-min-ttl: 60
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 86400

    # TLS: vérification du certificat serveur DoT
    tls-cert-bundle: ${tls_cert_bundle}

    # DNSSEC
    ${dnssec_mode}
EOF

    if [[ "${ENABLE_DNSSEC:-false}" = "true" && -f /var/lib/unbound/root.key ]]; then
        echo "    auto-trust-anchor-file: /var/lib/unbound/root.key" >> "$conf_file"
    fi

    # Zone principale → DoT
    cat >> "$conf_file" <<EOF

forward-zone:
    name: "."
    forward-tls-upstream: yes
${forward_addrs}
EOF

    # Zones Split DNS (override, sans TLS)
    [[ -n "$split_zones" ]] && echo "$split_zones" >> "$conf_file"

    # Validation de la config
    if ! unbound-checkconf "$conf_file" >/tmp/unbound.checkconf 2>&1; then
        log_json ERROR configure_unbound "unbound config test failed"
        cat /tmp/unbound.checkconf >&2 || true
        rm -f "$conf_file"
        return 1
    fi

    mv -f "$conf_file" /etc/unbound/unbound.conf
    log_json INFO configure_unbound "config written" \
        "dnssec=${ENABLE_DNSSEC:-false}" \
        "tls_bundle=${tls_cert_bundle}" \
        "split_dns=${DNS_SPLIT:-none}"
}

# --- Démarrage d'Unbound --------------------------------------------------------
start_unbound() {
    [[ "${ENABLE_DOT:-false}" = "true" ]] || return 0

    configure_unbound || return 0

    unbound -d -c /etc/unbound/unbound.conf &
    unbound_pid=$!

    # Attente de la disponibilité du port 5053
    local bound=0
    for _ in {1..6}; do
        if nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
            bound=1
            break
        fi
        sleep 1
    done

    if [[ "$bound" -eq 1 ]]; then
        METRIC_DOT_ACTIVE=1
        log_json INFO start_unbound "started — DoT active" "pid=${unbound_pid}" "port=5053"
    else
        log_json ERROR start_unbound "unbound did not bind to 127.0.0.1:5053"
        unbound_pid=""
        METRIC_DOT_ACTIVE=0
    fi
}

# --- Test de résolution DNS via Unbound ------------------------------------------
test_unbound_dns() {
    if command -v dig >/dev/null 2>&1; then
        dig @127.0.0.1 -p 5053 example.com +short | grep -q .
        return $?
    elif command -v nslookup >/dev/null 2>&1; then
        nslookup example.com 127.0.0.1#5053 >/dev/null 2>&1
        return $?
    fi
    return 1
}

# --- Boucle de rafraîchissement des IPs DoT --------------------------------------
_dot_refresh_loop() {
    local interval="${DOT_IP_REFRESH_INTERVAL:-$DEFAULT_DOT_IP_REFRESH_INTERVAL}"
    while true; do
        sleep "$interval"
        local dot_changed=0

        local servers="${DOT_DNS_SERVERS:-$DEFAULT_DOT_DNS_SERVERS}"
        servers=$(echo "$servers" | tr ',' ' ')

        for entry in $servers; do
            local host new_ip old_ip
            host=$(echo "$entry" | sed 's|^[a-z]*://||' | awk -F'[:/]' '{print $1}')
            [[ -z "$host" ]] && continue

            # Résolution IPv4 uniquement
            new_ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '/STREAM/{print $1; exit}' || true)
            old_ip=$(dot_ip_map_get "$host")

            if [[ -z "$new_ip" ]]; then
                log_json WARN dot_refresh "re-resolve failed" "host=${host}"
                continue
            fi

            if [[ "$new_ip" = "$old_ip" ]]; then
                log_json INFO dot_refresh "IP unchanged" "host=${host}" "ip=${new_ip}"
                continue
            fi

            log_json INFO dot_refresh "IP changed — refreshing iptables and config" \
                "host=${host}" "old=${old_ip:-none}" "new=${new_ip}"

            # Ajout de la nouvelle règle AVANT suppression de l'ancienne (zéro downtime)
            ipt_add_853 "$new_ip"

            if configure_unbound; then
                local ub_pid
                ub_pid=$(pidof unbound | awk '{print $1}' || true)
                if [[ -n "$ub_pid" ]]; then
                    kill -HUP "$ub_pid" 2>/dev/null || true
                    sleep 1
                    if test_unbound_dns; then
                        [[ -n "$old_ip" ]] && ipt_del_853 "$old_ip"
                        dot_ip_map_set "$host" "$new_ip"
                        dot_changed=1
                        log_json INFO dot_refresh "unbound config refreshed after DoT IP change" \
                            "pid=${ub_pid}" "host=${host}" "new_ip=${new_ip}"
                    else
                        log_json ERROR dot_refresh "unbound DNS validation failed after IP change" \
                            "host=${host}" "new_ip=${new_ip}"
                        ipt_del_853 "$new_ip"  # Rollback
                    fi
                else
                    log_json WARN dot_refresh "unbound not running while refreshing config"
                    ipt_del_853 "$new_ip"  # Rollback
                fi
            else
                log_json WARN dot_refresh "failed to regenerate unbound config after DoT IP change"
                ipt_del_853 "$new_ip"  # Rollback
            fi
        done

        [[ "$dot_changed" -eq 1 ]] && \
            log_json INFO dot_refresh "DoT IP refresh complete" "changed=1"
    done
}

# --- Démarrage de la boucle de rafraîchissement DoT ------------------------------
start_dot_ip_refresh() {
    [[ "${ENABLE_DOT:-false}" = "true" ]] || return 0

    local interval="${DOT_IP_REFRESH_INTERVAL:-$DEFAULT_DOT_IP_REFRESH_INTERVAL}"
    log_json INFO dot_refresh "starting periodic IP refresh" "interval=${interval}s"

    _dot_refresh_loop &
    dot_refresh_pid=$!
    log_json INFO dot_refresh "refresh loop started" "pid=${dot_refresh_pid}"
}

# =============================================================================
# Métriques Prometheus
# =============================================================================

# --- Mise à jour des fichiers de métriques -----------------------------------------
update_metrics() {
    printf '%s\n' "${METRIC_VPN_UP}"          > "${METRICS_DIR}/metric_vpn_up"          2>/dev/null || true
    printf '%s\n' "${METRIC_RESTART_COUNT}"   > "${METRICS_DIR}/metric_restart_count"   2>/dev/null || true
    printf '%s\n' "${METRIC_DOT_ACTIVE}"      > "${METRICS_DIR}/metric_dot_active"      2>/dev/null || true
    printf '%s\n' "${METRIC_START_TS}"        > "${METRICS_DIR}/metric_start_ts"        2>/dev/null || true
    printf '%s\n' "${METRIC_LAST_RESTART_TS}" > "${METRICS_DIR}/metric_last_restart_ts" 2>/dev/null || true
}

# --- Démarrage du serveur de métriques ------------------------------------------
start_metrics() {
    [[ "${ENABLE_METRICS:-false}" = "true" ]] || return 0

    require_command nc || return 0

    # Script de réponse HTTP (lu à chaque requête)
    cat > /tmp/metrics_handler.sh <<'HANDLER'
#!/bin/sh
vpn_up=$(cat /tmp/metric_vpn_up 2>/dev/null || echo 0)
restart_total=$(cat /tmp/metric_restart_count 2>/dev/null || echo 0)
dot_active=$(cat /tmp/metric_dot_active 2>/dev/null || echo 0)
start_ts=$(cat /tmp/metric_start_ts 2>/dev/null || echo 0)
last_restart=$(cat /tmp/metric_last_restart_ts 2>/dev/null || echo 0)
now=$(date +%s)
uptime_s=$((now - start_ts))

body="# HELP vpn_up VPN tunnel status (1=up 0=down)
# TYPE vpn_up gauge
vpn_up ${vpn_up}
# HELP vpn_restart_total Total supervisor restart cycles
# TYPE vpn_restart_total counter
vpn_restart_total ${restart_total}
# HELP dot_active DNS-over-TLS active
# TYPE dot_active gauge
dot_active ${dot_active}
# HELP process_uptime_seconds Container uptime in seconds
# TYPE process_uptime_seconds gauge
process_uptime_seconds ${uptime_s}
# HELP last_restart_timestamp_seconds Epoch of last supervisor restart
# TYPE last_restart_timestamp_seconds gauge
last_restart_timestamp_seconds ${last_restart}
"
len=${#body}
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
    "$len" "$body"
HANDLER
    chmod +x /tmp/metrics_handler.sh

    update_metrics

    # Utilisation de socat si disponible (meilleure performance)
    if command -v socat >/dev/null 2>&1; then
        socat TCP-LISTEN:9100,bind=127.0.0.1,reuseaddr,fork EXEC:/tmp/metrics_handler.sh &
        metrics_pid=$!
    else
        # Fallback: boucle nc (netcat-openbsd)
        (
            while true; do
                nc -l 127.0.0.1 9100 < <(/tmp/metrics_handler.sh) 2>/dev/null || sleep 1
            done
        ) &
        metrics_pid=$!
        log_json WARN start_metrics "socat not found, using nc fallback (one request at a time)"
    fi
    log_json INFO start_metrics "metrics endpoint started" "pid=${metrics_pid}" "addr=127.0.0.1:9100"
}

# =============================================================================
# Drop des capabilities Linux
# =============================================================================

drop_capabilities() {
    [[ "${DROP_CAPS:-false}" = "true" ]] || return 0

    if ! command -v python3 >/dev/null 2>&1; then
        log_json WARN drop_caps "python3 not found — capability drop skipped"
        return 0
    fi

    log_json INFO drop_caps "dropping capabilities via prctl" \
        "retaining=cap_net_admin(12),cap_net_raw(13)"

    python3 - <<'PYCAPS'
import ctypes, sys, os

libc = ctypes.CDLL("libc.so.6", use_errno=True)
PR_CAPBSET_DROP = 24
CAP_NET_ADMIN   = 12
CAP_NET_RAW     = 13
KEEP = {CAP_NET_ADMIN, CAP_NET_RAW}

errors = []
for cap in range(40):  # Linux caps 0-39
    if cap in KEEP:
        continue
    ret = libc.prctl(PR_CAPBSET_DROP, ctypes.c_ulong(cap), 0, 0, 0)
    if ret != 0:
        err = ctypes.get_errno()
        if err != 22:  # EINVAL (cap not supported)
            errors.append(f"cap {cap}: errno {err}")

if errors:
    print(f"[drop_caps] some caps could not be dropped: {errors}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"[drop_caps] bounding set reduced — kept CAP_NET_ADMIN({CAP_NET_ADMIN}) CAP_NET_RAW({CAP_NET_RAW})")
PYCAPS

    local rc=$?
    if [[ $rc -eq 0 ]]; then
        log_json INFO drop_caps "capabilities dropped successfully" "retained=cap_net_admin,cap_net_raw"
    else
        log_json WARN drop_caps "capability drop had errors — check stderr above"
    fi
}

# =============================================================================
# Services DNS (dnsmasq)
# =============================================================================

# --- Configuration de dnsmasq ----------------------------------------------------
configure_dnsmasq() {
    if [[ "${ENABLE_DOT:-false}" = "true" ]]; then
        cat > /etc/dnsmasq.conf <<EOF
# Generated at startup — DNS-over-TLS mode via local unbound
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=127.0.0.1#5053
cache-size=1000
log-facility=/dev/null
EOF
        log_json INFO configure_dnsmasq "DoT mode — upstream: 127.0.0.1#5053"
    else
        local dns1="${DNS_SERVER_1:-$DEFAULT_DNS_SERVER_1}"
        local dns2="${DNS_SERVER_2:-$DEFAULT_DNS_SERVER_2}"
        cat > /etc/dnsmasq.conf <<EOF
# Generated at startup from DNS_SERVER_1 / DNS_SERVER_2
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=${dns1}
server=${dns2}
cache-size=1000
log-facility=/dev/null
EOF
        # Split DNS en mode classique
        if [[ -n "${DNS_SPLIT:-}" ]]; then
            local entries
            entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')
            for entry in $entries; do
                local domain resolver res_ip res_port
                domain="${entry%%=*}"
                resolver="${entry#*=}"
                res_ip="${resolver%%:*}"
                res_port="${resolver##*:}"
                [[ "$res_port" = "$res_ip" ]] && res_port="53"
                [[ -z "$domain" || -z "$res_ip" ]] && continue
                echo "server=/${domain}/${res_ip}#${res_port}" >> /etc/dnsmasq.conf
                log_json INFO configure_dnsmasq "split DNS" "domain=${domain}" "resolver=${res_ip}:${res_port}"
            done
        fi
        log_json INFO configure_dnsmasq "upstream: ${dns1}, ${dns2}"
    fi
}

# --- Démarrage de dnsmasq ----------------------------------------------------------
start_dnsmasq() {
    configure_dnsmasq

    # Configuration de /etc/resolv.conf
    echo "nameserver 127.0.0.1" > /etc/resolv.conf || {
        echo "nameserver 127.0.0.1" > /tmp/resolv.conf
        mount --bind /tmp/resolv.conf /etc/resolv.conf || true
    }

    if ! dnsmasq --test --conf-file=/etc/dnsmasq.conf >/tmp/dnsmasq.test 2>&1; then
        log_json ERROR start_dnsmasq "config test failed"
        sed -n '1,200p' /tmp/dnsmasq.test >&2 || true
        return 0
    fi

    dnsmasq --no-daemon --conf-file=/etc/dnsmasq.conf --log-facility=- &
    dnsmasq_pid=$!

    # Attente de la disponibilité du port 53
    local bound=0
    for _ in {1..5}; do
        if nc -z -w 1 127.0.0.1 53 >/dev/null 2>&1; then
            bound=1
            break
        fi
        sleep 1
    done

    if [[ "$bound" -eq 1 ]]; then
        log_json INFO start_dnsmasq "started" "pid=${dnsmasq_pid}" "port=53"
    else
        log_json ERROR start_dnsmasq "dnsmasq did not bind to 127.0.0.1:53"
    fi
}

# =============================================================================
# Proxy (Privoxy + Nginx Auth)
# =============================================================================

# --- Configuration de l'authentification Privoxy --------------------------------
configure_privoxy_auth() {
    local user="${PROXY_USER:-}"
    local pass="${PROXY_PASS:-}"
    if [[ -n "$user" && -n "$pass" ]]; then
        sed -i 's|^listen-address .*|listen-address 127.0.0.1:3129|' /etc/privoxy/privoxy.config
        log_json INFO configure_privoxy_auth "auth enabled — privoxy on 127.0.0.1:3129"
    else
        sed -i 's|^listen-address .*|listen-address 0.0.0.0:3128|' /etc/privoxy/privoxy.config
        log_json INFO configure_privoxy_auth "no auth — privoxy on 0.0.0.0:3128"
    fi
}

# --- Démarrage de Privoxy ---------------------------------------------------------
start_privoxy() {
    configure_privoxy_auth
    /usr/sbin/privoxy --no-daemon /etc/privoxy/privoxy.config &
    privoxy_pid=$!
}

# --- Démarrage de Nginx (proxy auth) ----------------------------------------------
start_nginx_auth() {
    local user="${PROXY_USER:-}"
    local pass="${PROXY_PASS:-}"
    [[ -n "$user" && -n "$pass" ]] || return 0

    if ! command -v nginx >/dev/null 2>&1; then
        log_json WARN start_nginx_auth "nginx not found — falling back to no-auth"
        sed -i 's|^listen-address .*|listen-address 0.0.0.0:3128|' /etc/privoxy/privoxy.config
        return 0
    fi

    # Création du fichier htpasswd
    local htpasswd_file="/etc/nginx/.proxy_htpasswd"
    mkdir -p /etc/nginx
    htpasswd -cbB "$htpasswd_file" "$user" "$pass"
    chmod 600 "$htpasswd_file"

    # Attente de Privoxy
    local proxy_port=3129
    for _ in {1..5}; do
        if nc -z -w 1 127.0.0.1 3129 >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # Configuration Nginx
    mkdir -p /run/nginx /var/log/nginx
    cat > /etc/nginx/nginx_proxy_auth.conf <<'NGINXCONF'
worker_processes 1;
error_log /dev/null crit;
pid /run/nginx/nginx_proxy_auth.pid;
events { worker_connections 64; }
http {
    access_log off;
    proxy_connect_timeout 60s;
    proxy_read_timeout    300s;
    proxy_send_timeout    60s;
    server {
        listen 0.0.0.0:3128;
        auth_basic           "Proxy Authentication Required";
        auth_basic_user_file /etc/nginx/.proxy_htpasswd;
        location / {
            proxy_pass         http://127.0.0.1:3129;
            proxy_http_version 1.1;
            proxy_set_header   Host          $host;
            proxy_set_header   X-Real-IP     $remote_addr;
            proxy_set_header   Connection    "";
            proxy_set_header   Authorization "";
        }
    }
}
NGINXCONF

    nginx -c /etc/nginx/nginx_proxy_auth.conf -g 'daemon off;' &
    nginx_pid=$!
    log_json INFO start_nginx_auth "started" \
        "pid=${nginx_pid}" "frontend=0.0.0.0:3128" "backend=127.0.0.1:3129"
}

# =============================================================================
# OpenVPN
# =============================================================================

start_openvpn() {
    /usr/local/bin/openvpn.sh &
    vpn_pid=$!
}

# --- Vérification du routage OpenVPN ----------------------------------------------
check_openvpn_routing() {
    command -v ip >/dev/null 2>&1 || return 0
    local out dev
    out=$(ip route get "${ROUTE_TEST_IP:-$DEFAULT_ROUTE_TEST_IP}" 2>/dev/null || true)
    dev=$(echo "$out" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
    [[ -z "$dev" ]] && return 1
    case "$dev" in
        tun*|tap*) ;;
        *) return 1 ;;
    esac
    ip -4 addr show dev "$dev" >/dev/null 2>&1
}

# --- Redémarrage d'OpenVPN --------------------------------------------------------
restart_openvpn() {
    log_json WARN supervisor "restarting openvpn" "pid=${vpn_pid:-unknown}"
    kill_if_running "$vpn_pid"
    vpn_pid=""
    start_openvpn

    for _ in {1..5}; do
        sleep 1
        if check_openvpn_routing; then
            log_json INFO supervisor "openvpn routing restored" "pid=${vpn_pid}"
            return 0
        fi
    done

    log_json ERROR supervisor "openvpn routing still not functional after restart"
    return 1
}

# =============================================================================
# Tailscale
# =============================================================================

start_tailscale() {
    [[ "${ENABLE_TAILSCALE:-false}" = "true" ]] || return 0

    if ! command -v tailscaled >/dev/null 2>&1; then
        log_json WARN start_tailscale "tailscaled not installed — skipping"
        return 0
    fi

    mkdir -p /var/lib/tailscale "$TAILSCALE_RUN_DIR" || true
    log_json INFO start_tailscale "starting tailscaled"

    tailscaled \
        --state="/var/lib/tailscale/tailscaled.state" \
        --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" \
        >/var/log/tailscaled.log 2>&1 &
    export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
    tailscaled_pid=$!

    # Attente de la disponibilité de tailscaled
    local waited=0
    until tailscale status >/dev/null 2>&1 || [[ "$waited" -ge 20 ]]; do
        sleep 1
        waited=$((waited + 1))
    done

    if [[ -z "${TAILSCALE_AUTHKEY:-}" ]]; then
        log_json WARN start_tailscale "no authkey — skipping 'tailscale up'"
        return 0
    fi

    local up_flags="${TAILSCALE_FLAGS:-}"
    [[ "${TAILSCALE_ACCEPT_ROUTES:-false}" = "true" ]] && up_flags+=" --accept-routes"
    [[ -n "${TAILSCALE_HOSTNAME:-}" ]] && up_flags+=" --hostname=${TAILSCALE_HOSTNAME}"
    [[ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ]] && {
        up_flags+=" --advertise-exit-node"
        mkdir -p /etc/sysctl.d || true
        cat > /etc/sysctl.d/99-tailscale.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
        sysctl -p /etc/sysctl.d/99-tailscale.conf || true
        (tailscale set --advertise-exit-node=true >> /var/log/tailscale-up.log 2>&1) || true &
    }

    log_json INFO start_tailscale "running 'tailscale up'"
    # shellcheck disable=SC2086
    (tailscale up --accept-dns=false --authkey="$TAILSCALE_AUTHKEY" $up_flags \
        > /var/log/tailscale-up.log 2>&1) &
}

# =============================================================================
# Healthcheck
# =============================================================================

run_service_healthcheck() {
    local log_file="/tmp/healthcheck.log"
    if /usr/local/bin/healthcheck.sh >"$log_file" 2>&1; then
        return 0
    fi

    cat "$log_file" >&2 || true
    log_json WARN supervisor "healthcheck failed — restarting services"
    rm -f /tmp/vpn_healthy
    METRIC_VPN_UP=0
    return 1
}

# =============================================================================
# Superviseur principal
# =============================================================================

supervise_all() {
    local attempt=0
    local stable_cycles=0

    while true; do
        attempt=$((attempt + 1))
        METRIC_RESTART_COUNT=$((attempt - 1))
        METRIC_LAST_RESTART_TS=$(date +%s)

        # Ordre critique: start_unbound AVANT start_dnsmasq pour résoudre les IPs DoT
        start_unbound
        start_dnsmasq
        setup_iptables
        setup_ip6tables
        start_privoxy
        start_nginx_auth
        start_openvpn
        start_tailscale

        # Services auxiliaires (démarrés une seule fois)
        if [[ "$attempt" -eq 1 ]]; then
            start_metrics
            start_dot_ip_refresh
        fi

        log_json INFO supervisor "waiting for OpenVPN tunnel..."
        local tun_ready=0
        for _ in {1..30}; do
            if check_openvpn_routing; then
                tun_ready=1
                break
            fi
            sleep 1
        done

        if [[ "$tun_ready" -eq 1 ]]; then
            setup_return_routes
            check_vpn_ip
            touch /tmp/vpn_healthy
            METRIC_VPN_UP=1
        else
            log_json WARN supervisor "tunnel not ready after 30s — skipping return routes"
            rm -f /tmp/vpn_healthy
            METRIC_VPN_UP=0
        fi

        # Drop des capabilities après le 1er démarrage complet
        [[ "$attempt" -eq 1 ]] && drop_capabilities

        update_metrics

        log_json INFO supervisor "all services running" \
            "vpn=${vpn_pid}" \
            "dnsmasq=${dnsmasq_pid:-unknown}" \
            "privoxy=${privoxy_pid:-unknown}" \
            "nginx_auth=${nginx_pid:-disabled}" \
            "unbound=${unbound_pid:-disabled}" \
            "metrics=${metrics_pid:-disabled}" \
            "dot_refresh=${dot_refresh_pid:-disabled}"

        # Boucle de surveillance
        local fail=0
        while true; do
            sleep 10

            # Vérification des processus OpenVPN
            if [[ -n "$vpn_pid" && ! -e "/proc/$vpn_pid" ]]; then
                log_json ERROR supervisor "openvpn process died"
                fail=1
            fi

            # Vérification du routage OpenVPN
            if [[ "$fail" -eq 0 && ! $(check_openvpn_routing) ]]; then
                log_json WARN supervisor "openvpn routing failure"
                rm -f /tmp/vpn_healthy
                METRIC_VPN_UP=0
                if restart_openvpn; then
                    setup_return_routes
                    check_vpn_ip
                    touch /tmp/vpn_healthy
                    METRIC_VPN_UP=1
                    update_metrics
                    continue
                else
                    fail=1
                fi
            fi

            # Vérification de Privoxy
            local proxy_port=3128
            if [[ -f /etc/privoxy/privoxy.config ]]; then
                local addr
                addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' /etc/privoxy/privoxy.config || true)
                [[ -n "$addr" ]] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
            fi
            if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
                log_json ERROR supervisor "privoxy not listening" "port=${proxy_port}"
                fail=1
            fi

            # Vérification de Nginx (si activé)
            if [[ -n "$nginx_pid" ]]; then
                if [[ ! -e "/proc/$nginx_pid" ]]; then
                    log_json ERROR supervisor "nginx auth proxy died"
                    fail=1
                elif ! nc -z -w 3 127.0.0.1 3128 >/dev/null 2>&1; then
                    log_json ERROR supervisor "nginx auth proxy not listening"
                    fail=1
                fi
            fi

            # Vérification d'Unbound (si DoT activé)
            if [[ "${ENABLE_DOT:-false}" = "true" && -n "$unbound_pid" ]]; then
                if [[ ! -e "/proc/$unbound_pid" ]]; then
                    log_json ERROR supervisor "unbound process died"
                    fail=1
                    METRIC_DOT_ACTIVE=0
                elif ! nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
                    log_json ERROR supervisor "unbound not listening on 5053"
                    fail=1
                    METRIC_DOT_ACTIVE=0
                fi
            fi

            # Vérification de dnsmasq
            if [[ -n "$dnsmasq_pid" ]]; then
                if [[ ! -e "/proc/$dnsmasq_pid" ]]; then
                    log_json ERROR supervisor "dnsmasq process died"
                    fail=1
                elif ! nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                    log_json ERROR supervisor "DNS resolution via 127.0.0.1 failed"
                    fail=1
                fi
            fi

            # Vérification de Tailscale
            if [[ -n "$tailscaled_pid" && ! -e "/proc/$tailscaled_pid" ]]; then
                log_json ERROR supervisor "tailscaled process died"
                fail=1
            fi

            # Healthcheck personnalisé
            if [[ "$fail" -eq 0 && ! $(run_service_healthcheck) ]]; then
                fail=1
            fi

            [[ "$fail" -eq 0 ]] || break

            update_metrics
            stable_cycles=$((stable_cycles + 1))

            # Backoff: réinitialisation après 6 cycles stables
            if [[ "$stable_cycles" -ge 6 && "$attempt" -gt 1 ]]; then
                attempt=1
                stable_cycles=0
                log_json INFO supervisor "services stable — backoff counter reset"
            fi
        done

        log_json ERROR supervisor "failure detected — restarting services" "attempt=${attempt}"
        rm -f /tmp/vpn_healthy
        METRIC_VPN_UP=0
        METRIC_LAST_RESTART_TS=$(date +%s)
        update_metrics

        # Arrêt propre des services
        kill_if_running "$vpn_pid"
        kill_if_running "$privoxy_pid"
        kill_if_running "$nginx_pid"
        kill_if_running "$dnsmasq_pid"
        kill_if_running "$tailscaled_pid"
        kill_if_running "$unbound_pid"

        # Réinitialisation des PIDs
        vpn_pid=""
        privoxy_pid=""
        nginx_pid=""
        dnsmasq_pid=""
        tailscaled_pid=""
        unbound_pid=""

        # Réinitialisation des variables DoT
        DOT_RESOLVED_IPS=""
        unset DOT_HOST_IP_MAP
        declare -A DOT_HOST_IP_MAP

        # Backoff exponentiel (max 60s)
        local sleep_s=$((5 * attempt))
        [[ "$sleep_s" -gt 60 ]] && sleep_s=60
        log_json INFO supervisor "restarting in ${sleep_s}s" "attempt=${attempt}"
        sleep "$sleep_s"
    done
}

# --- Gestion des signaux (INT/TERM) ------------------------------------------------
trap 'kill 0 || true; exit 0' INT TERM

# =============================================================================
# Point d'entrée
# =============================================================================
supervise_all