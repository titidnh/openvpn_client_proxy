#!/bin/bash

# ===========================================================================
# start.sh - Script principal de supervision pour openvpn_client_proxy
# 
# Ce script est le point d'entrée du conteneur Docker. Il :
# 1. Configure et démarre tous les services (DNS, Proxy, VPN, etc.)
# 2. Met en place le firewall (kill switch)
# 3. Supervise les services et les redémarre en cas d'échec
# 4. Gère les métriques Prometheus
# 5. Optionnellement, configure Tailscale
# 
# Auteur: Vibe Code (amélioration 2026)
# Licence: MIT
# Version: 2.0.0
# ===========================================================================

set -euo pipefail

# ===========================================================================
# Initialisation
# ===========================================================================

# Charger les fonctions communes
source "/usr/local/lib/common.sh"

# Initialiser l'environnement
init_environment

# ===========================================================================
# Configuration globale
# ===========================================================================

# Chemins
readonly VPN_DIR="/vpn"
readonly VPN_CONF="${VPN_DIR}/vpn.conf"
readonly DNSMASQ_CONF="/etc/dnsmasq.conf"
readonly PRIVOXY_CONF="/etc/privoxy/privoxy.config"
readonly UNBOUND_CONF="/etc/unbound/unbound.conf"
readonly RESOLV_CONF="/etc/resolv.conf"

# Fichiers temporaires
readonly DOT_IP_MAP_FILE="/tmp/dot_ip_map"
readonly DOT_FORWARD_ADDRS_FILE="/tmp/dot_forward_addrs"
readonly VPN_HEALTHY_FILE="/tmp/vpn_healthy"
readonly METRICS_DIR="/tmp/metrics"

# PID files (pour suivi des processus)
declare -A SERVICE_PIDS=(
    [vpn]=0
    [privoxy]=0
    [nginx]=0
    [dnsmasq]=0
    [tailscaled]=0
    [unbound]=0
    [metrics]=0
    [dot_refresh]=0
)

# Compteurs de métriques
declare -g METRIC_RESTART_COUNT=0
declare -g METRIC_VPN_UP=0
declare -g METRIC_DOT_ACTIVE=0
declare -g METRIC_LAST_RESTART_TS=0
declare -g METRIC_START_TS=$(date +%s)

# IPs DoT résolues
declare -g DOT_RESOLVED_IPS=""
declare -gA DOT_HOST_IP_MAP=()

# ===========================================================================
# Validation de l'environnement
# ===========================================================================

validate_environment() {
    log_json INFO "validate_environment" "Validating environment variables"
    
    # Valider les booléens
    local bool_vars=(
        "ENABLE_TAILSCALE"
        "ENABLE_DOT"
        "ENABLE_DNSSEC"
        "ENABLE_METRICS"
        "DROP_CAPS"
        "TAILSCALE_ACCEPT_ROUTES"
        "TAILSCALE_ADVERTISE_EXIT_NODE"
    )
    
    for var in "${bool_vars[@]}"; do
        local value="${!var:-false}"
        if ! validate_boolean "$var" "$value"; then
            log_json WARN "validate_environment" \
                "Invalid boolean value for ${var}, using default" \
                "value=${value}"
            export "$var"="false"
        fi
    done
    
    # Valider les ports
    if [ -n "${PROXY_PORT:-}" ]; then
        validate_port "PROXY_PORT" "$PROXY_PORT" || export PROXY_PORT="$DEFAULT_PROXY_PORT"
    fi
    
    # Valider les IPs
    if [ -n "${DNS_SERVER_1:-}" ]; then
        validate_ip "DNS_SERVER_1" "$DNS_SERVER_1" || export DNS_SERVER_1="$DEFAULT_DNS_SERVER_1"
    fi
    
    if [ -n "${DNS_SERVER_2:-}" ]; then
        validate_ip "DNS_SERVER_2" "$DNS_SERVER_2" || export DNS_SERVER_2="$DEFAULT_DNS_SERVER_2"
    fi
    
    log_json INFO "validate_environment" "Environment validation complete"
}

# ===========================================================================
# Configuration du Firewall (iptables)
# ===========================================================================

# Ajoute une règle iptables pour le port 853 (DoT)
# Usage: ipt_add_853 IP
ipt_add_853() {
    local ip="$1"
    if [[ "$ip" =~ : ]]; then
        ipt6 -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
    else
        iptables -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
    fi
}

# Supprime une règle iptables pour le port 853 (DoT)
# Usage: ipt_del_853 IP
ipt_del_853() {
    local ip="$1"
    if [[ "$ip" =~ : ]]; then
        ipt6 -D OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
    else
        iptables -D OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
    fi
}

# Configure le firewall IPv4
setup_iptables() {
    log_json INFO "setup_iptables" "Configuring IPv4 firewall"
    
    local docker_network
    docker_network=$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet"{print $4}' || true)

    get_vpn_port_proto "$VPN_CONF"

    # Réinitialiser les règles
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # Autoriser temporairement DNS_SERVER_1 et DNS_SERVER_2 pour la résolution initiale
    for dns in "$DNS_SERVER_1" "$DNS_SERVER_2"; do
        iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
    done

    # Autoriser HEALTHCHECK_IP pour le healthcheck
    iptables -A OUTPUT -p tcp -d "$HEALTHCHECK_IP" --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp -d "$HEALTHCHECK_IP" --dport 443 -j ACCEPT
    iptables -A OUTPUT -p udp -d "$HEALTHCHECK_IP" --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d "$HEALTHCHECK_IP" --dport 53 -j ACCEPT

    # INPUT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    [ -n "$docker_network" ] && iptables -A INPUT -s "$docker_network" -j ACCEPT

    # FORWARD
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i lo -j ACCEPT
    [ -n "$docker_network" ] && iptables -A FORWARD -s "$docker_network" -j ACCEPT
    [ -n "$docker_network" ] && iptables -A FORWARD -d "$docker_network" -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i tap+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # OUTPUT - interfaces
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tun+ -j ACCEPT
    iptables -A OUTPUT -o tap+ -j ACCEPT
    iptables -A OUTPUT -o tailscale+ -j ACCEPT
    [ -n "$docker_network" ] && iptables -A OUTPUT -d "$docker_network" -j ACCEPT

    # OUTPUT - métriques locales
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 9100 -j ACCEPT

    # OUTPUT - DNS local
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 5053 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 5053 -j ACCEPT

    # DoT configuration
    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        if [ -n "$DOT_RESOLVED_IPS" ]; then
            for dot_ip in $DOT_RESOLVED_IPS; do
                ipt_add_853 "$dot_ip"
                log_json INFO "setup_iptables" "DoT: allowing TCP 853" "ip=${dot_ip}"
            done
        else
            log_json WARN "setup_iptables" "DoT: no resolved IPs - TCP 853 not explicitly allowed"
        fi
        # Kill switch DoT strict : bloquer tout DNS 53 externe
        iptables -A OUTPUT -p udp ! -d 127.0.0.0/8 --dport 53 -j DROP
        iptables -A OUTPUT -p tcp ! -d 127.0.0.0/8 --dport 53 -j DROP
        log_json INFO "setup_iptables" "DoT DNS leak prevention: external port 53 blocked"
    else
        # Mode non-DoT : autoriser DNS_SERVER_1/2 + upstreams dnsmasq
        for _dns in "$DNS_SERVER_1" "$DNS_SERVER_2"; do
            [[ "$_dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            iptables -A OUTPUT -p udp -d "$_dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$_dns" --dport 53 -j ACCEPT
            log_json INFO "setup_iptables" "allowing port 53" "ip=${_dns}"
        done
        
        # Autoriser aussi les upstreams dnsmasq
        while read -r dns; do
            [[ "$dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams "$DNSMASQ_CONF")
    fi

    # DNS Docker interne
    if grep -Fq "127.0.0.11" "$RESOLV_CONF" 2>/dev/null; then
        iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT
        iptables -A OUTPUT -p udp -d 127.0.0.11 --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d 127.0.0.11 --dport 53 -j ACCEPT
    fi

    # OpenVPN
    iptables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true

    # NAT
    iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    log_json INFO "setup_iptables" "IPv4 configured - kill switch active" \
        "vpn_proto=${VPN_PROTO}" "vpn_port=${VPN_PORT}"
}

# Configure le firewall IPv6
setup_ip6tables() {
    log_json INFO "setup_ip6tables" "Configuring IPv6 firewall"
    
    if ! command_exists ip6tables; then
        log_json WARN "setup_ip6tables" "ip6tables not installed, skipping"
        return 0
    fi
    
    if [ ! -f /proc/net/if_inet6 ]; then
        log_json WARN "setup_ip6tables" "IPv6 not available, skipping"
        return 0
    fi

    local docker6_network
    docker6_network=$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet6"{print $4; exit}' || true)

    ipt6 -F
    ipt6 -X
    ipt6 -t nat -F
    ipt6 -P INPUT DROP
    ipt6 -P FORWARD DROP
    ipt6 -P OUTPUT DROP

    ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A INPUT -p icmpv6 -j ACCEPT
    ipt6 -A INPUT -i lo -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A INPUT -s "$docker6_network" -j ACCEPT

    ipt6 -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -p icmpv6 -j ACCEPT
    ipt6 -A FORWARD -i lo -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A FORWARD -s "$docker6_network" -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A FORWARD -d "$docker6_network" -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    ipt6 -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i tap+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A OUTPUT -o lo -j ACCEPT
    ipt6 -A OUTPUT -o tun+ -j ACCEPT
    ipt6 -A OUTPUT -o tap+ -j ACCEPT
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT

    # OUTPUT - métriques locales (loopback IPv6)
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 9100 -j ACCEPT

    # OUTPUT - DNS local IPv6
    ipt6 -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p udp -d ::1 --dport 5053 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 5053 -j ACCEPT

    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        ipt6 -A OUTPUT -p udp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true
        ipt6 -A OUTPUT -p tcp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true
        log_json INFO "setup_ip6tables" "DoT DNS leak prevention: IPv6 port 53 blocked"
    else
        while read -r dns; do
            [[ "$dns" =~ : ]] || continue
            ipt6 -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            ipt6 -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams "$DNSMASQ_CONF")
    fi

    ipt6 -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
    ipt6 -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT
    ipt6 -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT

    ipt6 -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    ipt6 -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    log_json INFO "setup_ip6tables" "IPv6 configured - kill switch active"
}

# Configure les routes de retour
setup_return_routes() {
    log_json INFO "setup_return_routes" "Configuring return routes"
    
    local iface gw gw6 ips ip6s

    iface=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}')
    if [ -z "$iface" ]; then
        log_json WARN "setup_return_routes" "no default interface found, skipping"
        return 0
    fi

    gw=$(ip -4 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}')
    gw6=$(ip -6 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}')
    ips=$(ip -4 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet /{print $3}')
    ip6s=$(ip -6 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet6.*global/{print $3}')

    for ip in $ips; do
        ip -4 rule show table 10 2>/dev/null | grep -q "$ip" || \
            ip rule add from "$ip" lookup 10 2>/dev/null || true
        iptables -C INPUT -d "$ip" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -d "$ip" -j ACCEPT
    done
    [ -n "$gw" ] && {
        ip -4 route show table 10 2>/dev/null | grep -q "default" || \
            ip route add default via "$gw" table 10 2>/dev/null || true
    }

    for ip6 in $ip6s; do
        ip -6 rule show table 10 2>/dev/null | grep -q "$ip6" || \
            ip -6 rule add from "$ip6" lookup 10 2>/dev/null || true
        ipt6 -C INPUT -d "$ip6" -j ACCEPT || ipt6 -A INPUT -d "$ip6" -j ACCEPT
    done
    [ -n "$gw6" ] && {
        ip -6 route show table 10 2>/dev/null | grep -q "default" || \
            ip -6 route add default via "$gw6" table 10 2>/dev/null || true
    }

    log_json INFO "setup_return_routes" "return routes configured" "iface=${iface}"
}

# ===========================================================================
# Configuration DNS-over-TLS (Unbound)
# ===========================================================================

# Définit une correspondance hôte -> IP pour DoT
dot_ip_map_set() {
    local host="$1"
    local ip="$2"
    DOT_HOST_IP_MAP["$host"]="$ip"
    local tmp
    tmp=$(temp_file "dot_ip_map")
    [ -f "$DOT_IP_MAP_FILE" ] && grep -v "^${host}=" "$DOT_IP_MAP_FILE" > "$tmp" || true
    echo "${host}=${ip}" >> "$tmp"
    mv -f "$tmp" "$DOT_IP_MAP_FILE"
}

# Récupère une IP depuis la correspondance DoT
dot_ip_map_get() {
    local host="$1"
    if [ -n "${DOT_HOST_IP_MAP[$host]:-}" ]; then
        echo "${DOT_HOST_IP_MAP[$host]}"
    elif [ -f "$DOT_IP_MAP_FILE" ]; then
        grep "^${host}=" "$DOT_IP_MAP_FILE" | cut -d= -f2- | tail -1
    fi
}

# Parse les serveurs DoT et résout leurs IPs
parse_dot_servers() {
    log_json INFO "parse_dot_servers" "Parsing DoT servers"
    
    local servers="${DOT_DNS_SERVERS}"
    servers=$(echo "$servers" | tr ',' ' ')
    local tmp_map tmp_forward
    tmp_map=$(temp_file "dot_ip_map")
    tmp_forward=$(temp_file "dot_forward_addrs")
    DOT_RESOLVED_IPS=""
    DOT_HOST_IP_MAP=()

    for entry in $servers; do
        local proto host
        proto=$(echo "$entry" | awk -F'://' '{print $1}')
        host=$(echo "$entry" | sed 's|^[a-z]*://||' | awk -F'[:/]' '{print $1}')
        [ -z "$host" ] && continue

        # Résoudre l'hôte en IP
        local ip
        ip=$(resolve_hostname "$host" "$DNS_SERVER_1" "$DNS_SERVER_2")

        if [ -n "$ip" ]; then
            DOT_RESOLVED_IPS="${DOT_RESOLVED_IPS}${ip} "
            DOT_HOST_IP_MAP["$host"]="$ip"
            echo "${host}=${ip}" >> "$tmp_map"
            if [ "$proto" = "https" ]; then
                echo "        forward-addr: ${ip}@443#${host}" >> "$tmp_forward"
            else
                echo "        forward-addr: ${ip}@853#${host}" >> "$tmp_forward"
            fi
            log_json INFO "parse_dot_servers" "resolved" \
                "host=${host}" "ip=${ip}" "proto=${proto}"
        else
            log_json WARN "parse_dot_servers" \
                "could not resolve, skipping" "host=${host}"
        fi
    done

    if [ -s "$tmp_map" ]; then
        mv -f "$tmp_map" "$DOT_IP_MAP_FILE"
    else
        rm -f "$tmp_map"
    fi
    
    if [ -s "$tmp_forward" ]; then
        mv -f "$tmp_forward" "$DOT_FORWARD_ADDRS_FILE"
    else
        rm -f "$tmp_forward"
    fi
}

# Configure Unbound pour DoT
configure_unbound() {
    log_json INFO "configure_unbound" "Configuring Unbound for DoT"
    
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    if ! command_exists unbound; then
        log_json ERROR "configure_unbound" "unbound binary not found - DoT disabled"
        return 1
    fi

    local conf_file
    conf_file=$(temp_file "unbound")

    parse_dot_servers

    if [ ! -s "$DOT_FORWARD_ADDRS_FILE" ]; then
        log_json ERROR "configure_unbound" "no valid DoT servers parsed - DoT disabled"
        rm -f "$conf_file"
        return 1
    fi
    
    local forward_addrs
    forward_addrs=$(cat "$DOT_FORWARD_ADDRS_FILE")

    # DNSSEC : permissive par défaut, strict si ENABLE_DNSSEC=true
    local dnssec_mode="val-permissive-mode: yes"
    if [ "${ENABLE_DNSSEC:-false}" = "true" ]; then
        dnssec_mode="val-permissive-mode: no"
        mkdir -p /var/lib/unbound
        chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true
        unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
        log_json INFO "configure_unbound" "DNSSEC strict validation enabled"
    fi

    # TLS cert bundle
    local tls_cert_bundle="/etc/ssl/certs/ca-certificates.crt"
    if [ -n "${DOT_TLS_CERT_BUNDLE:-}" ] && [ -f "${DOT_TLS_CERT_BUNDLE}" ]; then
        tls_cert_bundle="${DOT_TLS_CERT_BUNDLE}"
        log_json INFO "configure_unbound" "TLS cert bundle (pinning)" "bundle=${tls_cert_bundle}"
    fi

    # Split DNS
    local split_zones=""
    if [ -n "${DNS_SPLIT:-}" ]; then
        local split_entries
        split_entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')
        for entry in $split_entries; do
            local domain resolver res_ip res_port
            domain="${entry%%=*}"
            resolver="${entry#*=}"
            res_ip="${resolver%%:*}"
            res_port="${resolver##*:}"
            [ "$res_port" = "$res_ip" ] && res_port="53"
            [ -z "$domain" ] || [ -z "$res_ip" ] && continue
            split_zones="${split_zones}
forward-zone:
    name: \"${domain}\"
    forward-tls-upstream: no
    forward-addr: ${res_ip}@${res_port}"
            log_json INFO "configure_unbound" "split DNS zone" \
                "domain=${domain}" "resolver=${res_ip}:${res_port}"
        done
    fi

    mkdir -p /etc/unbound /var/lib/unbound
    chown -R unbound:unbound /etc/unbound /var/lib/unbound 2>/dev/null || true
    chmod 0755 /etc/unbound 2>/dev/null || true

    # Écrire la configuration Unbound
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
    logfile: "/var/log/unbound.log"

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

    # TLS
    tls-cert-bundle: ${tls_cert_bundle}

    # DNSSEC
    ${dnssec_mode}
EOF

    if [ "${ENABLE_DNSSEC:-false}" = "true" ] && [ -f /var/lib/unbound/root.key ]; then
        echo "    auto-trust-anchor-file: /var/lib/unbound/root.key" >> "$conf_file"
    fi

    cat >> "$conf_file" <<EOF

forward-zone:
    name: "."
    forward-tls-upstream: yes
${forward_addrs}
EOF

    [ -n "$split_zones" ] && echo "$split_zones" >> "$conf_file"

    if ! unbound-checkconf "$conf_file" >/tmp/unbound.checkconf 2>&1; then
        log_json ERROR "configure_unbound" "unbound config test failed"
        cat /tmp/unbound.checkconf >&2 || true
        rm -f "$conf_file"
        return 1
    fi

    chmod 0644 "$conf_file" 2>/dev/null || true
    chown unbound:unbound "$conf_file" 2>/dev/null || true
    touch /var/log/unbound.log 2>/dev/null || true
    chown unbound:unbound /var/log/unbound.log 2>/dev/null || true
    mv -f "$conf_file" "$UNBOUND_CONF"
    chmod 0644 "$UNBOUND_CONF" 2>/dev/null || true
    chown unbound:unbound "$UNBOUND_CONF" 2>/dev/null || true

    log_json INFO "configure_unbound" "config written" \
        "dnssec=${ENABLE_DNSSEC:-false}" \
        "tls_bundle=${tls_cert_bundle}" \
        "split_dns=${DNS_SPLIT:-none}"
}

# Démarre Unbound
start_unbound() {
    log_json INFO "start_unbound" "Starting Unbound"
    
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    configure_unbound || return 0

    unbound -d -c "$UNBOUND_CONF" &
    SERVICE_PIDS[unbound]=$!

    local max_wait=10
    if [ "${ENABLE_DNSSEC:-false}" = "true" ]; then
        max_wait=10
        log_json INFO "start_unbound" "DNSSEC enabled - extended startup timeout" \
            "timeout=${max_wait}s"
    fi

    local bound=0 i
    for i in $(seq 1 "$max_wait"); do
        if ! kill -0 "${SERVICE_PIDS[unbound]}" 2>/dev/null; then
            log_json WARN "start_unbound" "unbound exited during startup" \
                "pid=${SERVICE_PIDS[unbound]}"
            break
        fi

        if nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
            if test_unbound_dns_robust; then
                bound=1
                break
            fi
        fi
        sleep 1
    done

    if [ "$bound" -eq 1 ]; then
        METRIC_DOT_ACTIVE=1
        log_json INFO "start_unbound" "started - DoT active" \
            "pid=${SERVICE_PIDS[unbound]}" "port=5053"
    else
        log_json WARN "start_unbound" "unbound not ready after startup window" \
            "timeout=${max_wait}s" "pid=${SERVICE_PIDS[unbound]:-unknown}"
        METRIC_DOT_ACTIVE=0
    fi
}

# Teste la résolution DNS via Unbound avec retries pour laisser le temps
# aux connexions TLS et aux validations DNSSEC de se finaliser.
test_unbound_dns_robust() {
    local attempt=0
    local max_attempts=3

    while [ "$attempt" -lt "$max_attempts" ]; do
        attempt=$((attempt + 1))

        if command_exists dig; then
            if timeout 3 dig @127.0.0.1 -p 5053 \
                +tries=1 +timeout=2 example.com +short 2>/dev/null | grep -q .; then
                return 0
            fi
        elif command_exists nslookup; then
            if timeout 3 nslookup example.com 127.0.0.1 2>/dev/null | grep -q "Name:"; then
                return 0
            fi
        fi

        if [ "$attempt" -lt "$max_attempts" ]; then
            sleep 1
        fi
    done

    return 1
}

# Boucle de rafraîchissement des IPs DoT
_dot_refresh_loop() {
    local interval="${DOT_IP_REFRESH_INTERVAL:-3600}"
    
    log_json INFO "dot_refresh" "Starting periodic IP refresh" "interval=${interval}s"
    
    while true; do
        sleep "$interval"
        local dot_changed=0

        local servers="${DOT_DNS_SERVERS}"
        servers=$(echo "$servers" | tr ',' ' ')

        for entry in $servers; do
            local host new_ip old_ip
            host=$(echo "$entry" | sed 's|^[a-z]*://||' | awk -F'[:/]' '{print $1}')
            [ -z "$host" ] && continue

            new_ip=$(resolve_hostname "$host" "$DNS_SERVER_1" "$DNS_SERVER_2")
            old_ip=$(dot_ip_map_get "$host")

            if [ -z "$new_ip" ]; then
                log_json WARN "dot_refresh" "re-resolve failed" "host=${host}"
                continue
            fi

            if [ "$new_ip" = "$old_ip" ]; then
                log_json INFO "dot_refresh" "IP unchanged" "host=${host}" "ip=${new_ip}"
                continue
            fi

            log_json INFO "dot_refresh" "IP changed - preparing refresh" \
                "host=${host}" "old=${old_ip:-none}" "new=${new_ip}"

            ipt_add_853 "$new_ip"

            if configure_unbound; then
                local ub_pid
                ub_pid=$(pidof unbound | awk '{print $1}' || true)
                if [ -n "$ub_pid" ]; then
                    log_json INFO "dot_refresh" "Reloading unbound after config change" \
                        "pid=${ub_pid}" "host=${host}"

                    kill -HUP "$ub_pid" 2>/dev/null || true

                    local reload_ok=0
                    local reload_max_wait=15

                    for reload_attempt in $(seq 1 "$reload_max_wait"); do
                        sleep 1

                        if ! kill -0 "$ub_pid" 2>/dev/null; then
                            log_json WARN "dot_refresh" "unbound died during reload" \
                                "host=${host}"
                            break
                        fi

                        if test_unbound_dns_robust; then
                            reload_ok=1
                            break
                        fi
                    done

                    if [ "$reload_ok" -eq 1 ]; then
                        [ -n "$old_ip" ] && ipt_del_853 "$old_ip"
                        dot_ip_map_set "$host" "$new_ip"
                        dot_changed=1
                        log_json INFO "dot_refresh" "unbound reloaded successfully" \
                            "pid=${ub_pid}" "host=${host}" "new_ip=${new_ip}"
                    else
                        log_json WARN "dot_refresh" "unbound reload validation timeout" \
                            "host=${host}" "new_ip=${new_ip}"
                        ipt_del_853 "$new_ip"
                    fi
                else
                    log_json WARN "dot_refresh" "unbound not running while refreshing config"
                    ipt_del_853 "$new_ip"
                fi
            else
                log_json WARN "dot_refresh" "failed to regenerate unbound config after DoT IP change"
                ipt_del_853 "$new_ip"
            fi
        done

        if [ "$dot_changed" -eq 1 ]; then
            log_json INFO "dot_refresh" "DoT IP refresh complete" "changed=1"
        fi
    done
}

# Démarre la boucle de rafraîchissement DoT
start_dot_ip_refresh() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    local interval="${DOT_IP_REFRESH_INTERVAL:-3600}"
    log_json INFO "dot_refresh" "starting periodic IP refresh" "interval=${interval}s"

    _dot_refresh_loop &
    SERVICE_PIDS[dot_refresh]=$!
    log_json INFO "dot_refresh" "refresh loop started" "pid=${SERVICE_PIDS[dot_refresh]}"
}

# ===========================================================================
# Endpoint métriques Prometheus
# ===========================================================================

# Met à jour les fichiers de métriques
update_metrics() {
    printf '%s\n' "${METRIC_VPN_UP}" > "${METRICS_DIR}/metric_vpn_up" 2>/dev/null || true
    printf '%s\n' "${METRIC_RESTART_COUNT}" > "${METRICS_DIR}/metric_restart_count" 2>/dev/null || true
    printf '%s\n' "${METRIC_DOT_ACTIVE}" > "${METRICS_DIR}/metric_dot_active" 2>/dev/null || true
    printf '%s\n' "${METRIC_START_TS}" > "${METRICS_DIR}/metric_start_ts" 2>/dev/null || true
    printf '%s\n' "${METRIC_LAST_RESTART_TS}" > "${METRICS_DIR}/metric_last_restart_ts" 2>/dev/null || true
}

# Démarre le serveur de métriques
start_metrics() {
    [ "${ENABLE_METRICS:-false}" = "true" ] || return 0

    if ! command_exists nc; then
        log_json WARN "start_metrics" "nc not available - metrics disabled"
        return 0
    fi

    mkdir -p "$METRICS_DIR"

    cat > /tmp/metrics_handler.sh <<'HANDLER'
#!/bin/sh
vpn_up=$(cat /tmp/metrics/metric_vpn_up 2>/dev/null || echo 0)
restart_total=$(cat /tmp/metrics/metric_restart_count 2>/dev/null || echo 0)
dot_active=$(cat /tmp/metrics/metric_dot_active 2>/dev/null || echo 0)
start_ts=$(cat /tmp/metrics/metric_start_ts 2>/dev/null || echo 0)
last_restart=$(cat /tmp/metrics/metric_last_restart_ts 2>/dev/null || echo 0)
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

    if command_exists socat; then
        socat TCP-LISTEN:9100,bind=127.0.0.1,reuseaddr,fork EXEC:/tmp/metrics_handler.sh &
        SERVICE_PIDS[metrics]=$!
    else
        (
            while true; do
                nc -l 127.0.0.1 9100 < <(/tmp/metrics_handler.sh) 2>/dev/null || sleep 1
            done
        ) &
        SERVICE_PIDS[metrics]=$!
        log_json WARN "start_metrics" "socat not found, using nc fallback (one request at a time)"
    fi
    
    log_json INFO "start_metrics" "metrics endpoint started" \
        "pid=${SERVICE_PIDS[metrics]}" "addr=127.0.0.1:9100"
}

# ===========================================================================
# Drop capabilities
# ===========================================================================

drop_capabilities() {
    [ "${DROP_CAPS:-false}" = "true" ] || return 0

    if ! command_exists python3; then
        log_json WARN "drop_caps" "python3 not found - capability drop skipped"
        return 0
    fi

    log_json INFO "drop_caps" "dropping capabilities via prctl" \
        "retaining=cap_net_admin(12),cap_net_raw(13)"

    python3 - <<'PYCAPS'
import ctypes, sys, os

libc = ctypes.CDLL(None, use_errno=True)
PR_CAPBSET_DROP = 24
CAP_NET_RAW     = 13
CAP_NET_ADMIN   = 12
KEEP = {CAP_NET_ADMIN, CAP_NET_RAW}

errors = []
for cap in range(40):
    if cap in KEEP:
        continue
    ret = libc.prctl(PR_CAPBSET_DROP, ctypes.c_ulong(cap), 0, 0, 0)
    if ret != 0:
        err = ctypes.get_errno()
        if err != 22:
            errors.append(f"cap {cap}: errno {err}")

if errors:
    print(f"[drop_caps] some caps could not be dropped: {errors}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"[drop_caps] bounding set reduced - kept CAP_NET_ADMIN(12) CAP_NET_RAW(13)")
PYCAPS

    local rc=$?
    if [ $rc -eq 0 ]; then
        log_json INFO "drop_caps" "capabilities dropped successfully" \
            "retained=cap_net_admin,cap_net_raw"
    else
        log_json WARN "drop_caps" "capability drop had errors - check stderr above"
    fi
}

# ===========================================================================
# Configuration DNS
# ===========================================================================

# Configure dnsmasq
configure_dnsmasq() {
    log_json INFO "configure_dnsmasq" "Configuring dnsmasq"
    
    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        cat > "$DNSMASQ_CONF" <<EOF
# Generated at startup - DNS-over-TLS mode via local unbound
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=127.0.0.1#5053
cache-size=1000
log-facility=/dev/null
EOF
        log_json INFO "configure_dnsmasq" "DoT mode - upstream: 127.0.0.1#5053"
    else
        cat > "$DNSMASQ_CONF" <<EOF
# Generated at startup from DNS_SERVER_1 / DNS_SERVER_2
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=${DNS_SERVER_1}
server=${DNS_SERVER_2}
cache-size=1000
log-facility=/dev/null
EOF
        
        # Split DNS en mode classique via dnsmasq
        if [ -n "${DNS_SPLIT:-}" ]; then
            local entries
            entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')
            for entry in $entries; do
                local domain resolver res_ip res_port
                domain="${entry%%=*}" resolver="${entry#*=}"
                res_ip="${resolver%%:*}" res_port="${resolver##*:}"
                [ "$res_port" = "$res_ip" ] && res_port="53"
                [ -z "$domain" ] || [ -z "$res_ip" ] && continue
                echo "server=/${domain}/${res_ip}#${res_port}" >> "$DNSMASQ_CONF"
                log_json INFO "configure_dnsmasq" "split DNS" \
                    "domain=${domain}" "resolver=${res_ip}:${res_port}"
            done
        fi
        log_json INFO "configure_dnsmasq" "upstream: ${DNS_SERVER_1}, ${DNS_SERVER_2}"
    fi
}

# Démarre dnsmasq
start_dnsmasq() {
    log_json INFO "start_dnsmasq" "Starting dnsmasq"
    
    configure_dnsmasq

    echo "nameserver 127.0.0.1" > "$RESOLV_CONF" || {
        echo "nameserver 127.0.0.1" > /tmp/resolv.conf
        mount --bind /tmp/resolv.conf "$RESOLV_CONF" || true
    }

    if ! dnsmasq --test --conf-file="$DNSMASQ_CONF" >/tmp/dnsmasq.test 2>&1; then
        log_json ERROR "start_dnsmasq" "config test failed"
        sed -n '1,200p' /tmp/dnsmasq.test >&2 || true
        return 0
    fi

    dnsmasq --no-daemon --conf-file="$DNSMASQ_CONF" --log-facility=- &
    SERVICE_PIDS[dnsmasq]=$!

    local bound=0 i
    for i in 1 2 3 4 5; do
        nc -z -w 1 127.0.0.1 53 >/dev/null 2>&1 && { bound=1; break; }
        sleep 1
    done

    if [ "$bound" -eq 1 ]; then
        log_json INFO "start_dnsmasq" "started" "pid=${SERVICE_PIDS[dnsmasq]}" "port=53"
    else
        log_json ERROR "start_dnsmasq" "dnsmasq did not bind to 127.0.0.1:53"
    fi
}

# ===========================================================================
# Configuration Proxy
# ===========================================================================

# Configure l'authentification Privoxy
configure_privoxy_auth() {
    log_json INFO "configure_privoxy_auth" "Configuring Privoxy authentication"
    
    local user="${PROXY_USER:-}" pass="${PROXY_PASS:-}"
    if [ -n "$user" ] && [ -n "$pass" ]; then
        sed -i 's|^listen-address .*|listen-address 127.0.0.1:3129|' "$PRIVOXY_CONF"
        log_json INFO "configure_privoxy_auth" "auth enabled - privoxy on 127.0.0.1:3129"
    else
        sed -i 's|^listen-address .*|listen-address 0.0.0.0:3128|' "$PRIVOXY_CONF"
        log_json INFO "configure_privoxy_auth" "no auth - privoxy on 0.0.0.0:3128"
    fi
}

# Démarre Privoxy
start_privoxy() {
    log_json INFO "start_privoxy" "Starting Privoxy"
    
    configure_privoxy_auth
    /usr/sbin/privoxy --no-daemon "$PRIVOXY_CONF" &
    SERVICE_PIDS[privoxy]=$!
}

# Démarre nginx pour l'authentification proxy
start_nginx_auth() {
    log_json INFO "start_nginx_auth" "Starting nginx auth proxy"
    
    local user="${PROXY_USER:-}" pass="${PROXY_PASS:-}"
    [ -n "$user" ] && [ -n "$pass" ] || return 0

    if ! command_exists nginx; then
        log_json WARN "start_nginx_auth" "nginx not found - falling back to no-auth"
        sed -i 's|^listen-address .*|listen-address 0.0.0.0:3128|' "$PRIVOXY_CONF"
        return 0
    fi

    local htpasswd_file="/etc/nginx/.proxy_htpasswd"
    mkdir -p /etc/nginx
    htpasswd -cbB "$htpasswd_file" "$user" "$pass"
    chmod 600 "$htpasswd_file"

    local i
    for i in 1 2 3 4 5; do
        nc -z -w 1 127.0.0.1 3129 >/dev/null 2>&1 && break
        sleep 1
    done

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
    SERVICE_PIDS[nginx]=$!
    log_json INFO "start_nginx_auth" "started" \
        "pid=${SERVICE_PIDS[nginx]}" "frontend=0.0.0.0:3128" "backend=127.0.0.1:3129"
}

# Démarre OpenVPN
start_openvpn() {
    log_json INFO "start_openvpn" "Starting OpenVPN"
    
    /usr/local/bin/openvpn.sh &
    SERVICE_PIDS[vpn]=$!
}

# ===========================================================================
# Configuration Tailscale
# ===========================================================================

tailscale_has_state() {
    [ -s /var/lib/tailscale/tailscaled.state ]
}

tailscale_can_advertise_exit_node() {
    local ipv4_forward ipv6_forward
    ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
    ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0)
    [ "$ipv4_forward" = "1" ] && [ "$ipv6_forward" = "1" ]
}

build_tailscale_up_flags() {
    local up_flags="${TAILSCALE_FLAGS:-}"

    [ "${TAILSCALE_ACCEPT_ROUTES:-false}" = "true" ] && up_flags="$up_flags --accept-routes"
    [ -n "${TAILSCALE_HOSTNAME:-}" ] && up_flags="$up_flags --hostname=${TAILSCALE_HOSTNAME}"

    if [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ]; then
        if tailscale_can_advertise_exit_node; then
            up_flags="$up_flags --advertise-exit-node"
        else
            log_json WARN "start_tailscale" \
                "exit-node advertisement requested but forwarding sysctls are disabled" \
                "required=net.ipv4.ip_forward=1,net.ipv6.conf.all.forwarding=1"
        fi
    fi

    printf '%s\n' "$up_flags"
}

run_tailscale_up_async() {
    local up_flags="$1"

    log_json INFO "start_tailscale" "running 'tailscale up'"
    # shellcheck disable=SC2086
    (tailscale up --accept-dns=false $up_flags > /var/log/tailscale-up.log 2>&1) &
}

start_tailscale() {
    log_json INFO "start_tailscale" "Starting Tailscale"
    
    [ "${ENABLE_TAILSCALE:-false}" = "true" ] || return 0

    if ! command_exists tailscaled; then
        log_json WARN "start_tailscale" "tailscaled not installed - skipping"
        return 0
    fi

    mkdir -p /var/lib/tailscale "$TAILSCALE_RUN_DIR" || true
    log_json INFO "start_tailscale" "starting tailscaled"

    tailscaled \
        --state="/var/lib/tailscale/tailscaled.state" \
        --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" \
        >/var/log/tailscaled.log 2>&1 &
    export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
    SERVICE_PIDS[tailscaled]=$!

    local waited=0
    until tailscale status >/dev/null 2>&1 || [ "$waited" -ge 20 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    if ! tailscale status >/dev/null 2>&1; then
        log_json WARN "start_tailscale" "tailscale daemon socket not ready after wait window"
    fi

    local up_flags
    up_flags=$(build_tailscale_up_flags)

    if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
        up_flags="--authkey=${TAILSCALE_AUTHKEY} ${up_flags}"
        run_tailscale_up_async "$up_flags"
        return 0
    fi

    if tailscale_has_state; then
        log_json INFO "start_tailscale" "existing tailscale state detected - refreshing settings without authkey"
        run_tailscale_up_async "$up_flags"
        return 0
    fi

    log_json WARN "start_tailscale" "no authkey and no persisted state - skipping 'tailscale up'"
}

# ===========================================================================
# Vérification de l'IP VPN
# ===========================================================================

check_vpn_ip() {
    log_json INFO "check_vpn_ip" "Checking VPN public IP"
    
    if ! command_exists curl; then
        log_json WARN "check_vpn_ip" "curl not available, skipping public IP check"
        return 0
    fi

    local proxy_port
    proxy_port=$(get_privoxy_port)

    # Vérifier que Privoxy est prêt
    if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
        log_json WARN "check_vpn_ip" "Privoxy not ready on port ${proxy_port}, skipping public IP check"
        return 0
    fi

    local public_ip
    local proxy_url="http://127.0.0.1:${proxy_port}"
    if [ -n "${PROXY_USER:-}" ] && [ -n "${PROXY_PASS:-}" ]; then
        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${proxy_port}"
    fi

    # Utiliser HEALTHCHECK_IP pour le test de connectivité
    public_ip=$(curl -fsS --max-time 20 --retry 3 --retry-delay 2 --proxy "$proxy_url" \
        "https://api.ipify.org" 2>/dev/null || true)

    if [ -n "$public_ip" ]; then
        log_json INFO "check_vpn_ip" "public IP via VPN confirmed" "ip=${public_ip}"
        METRIC_VPN_UP=1
    else
        # Fallback : vérifier la connectivité via un ping vers HEALTHCHECK_IP
        if ping -c 1 -W 5 "$HEALTHCHECK_IP" >/dev/null 2>&1; then
            log_json INFO "check_vpn_ip" "VPN connectivity confirmed (ping to ${HEALTHCHECK_IP})"
            METRIC_VPN_UP=1
        else
            log_json WARN "check_vpn_ip" "could not determine public IP (tunnel may still be initializing)"
        fi
    fi
}

# ===========================================================================
# Monitoring OpenVPN
# ===========================================================================

check_openvpn_routing() {
    command_exists ip || return 0
    vpn_tunnel_ready
}

restart_openvpn() {
    log_json WARN "supervisor" "restarting openvpn" "pid=${SERVICE_PIDS[vpn]:-unknown}"
    kill_if_running "${SERVICE_PIDS[vpn]}"
    [ -n "${SERVICE_PIDS[vpn]}" ] && wait "${SERVICE_PIDS[vpn]}" 2>/dev/null || true
    SERVICE_PIDS[vpn]=0
    start_openvpn
    local i
    for i in 1 2 3 4 5; do
        sleep 1
        if check_openvpn_routing; then
            log_json INFO "supervisor" "openvpn routing restored" "pid=${SERVICE_PIDS[vpn]}"
            return 0
        fi
    done
    log_json ERROR "supervisor" "openvpn routing still not functional after restart"
    return 1
}

run_service_healthcheck() {
    local log_file="/tmp/healthcheck.log"
    local max_retries=3
    local retry=0
    local success=0

    while [ $retry -lt $max_retries ]; do
        if /usr/local/bin/healthcheck.sh >"$log_file" 2>&1; then
            success=1
            break
        fi
        retry=$((retry + 1))
        log_json WARN "supervisor" "healthcheck failed (attempt ${retry}/${max_retries}) - retrying in 5s"
        sleep 5
    done

    if [ $success -eq 0 ]; then
        cat "$log_file" >&2 || true
        log_json WARN "supervisor" "healthcheck failed after ${max_retries} retries - restarting services"
        rm -f "$VPN_HEALTHY_FILE"
        METRIC_VPN_UP=0
        return 1
    fi
    return 0
}

# ===========================================================================
# Superviseur principal
# ===========================================================================

supervise_all() {
    log_json INFO "supervisor" "Starting supervisor" "version=2.0.0"
    
    local attempt=0

    # Valider l'environnement
    validate_environment

    # Configurer un DNS temporaire avec DNS_SERVER_1 et DNS_SERVER_2
    cp "$RESOLV_CONF" /tmp/resolv.conf.bak 2>/dev/null || true
    echo "nameserver ${DNS_SERVER_1}" > "$RESOLV_CONF"
    echo "nameserver ${DNS_SERVER_2}" >> "$RESOLV_CONF"

    while true; do
        attempt=$((attempt + 1))
        METRIC_RESTART_COUNT=$((attempt - 1))
        METRIC_LAST_RESTART_TS=$(date +%s)

        # Démarrer unbound EN PREMIER (pour résoudre les IPs DoT)
        start_unbound
        start_dnsmasq

        # Attendre que DNS soit prêt (unbound + dnsmasq)
        if [ "${ENABLE_DOT:-false}" = "true" ]; then
            log_json INFO "supervisor" "waiting for DNS services to be ready..."
            local dns_ready=0
            for i in $(seq 1 60); do
                if nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1 && test_unbound_dns_robust; then
                    dns_ready=1
                    break
                fi
                sleep 2
            done
            if [ "$dns_ready" -ne 1 ]; then
                log_json ERROR "supervisor" "DNS services (unbound/dnsmasq) not ready after 10s retrying"
                continue
            fi
        else
            # Mode non-DoT : vérifier que dnsmasq répond
            local dns_ready=0
            for i in 1 2 3 4 5; do
                if nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                    dns_ready=1
                    break
                fi
                sleep 2
            done
            if [ "$dns_ready" -ne 1 ]; then
                log_json ERROR "supervisor" "dnsmasq not ready after 10s - retrying"
                continue
            fi
        fi

        setup_iptables
        setup_ip6tables
        start_privoxy
        start_nginx_auth
        start_openvpn

        # Services auxiliaires : démarrés une seule fois
        if [ "$attempt" -eq 1 ]; then
            start_metrics
            start_dot_ip_refresh
        fi

        log_json INFO "supervisor" "waiting for OpenVPN tunnel..."
        local tun_ready=0
        if wait_for_vpn_tunnel 30; then
            tun_ready=1
        fi

        if [ "$tun_ready" -eq 1 ]; then
            setup_return_routes
            check_vpn_ip

            # Attendre que le tunnel soit pleinement opérationnel
            log_json INFO "supervisor" "waiting for tunnel to be fully operational..."
            local full_ready=0
            for i in 1 2 3; do
                if check_vpn_ip && nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                    full_ready=1
                    break
                fi
                sleep 5
            done

            if [ "$full_ready" -eq 1 ]; then
                touch "$VPN_HEALTHY_FILE"
                METRIC_VPN_UP=1
                start_tailscale
            else
                log_json WARN "supervisor" "tunnel not fully operational after 15s - skipping Tailscale"
                rm -f "$VPN_HEALTHY_FILE"
                METRIC_VPN_UP=0
            fi
        else
            log_json WARN "supervisor" "tunnel not ready after 30s - skipping return routes"
            rm -f "$VPN_HEALTHY_FILE"
            METRIC_VPN_UP=0
        fi

        # Drop capabilities après le 1er démarrage complet
        [ "$attempt" -eq 1 ] && drop_capabilities

        update_metrics

        log_json INFO "supervisor" "all services running" \
            "vpn=${SERVICE_PIDS[vpn]}" \
            "dnsmasq=${SERVICE_PIDS[dnsmasq]:-unknown}" \
            "privoxy=${SERVICE_PIDS[privoxy]:-unknown}" \
            "nginx_auth=${SERVICE_PIDS[nginx]:-disabled}" \
            "unbound=${SERVICE_PIDS[unbound]:-disabled}" \
            "metrics=${SERVICE_PIDS[metrics]:-disabled}" \
            "dot_refresh=${SERVICE_PIDS[dot_refresh]:-disabled}"

        # Attendre 20s avant le premier healthcheck
        log_json INFO "supervisor" "waiting 20s before first healthcheck..."
        sleep 20

        local fail=0
        local start_time=$(date +%s)
        local stable_cycles=0

        while true; do
            sleep 10
            local current_time=$(date +%s)
            local elapsed_minutes=$(( (current_time - start_time) / 60 ))

            # Sauter le healthcheck pendant les premières minutes
            if [ "$elapsed_minutes" -lt "$SKIP_HEALTHCHECK_FIRST_MINUTES" ]; then
                log_json INFO "supervisor" "skipping healthcheck (elapsed: ${elapsed_minutes}min < ${SKIP_HEALTHCHECK_FIRST_MINUTES}min)"
                continue
            fi

            # OpenVPN process
            if ! is_process_running "${SERVICE_PIDS[vpn]}"; then
                log_json ERROR "supervisor" "openvpn process died"
                fail=1
            fi

            # OpenVPN routing
            if [ "$fail" -eq 0 ] && ! check_openvpn_routing; then
                log_json WARN "supervisor" "openvpn routing failure"
                rm -f "$VPN_HEALTHY_FILE"
                METRIC_VPN_UP=0
                if restart_openvpn; then
                    setup_return_routes
                    check_vpn_ip
                    touch "$VPN_HEALTHY_FILE"
                    METRIC_VPN_UP=1
                    update_metrics
                    continue
                else
                    fail=1
                fi
            fi

            # Privoxy
            local proxy_port
            proxy_port=$(get_privoxy_port)
            if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
                log_json ERROR "supervisor" "privoxy not listening" "port=${proxy_port}"
                fail=1
            fi

            # nginx auth proxy
            if [ -n "${SERVICE_PIDS[nginx]}" ]; then
                if ! is_process_running "${SERVICE_PIDS[nginx]}"; then
                    log_json ERROR "supervisor" "nginx auth proxy died"
                    fail=1
                elif ! nc -z -w 3 127.0.0.1 3128 >/dev/null 2>&1; then
                    log_json ERROR "supervisor" "nginx auth proxy not listening"
                    fail=1
                fi
            fi

            # unbound
            if [ "${ENABLE_DOT:-false}" = "true" ] && [ -n "${SERVICE_PIDS[unbound]}" ]; then
                if ! is_process_running "${SERVICE_PIDS[unbound]}"; then
                    log_json ERROR "supervisor" "unbound process died"
                    fail=1
                    METRIC_DOT_ACTIVE=0
                elif ! nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
                    log_json ERROR "supervisor" "unbound not listening on 5053"
                    fail=1
                    METRIC_DOT_ACTIVE=0
                fi
            fi

            # dnsmasq
            if [ -n "${SERVICE_PIDS[dnsmasq]}" ]; then
                if ! is_process_running "${SERVICE_PIDS[dnsmasq]}"; then
                    log_json ERROR "supervisor" "dnsmasq process died"
                    fail=1
                elif ! nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                    log_json ERROR "supervisor" "DNS resolution via 127.0.0.1 failed"
                    fail=1
                fi
            fi

            # Tailscale
            if [ -n "${SERVICE_PIDS[tailscaled]}" ] && ! is_process_running "${SERVICE_PIDS[tailscaled]}"; then
                log_json ERROR "supervisor" "tailscaled process died"
                fail=1
            fi

            if [ "$fail" -eq 0 ] && ! run_service_healthcheck; then
                fail=1
            fi

            [ "$fail" -eq 1 ] && break

            update_metrics

            stable_cycles=$((stable_cycles + 1))
            if [ "$stable_cycles" -ge 6 ] && [ "$attempt" -gt 1 ]; then
                attempt=1
                stable_cycles=0
                log_json INFO "supervisor" "services stable - backoff counter reset"
            fi
        done

        log_json ERROR "supervisor" "failure detected - restarting services" "attempt=${attempt}"
        rm -f "$VPN_HEALTHY_FILE"
        METRIC_VPN_UP=0
        METRIC_LAST_RESTART_TS=$(date +%s)
        update_metrics

        # Arrêter tous les services
        kill_if_running "${SERVICE_PIDS[vpn]}"
        kill_if_running "${SERVICE_PIDS[privoxy]}"
        kill_if_running "${SERVICE_PIDS[nginx]}"
        kill_if_running "${SERVICE_PIDS[dnsmasq]}"
        kill_if_running "${SERVICE_PIDS[tailscaled]}"
        kill_if_running "${SERVICE_PIDS[unbound]}"
        
        # Attendre que les processus se terminent
        local pids_to_wait=""
        for pid in "${SERVICE_PIDS[vpn]}" "${SERVICE_PIDS[privoxy]}" "${SERVICE_PIDS[nginx]}" \
                   "${SERVICE_PIDS[dnsmasq]}" "${SERVICE_PIDS[tailscaled]}" "${SERVICE_PIDS[unbound]}"; do
            [ -n "$pid" ] && [ "$pid" -ne 0 ] && pids_to_wait="$pids_to_wait $pid"
        done
        [ -n "$pids_to_wait" ] && wait $pids_to_wait 2>/dev/null || true

        # Réinitialiser les PIDs
        SERVICE_PIDS[vpn]=0
        SERVICE_PIDS[privoxy]=0
        SERVICE_PIDS[nginx]=0
        SERVICE_PIDS[dnsmasq]=0
        SERVICE_PIDS[tailscaled]=0
        SERVICE_PIDS[unbound]=0
        
        DOT_RESOLVED_IPS=""
        unset DOT_HOST_IP_MAP
        declare -gA DOT_HOST_IP_MAP=()

        local sleep_s=$((5 * attempt))
        [ "$sleep_s" -gt 60 ] && sleep_s=60
        log_json INFO "supervisor" "restarting in ${sleep_s}s" "attempt=${attempt}"
        sleep "$sleep_s"
    done
}

# ===========================================================================
# Gestion des signaux
# ===========================================================================

# Nettoyage à la sortie
cleanup() {
    log_json INFO "cleanup" "Cleaning up services"
    
    # Arrêter tous les services
    for service in "${!SERVICE_PIDS[@]}"; do
        kill_if_running "${SERVICE_PIDS[$service]}"
    done
    
    # Attendre que les processus se terminent
    local all_pids=""
    for pid in "${SERVICE_PIDS[@]}"; do
        [ -n "$pid" ] && [ "$pid" -ne 0 ] && all_pids="$all_pids $pid"
    done
    [ -n "$all_pids" ] && wait $all_pids 2>/dev/null || true
    
    log_json INFO "cleanup" "All services stopped"
    exit 0
}

# Configurer les traps pour les signaux
trap cleanup INT TERM

# ===========================================================================
# Point d'entrée principal
# ===========================================================================

log_json INFO "start.sh" "Starting openvpn_client_proxy" "version=2.0.0"

# Créer le répertoire pour les métriques
mkdir -p "$METRICS_DIR"

# Démarrer le superviseur
supervise_all
