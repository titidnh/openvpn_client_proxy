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
# Auteur: Vibe Code
# Licence: MIT
# Version: 2.1.0
# ===========================================================================

set -euo pipefail

# ===========================================================================
# Initialisation
# ===========================================================================

source "/usr/local/lib/common.sh"

init_environment

# ===========================================================================
# Configuration globale
# ===========================================================================

readonly VPN_DIR="/vpn"
readonly VPN_CONF="${VPN_DIR}/vpn.conf"
readonly DNSMASQ_CONF="/etc/dnsmasq.conf"
readonly PRIVOXY_CONF="/etc/privoxy/privoxy.config"
readonly UNBOUND_CONF="/etc/unbound/unbound.conf"
readonly RESOLV_CONF="/etc/resolv.conf"

readonly DOT_IP_MAP_FILE="/tmp/dot_ip_map"
readonly DOT_FORWARD_ADDRS_FILE="/tmp/dot_forward_addrs"
readonly VPN_HEALTHY_FILE="/tmp/vpn_healthy"
readonly METRICS_DIR="/tmp/metrics"

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

declare -g METRIC_RESTART_COUNT=0
declare -g METRIC_VPN_UP=0
declare -g METRIC_DOT_ACTIVE=0
declare -g METRIC_LAST_RESTART_TS=0
declare -g METRIC_START_TS
METRIC_START_TS=$(date +%s)

declare -g DOT_RESOLVED_IPS=""
declare -gA DOT_HOST_IP_MAP=()

# ===========================================================================
# Validation de l'environnement
# ===========================================================================

validate_environment() {
    log_json INFO "validate_environment" "Validating environment variables"

    local bool_vars=(
        "ENABLE_TAILSCALE"
        "ENABLE_DOT"
        "ENABLE_DNSSEC"
        "ENABLE_METRICS"
        "DROP_CAPS"
        "TAILSCALE_ACCEPT_ROUTES"
        "TAILSCALE_ADVERTISE_EXIT_NODE"
    )

    local var
    for var in "${bool_vars[@]}"; do
        local value="${!var:-false}"

        if ! validate_boolean "$var" "$value"; then
            log_json WARN "validate_environment" \
                "Invalid boolean value for ${var}, using default" \
                "value=${value}"
            export "$var"="false"
        fi
    done

    if [ -n "${PROXY_PORT:-}" ]; then
        validate_port "PROXY_PORT" "$PROXY_PORT" ||
            export PROXY_PORT="$DEFAULT_PROXY_PORT"
    fi

    if [ -n "${DNS_SERVER_1:-}" ]; then
        validate_ip "DNS_SERVER_1" "$DNS_SERVER_1" ||
            export DNS_SERVER_1="$DEFAULT_DNS_SERVER_1"
    fi

    if [ -n "${DNS_SERVER_2:-}" ]; then
        validate_ip "DNS_SERVER_2" "$DNS_SERVER_2" ||
            export DNS_SERVER_2="$DEFAULT_DNS_SERVER_2"
    fi

    log_json INFO "validate_environment" "Environment validation complete"
}

# ===========================================================================
# Firewall
# ===========================================================================

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

setup_iptables() {
    log_json INFO "setup_iptables" "Configuring IPv4 firewall"

    local docker_network
    docker_network=$(
        ip -o addr show dev eth0 2>/dev/null |
            awk '$3=="inet"{print $4}' || true
    )

    get_vpn_port_proto "$VPN_CONF"

    iptables -F
    iptables -X
    iptables -t nat -F

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # DNS initial
    for dns in "$DNS_SERVER_1" "$DNS_SERVER_2"; do
        iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
    done

    # Healthcheck
    iptables -A OUTPUT -p tcp -d "$HEALTHCHECK_IP" --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp -d "$HEALTHCHECK_IP" --dport 443 -j ACCEPT
    iptables -A OUTPUT -p udp -d "$HEALTHCHECK_IP" --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d "$HEALTHCHECK_IP" --dport 53 -j ACCEPT

    # INPUT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT

    if [ -n "$docker_network" ]; then
        iptables -A INPUT -s "$docker_network" -j ACCEPT
    fi

    # FORWARD
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i lo -j ACCEPT

    if [ -n "$docker_network" ]; then
        iptables -A FORWARD -s "$docker_network" -j ACCEPT
        iptables -A FORWARD -d "$docker_network" -j ACCEPT
    fi

    iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i tap+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # OUTPUT - interfaces autorisées
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tun+ -j ACCEPT
    iptables -A OUTPUT -o tap+ -j ACCEPT
    iptables -A OUTPUT -o tailscale+ -j ACCEPT

    if [ -n "$docker_network" ]; then
        iptables -A OUTPUT -d "$docker_network" -j ACCEPT
    fi

    # Métriques
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 9100 -j ACCEPT

    # DNS local
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 5053 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 5053 -j ACCEPT

    # DoT
    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        if [ -n "$DOT_RESOLVED_IPS" ]; then
            local dot_ip

            for dot_ip in $DOT_RESOLVED_IPS; do
                ipt_add_853 "$dot_ip"

                log_json INFO "setup_iptables" \
                    "DoT: allowing TCP 853" \
                    "ip=${dot_ip}"
            done
        else
            log_json WARN "setup_iptables" \
                "DoT: no resolved IPs - TCP 853 not explicitly allowed"
        fi

        # Kill switch DNS externe.
        iptables -A OUTPUT -p udp ! -d 127.0.0.0/8 --dport 53 -j DROP
        iptables -A OUTPUT -p tcp ! -d 127.0.0.0/8 --dport 53 -j DROP

        log_json INFO "setup_iptables" \
            "DoT DNS leak prevention: external port 53 blocked"
    else
        # Mode DNS classique.
        local _dns

        for _dns in "$DNS_SERVER_1" "$DNS_SERVER_2"; do
            [[ "$_dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue

            iptables -A OUTPUT -p udp -d "$_dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$_dns" --dport 53 -j ACCEPT

            log_json INFO "setup_iptables" \
                "allowing port 53" \
                "ip=${_dns}"
        done

        while read -r _dns; do
            [[ "$_dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue

            iptables -A OUTPUT -p udp -d "$_dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$_dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams "$DNSMASQ_CONF")
    fi

    # DNS Docker interne.
    if grep -Fq "127.0.0.11" "$RESOLV_CONF" 2>/dev/null; then
        iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT
        iptables -A OUTPUT -p udp -d 127.0.0.11 --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d 127.0.0.11 --dport 53 -j ACCEPT
    fi

    # OpenVPN.
    iptables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true

    # NAT.
    iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    log_json INFO "setup_iptables" \
        "IPv4 configured - kill switch active" \
        "vpn_proto=${VPN_PROTO}" \
        "vpn_port=${VPN_PORT}"
}

setup_ip6tables() {
    log_json INFO "setup_ip6tables" "Configuring IPv6 firewall"

    if ! command_exists ip6tables; then
        log_json WARN "setup_ip6tables" \
            "ip6tables not installed, skipping"
        return 0
    fi

    if [ ! -f /proc/net/if_inet6 ]; then
        log_json WARN "setup_ip6tables" \
            "IPv6 not available, skipping"
        return 0
    fi

    local docker6_network

    docker6_network=$(
        ip -o addr show dev eth0 2>/dev/null |
            awk '$3=="inet6"{print $4; exit}' || true
    )

    ipt6 -F
    ipt6 -X
    ipt6 -t nat -F

    ipt6 -P INPUT DROP
    ipt6 -P FORWARD DROP
    ipt6 -P OUTPUT DROP

    ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A INPUT -p icmpv6 -j ACCEPT
    ipt6 -A INPUT -i lo -j ACCEPT

    if [ -n "$docker6_network" ]; then
        ipt6 -A INPUT -s "$docker6_network" -j ACCEPT
    fi

    ipt6 -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -p icmpv6 -j ACCEPT
    ipt6 -A FORWARD -i lo -j ACCEPT

    if [ -n "$docker6_network" ]; then
        ipt6 -A FORWARD -s "$docker6_network" -j ACCEPT
        ipt6 -A FORWARD -d "$docker6_network" -j ACCEPT
    fi

    ipt6 -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    ipt6 -A FORWARD -i tun+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i tap+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A OUTPUT -o lo -j ACCEPT
    ipt6 -A OUTPUT -o tun+ -j ACCEPT
    ipt6 -A OUTPUT -o tap+ -j ACCEPT
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT

    if [ -n "$docker6_network" ]; then
        ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT
    fi

    ipt6 -A OUTPUT -p tcp -d ::1 --dport 9100 -j ACCEPT

    ipt6 -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p udp -d ::1 --dport 5053 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 5053 -j ACCEPT

    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        ipt6 -A OUTPUT -p udp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true
        ipt6 -A OUTPUT -p tcp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true

        log_json INFO "setup_ip6tables" \
            "DoT DNS leak prevention: IPv6 port 53 blocked"
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

    log_json INFO "setup_ip6tables" \
        "IPv6 configured - kill switch active"
}

# ===========================================================================
# Routes
# ===========================================================================

setup_return_routes() {
    log_json INFO "setup_return_routes" "Configuring return routes"

    local iface gw gw6 ips ip6s ip

    iface=$(
        ip route 2>/dev/null |
            awk '/^default/{print $5; exit}'
    )

    if [ -z "$iface" ]; then
        log_json WARN "setup_return_routes" \
            "no default interface found, skipping"
        return 0
    fi

    gw=$(
        ip -4 route show dev "$iface" 2>/dev/null |
            awk '/default/{print $3; exit}'
    )

    gw6=$(
        ip -6 route show dev "$iface" 2>/dev/null |
            awk '/default/{print $3; exit}'
    )

    ips=$(
        ip -4 addr show dev "$iface" 2>/dev/null |
            awk -F'[ /]+' '/inet /{print $3}'
    )

    ip6s=$(
        ip -6 addr show dev "$iface" 2>/dev/null |
            awk -F'[ /]+' '/inet6.*global/{print $3}'
    )

    for ip in $ips; do
        if ! ip -4 rule show table 10 2>/dev/null | grep -q "$ip"; then
            ip rule add from "$ip" lookup 10 2>/dev/null || true
        fi

        if ! iptables -C INPUT -d "$ip" -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -d "$ip" -j ACCEPT
        fi
    done

    if [ -n "$gw" ]; then
        if ! ip -4 route show table 10 2>/dev/null | grep -q "default"; then
            ip route add default via "$gw" table 10 2>/dev/null || true
        fi
    fi

    local ip6
    for ip6 in $ip6s; do
        if ! ip -6 rule show table 10 2>/dev/null | grep -q "$ip6"; then
            ip -6 rule add from "$ip6" lookup 10 2>/dev/null || true
        fi

        if ! ipt6 -C INPUT -d "$ip6" -j ACCEPT 2>/dev/null; then
            ipt6 -A INPUT -d "$ip6" -j ACCEPT
        fi
    done

    if [ -n "$gw6" ]; then
        if ! ip -6 route show table 10 2>/dev/null | grep -q "default"; then
            ip -6 route add default via "$gw6" table 10 2>/dev/null || true
        fi
    fi

    log_json INFO "setup_return_routes" \
        "return routes configured" \
        "iface=${iface}"
}

cleanup_routes_on_restart() {
    local tun_dev

    tun_dev=$(find_vpn_interface || true)

    if [ -n "$tun_dev" ] &&
        ip link show "$tun_dev" >/dev/null 2>&1; then

        log_json DEBUG "supervisor" \
            "cleaning up TUN device" \
            "dev=$tun_dev"

        timeout 3 ip addr flush dev "$tun_dev" 2>/dev/null || true
    fi

    timeout 3 ip route del default via 0.0.0.0 2>/dev/null || true
    timeout 3 ip route del 0.0.0.0/1 via 10.0.0.0 2>/dev/null || true
}

# ===========================================================================
# DNS-over-TLS / Unbound
# ===========================================================================

dot_ip_map_set() {
    local host="$1"
    local ip="$2"
    local tmp

    DOT_HOST_IP_MAP["$host"]="$ip"

    tmp=$(temp_file "dot_ip_map")

    if [ -f "$DOT_IP_MAP_FILE" ]; then
        grep -v "^${host}=" "$DOT_IP_MAP_FILE" > "$tmp" || true
    fi

    echo "${host}=${ip}" >> "$tmp"
    mv -f "$tmp" "$DOT_IP_MAP_FILE"
}

dot_ip_map_get() {
    local host="$1"

    if [ -n "${DOT_HOST_IP_MAP[$host]:-}" ]; then
        echo "${DOT_HOST_IP_MAP[$host]}"
    elif [ -f "$DOT_IP_MAP_FILE" ]; then
        grep "^${host}=" "$DOT_IP_MAP_FILE" |
            cut -d= -f2- |
            tail -1
    fi
}

parse_dot_servers() {
    log_json INFO "parse_dot_servers" "Parsing DoT servers"

    local servers="${DOT_DNS_SERVERS}"
    servers=$(echo "$servers" | tr ',' ' ')

    local tmp_map tmp_forward
    tmp_map=$(temp_file "dot_ip_map")
    tmp_forward=$(temp_file "dot_forward_addrs")

    DOT_RESOLVED_IPS=""
    DOT_HOST_IP_MAP=()

    local entry
    for entry in $servers; do
        local proto host ip attempt max_attempts backoff

        proto=$(echo "$entry" | awk -F'://' '{print $1}')
        host=$(echo "$entry" |
            sed 's|^[a-z]*://||' |
            awk -F'[:/]' '{print $1}')

        [ -z "$host" ] && continue

        # FIX STABILITÉ #1 : Retry with exponential backoff for DoT host resolution
        ip=""
        max_attempts=5
        backoff=1
        
        for attempt in $(seq 1 "$max_attempts"); do
            ip=$(resolve_hostname \
                "$host" \
                "$DNS_SERVER_1" \
                "$DNS_SERVER_2" 2>/dev/null || true)

            if [ -n "$ip" ]; then
                if [ "$attempt" -gt 1 ]; then
                    log_json INFO "parse_dot_servers" \
                        "resolved after retry" \
                        "host=${host}" \
                        "ip=${ip}" \
                        "attempts=${attempt}"
                fi
                break
            fi

            if [ "$attempt" -lt "$max_attempts" ]; then
                log_json WARN "parse_dot_servers" \
                    "resolve attempt failed, retrying" \
                    "host=${host}" \
                    "attempt=${attempt}/${max_attempts}" \
                    "wait=${backoff}s"
                
                sleep "$backoff"
                backoff=$((backoff * 2))
                
                if [ "$backoff" -gt 10 ]; then
                    backoff=10
                fi
            fi
        done

        if [ -n "$ip" ]; then
            DOT_RESOLVED_IPS="${DOT_RESOLVED_IPS}${ip} "
            DOT_HOST_IP_MAP["$host"]="$ip"

            echo "${host}=${ip}" >> "$tmp_map"

            if [ "$proto" = "https" ]; then
                echo "        forward-addr: ${ip}@443#${host}" \
                    >> "$tmp_forward"
            else
                echo "        forward-addr: ${ip}@853#${host}" \
                    >> "$tmp_forward"
            fi

            log_json INFO "parse_dot_servers" \
                "resolved" \
                "host=${host}" \
                "ip=${ip}" \
                "proto=${proto}"
        else
            log_json WARN "parse_dot_servers" \
                "could not resolve after max retries, skipping" \
                "host=${host}" \
                "max_attempts=${max_attempts}"
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

configure_unbound() {
    log_json INFO "configure_unbound" \
        "Configuring Unbound for DoT"

    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    if ! command_exists unbound; then
        log_json ERROR "configure_unbound" \
            "unbound binary not found - DoT disabled"
        return 1
    fi

    local conf_file
    conf_file=$(temp_file "unbound")

    parse_dot_servers

    if [ ! -s "$DOT_FORWARD_ADDRS_FILE" ]; then
        log_json ERROR "configure_unbound" \
            "no valid DoT servers parsed - DoT disabled"
        rm -f "$conf_file"
        return 1
    fi

    local forward_addrs
    forward_addrs=$(cat "$DOT_FORWARD_ADDRS_FILE")

    local dnssec_mode="val-permissive-mode: yes"

    if [ "${ENABLE_DNSSEC:-false}" = "true" ]; then
        dnssec_mode="val-permissive-mode: no"

        mkdir -p /var/lib/unbound
        chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true

        unbound-anchor \
            -a /var/lib/unbound/root.key \
            2>/dev/null || true

        log_json INFO "configure_unbound" \
            "DNSSEC strict validation enabled"
    fi

    local tls_cert_bundle="/etc/ssl/certs/ca-certificates.crt"

    if [ -n "${DOT_TLS_CERT_BUNDLE:-}" ] &&
        [ -f "${DOT_TLS_CERT_BUNDLE}" ]; then

        tls_cert_bundle="${DOT_TLS_CERT_BUNDLE}"

        log_json INFO "configure_unbound" \
            "TLS cert bundle (pinning)" \
            "bundle=${tls_cert_bundle}"
    fi

    local split_zones=""

    if [ -n "${DNS_SPLIT:-}" ]; then
        local split_entries
        split_entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')

        local entry
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

            log_json INFO "configure_unbound" \
                "split DNS zone" \
                "domain=${domain}" \
                "resolver=${res_ip}:${res_port}"
        done
    fi

    mkdir -p /etc/unbound /var/lib/unbound
    chown -R unbound:unbound \
        /etc/unbound \
        /var/lib/unbound \
        2>/dev/null || true

    chmod 0755 /etc/unbound 2>/dev/null || true

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

    hide-identity: yes
    hide-version: yes

    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    use-caps-for-id: yes
    unwanted-reply-threshold: 10000000

    cache-min-ttl: 60
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 86400

    tls-cert-bundle: ${tls_cert_bundle}

    ${dnssec_mode}
EOF

    if [ "${ENABLE_DNSSEC:-false}" = "true" ] &&
        [ -f /var/lib/unbound/root.key ]; then

        echo "    auto-trust-anchor-file: /var/lib/unbound/root.key" \
            >> "$conf_file"
    fi

    cat >> "$conf_file" <<EOF

forward-zone:
    name: "."
    forward-tls-upstream: yes
${forward_addrs}
EOF

    [ -n "$split_zones" ] && echo "$split_zones" >> "$conf_file"

    if command_exists unbound-checkconf; then
        if ! unbound-checkconf "$conf_file" \
            >/tmp/unbound.checkconf 2>&1; then

            log_json ERROR "configure_unbound" \
                "unbound config test failed"

            cat /tmp/unbound.checkconf >&2 || true

            mv -f "$conf_file" \
                "${UNBOUND_CONF}.invalid" \
                2>/dev/null || true

            chmod 0644 "${UNBOUND_CONF}.invalid" \
                2>/dev/null || true

            chown unbound:unbound \
                "${UNBOUND_CONF}.invalid" \
                2>/dev/null || true

            cp -f "${UNBOUND_CONF}.invalid" \
                "$UNBOUND_CONF" \
                2>/dev/null || true
        fi
    else
        log_json WARN "configure_unbound" \
            "unbound-checkconf not found - skipping syntax check"
    fi

    if [ -f "$conf_file" ]; then
        mv -f "$conf_file" "$UNBOUND_CONF" 2>/dev/null || true
    fi

    chmod 0644 "$UNBOUND_CONF" 2>/dev/null || true
    chown unbound:unbound "$UNBOUND_CONF" 2>/dev/null || true

    touch /var/log/unbound.log 2>/dev/null || true
    chown unbound:unbound \
        /var/log/unbound.log \
        2>/dev/null || true

    chmod 0644 "$UNBOUND_CONF" 2>/dev/null || true

    log_json INFO "configure_unbound" \
        "config written" \
        "dnssec=${ENABLE_DNSSEC:-false}" \
        "tls_bundle=${tls_cert_bundle}" \
        "split_dns=${DNS_SPLIT:-none}"
}

test_unbound_dns_robust() {
    local attempt=0
    local max_attempts=6

    while [ "$attempt" -lt "$max_attempts" ]; do
        attempt=$((attempt + 1))

        if command_exists dig; then
            if timeout 6 dig \
                @127.0.0.1 \
                -p 5053 \
                +tries=1 \
                +timeout=4 \
                example.com \
                +short \
                2>/dev/null | grep -q .; then
                return 0
            fi
        elif command_exists nslookup; then
            if timeout 6 nslookup \
                example.com \
                127.0.0.1 \
                2>/dev/null |
                grep -q "Name:"; then
                return 0
            fi
        fi

        if [ "$attempt" -lt "$max_attempts" ]; then
            sleep 1
        fi
    done

    return 1
}

start_unbound() {
    log_json INFO "start_unbound" "Starting Unbound"

    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    if ! wait_for_dns_ready 30; then
        log_json WARN "start_unbound" \
            "classic DNS not ready - delaying unbound"
        return 0
    fi

    configure_unbound || return 0

    pkill -9 -f "^unbound -d" 2>/dev/null || true
    sleep 1

    unbound -d -c "$UNBOUND_CONF" &
    SERVICE_PIDS[unbound]=$!

    local max_wait=10

    if [ "${ENABLE_DNSSEC:-false}" = "true" ]; then
        max_wait=30

        log_json INFO "start_unbound" \
            "DNSSEC enabled - extended startup timeout" \
            "timeout=${max_wait}s"
    fi

    local bound=0
    local i

    for i in $(seq 1 "$max_wait"); do
        if ! kill -0 "${SERVICE_PIDS[unbound]}" 2>/dev/null; then
            log_json WARN "start_unbound" \
                "unbound exited during startup" \
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
        reconfigure_dnsmasq_to_unbound

        METRIC_DOT_ACTIVE=1

        log_json INFO "start_unbound" \
            "started - DoT active" \
            "pid=${SERVICE_PIDS[unbound]}" \
            "port=5053"
    else
        log_json WARN "start_unbound" \
            "unbound not ready after startup window" \
            "timeout=${max_wait}s" \
            "pid=${SERVICE_PIDS[unbound]:-unknown}"

        METRIC_DOT_ACTIVE=0
    fi
}

restart_unbound_if_needed() {
    if [ "${ENABLE_DOT:-false}" != "true" ]; then
        return 0
    fi

    if ! kill -0 "${SERVICE_PIDS[unbound]}" 2>/dev/null; then
        log_json WARN "supervisor" \
            "unbound process died - restarting immediately"

        pkill -9 -f "^unbound" 2>/dev/null || true
        sleep 1

        configure_unbound || return 1

        unbound -d -c "$UNBOUND_CONF" &
        SERVICE_PIDS[unbound]=$!

        reconfigure_dnsmasq_to_unbound

        log_json INFO "supervisor" \
            "unbound restarted" \
            "pid=${SERVICE_PIDS[unbound]}"

        return 1
    fi

    if ! nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
        log_json WARN "supervisor" \
            "unbound port unresponsive - hard restart"

        pkill -9 -f "^unbound" 2>/dev/null || true
        sleep 2

        configure_unbound || return 1

        unbound -d -c "$UNBOUND_CONF" &
        SERVICE_PIDS[unbound]=$!

        reconfigure_dnsmasq_to_unbound

        return 1
    fi

    return 0
}

# ===========================================================================
# Refresh périodique des IP DoT
# ===========================================================================

_dot_refresh_loop() {
    local interval="${DOT_IP_REFRESH_INTERVAL:-3600}"

    log_json INFO "dot_refresh" \
        "Starting periodic IP refresh" \
        "interval=${interval}s"

    while true; do
        sleep "$interval"

        local dot_changed=0
        local servers="${DOT_DNS_SERVERS}"

        servers=$(echo "$servers" | tr ',' ' ')

        local entry
        for entry in $servers; do
            local host new_ip old_ip

            host=$(echo "$entry" |
                sed 's|^[a-z]*://||' |
                awk -F'[:/]' '{print $1}')

            [ -z "$host" ] && continue

            new_ip=$(resolve_hostname \
                "$host" \
                "$DNS_SERVER_1" \
                "$DNS_SERVER_2")

            old_ip=$(dot_ip_map_get "$host")

            if [ -z "$new_ip" ]; then
                log_json WARN "dot_refresh" \
                    "re-resolve failed" \
                    "host=${host}"
                continue
            fi

            if [ "$new_ip" = "$old_ip" ]; then
                log_json INFO "dot_refresh" \
                    "IP unchanged" \
                    "host=${host}" \
                    "ip=${new_ip}"
                continue
            fi

            log_json INFO "dot_refresh" \
                "IP changed - preparing refresh" \
                "host=${host}" \
                "old=${old_ip:-none}" \
                "new=${new_ip}"

            # FIX STABILITÉ :
            # Autoriser la nouvelle IP AVANT de recharger Unbound.
            # L'ancienne IP reste autorisée jusqu'à validation complète.
            ipt_add_853 "$new_ip"

            if configure_unbound; then
                local ub_pid

                ub_pid=$(pidof unbound | awk '{print $1}' || true)

                if [ -n "$ub_pid" ]; then
                    log_json INFO "dot_refresh" \
                        "Reloading unbound after config change" \
                        "pid=${ub_pid}" \
                        "host=${host}"

                    kill -HUP "$ub_pid" 2>/dev/null || true

                    local reload_ok=0
                    local reload_max_wait=15
                    local reload_attempt

                    for reload_attempt in $(seq 1 "$reload_max_wait"); do
                        sleep 1

                        if ! kill -0 "$ub_pid" 2>/dev/null; then
                            log_json WARN "dot_refresh" \
                                "unbound died during reload" \
                                "host=${host}"
                            break
                        fi

                        if test_unbound_dns_robust; then
                            reload_ok=1
                            break
                        fi
                    done

                    if [ "$reload_ok" -eq 1 ]; then
                        # Le nouveau serveur fonctionne.
                        # On peut maintenant retirer l'ancienne IP.
                        if [ -n "$old_ip" ] &&
                            [ "$old_ip" != "$new_ip" ]; then
                            ipt_del_853 "$old_ip"
                        fi

                        dot_ip_map_set "$host" "$new_ip"
                        dot_changed=1

                        log_json INFO "dot_refresh" \
                            "unbound reloaded successfully" \
                            "pid=${ub_pid}" \
                            "host=${host}" \
                            "new_ip=${new_ip}" \
                            "iptables_updated=true"
                    else
                        # Le reload n'est pas validé :
                        # retirer uniquement la nouvelle règle.
                        log_json WARN "dot_refresh" \
                            "unbound reload validation timeout" \
                            "host=${host}" \
                            "new_ip=${new_ip}"

                        ipt_del_853 "$new_ip"
                    fi
                else
                    log_json WARN "dot_refresh" \
                        "unbound not running while refreshing config"

                    ipt_del_853 "$new_ip"
                fi
            else
                log_json WARN "dot_refresh" \
                    "failed to regenerate unbound config after DoT IP change"

                ipt_del_853 "$new_ip"
            fi
        done

        if [ "$dot_changed" -eq 1 ]; then
            log_json INFO "dot_refresh" \
                "DoT IP refresh complete" \
                "changed=1"
        fi
    done
}

start_dot_ip_refresh() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    local interval="${DOT_IP_REFRESH_INTERVAL:-3600}"

    log_json INFO "dot_refresh" \
        "starting periodic IP refresh" \
        "interval=${interval}s"

    _dot_refresh_loop &

    SERVICE_PIDS[dot_refresh]=$!

    log_json INFO "dot_refresh" \
        "refresh loop started" \
        "pid=${SERVICE_PIDS[dot_refresh]}"
}

# ===========================================================================
# Métriques Prometheus
# ===========================================================================

update_metrics() {
    printf '%s\n' "${METRIC_VPN_UP}" \
        > "${METRICS_DIR}/metric_vpn_up" 2>/dev/null || true

    printf '%s\n' "${METRIC_RESTART_COUNT}" \
        > "${METRICS_DIR}/metric_restart_count" 2>/dev/null || true

    printf '%s\n' "${METRIC_DOT_ACTIVE}" \
        > "${METRICS_DIR}/metric_dot_active" 2>/dev/null || true

    printf '%s\n' "${METRIC_START_TS}" \
        > "${METRICS_DIR}/metric_start_ts" 2>/dev/null || true

    printf '%s\n' "${METRIC_LAST_RESTART_TS}" \
        > "${METRICS_DIR}/metric_last_restart_ts" 2>/dev/null || true
}

start_metrics() {
    [ "${ENABLE_METRICS:-false}" = "true" ] || return 0

    if ! command_exists nc; then
        log_json WARN "start_metrics" \
            "nc not available - metrics disabled"
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
        socat \
            TCP-LISTEN:9100,bind=127.0.0.1,reuseaddr,fork \
            EXEC:/tmp/metrics_handler.sh &

        SERVICE_PIDS[metrics]=$!
    else
        (
            while true; do
                nc -l 127.0.0.1 9100 \
                    < <(/tmp/metrics_handler.sh) \
                    2>/dev/null || sleep 1
            done
        ) &

        SERVICE_PIDS[metrics]=$!

        log_json WARN "start_metrics" \
            "socat not found, using nc fallback (one request at a time)"
    fi

    log_json INFO "start_metrics" \
        "metrics endpoint started" \
        "pid=${SERVICE_PIDS[metrics]}" \
        "addr=127.0.0.1:9100"
}

# ===========================================================================
# Capabilities
# ===========================================================================

drop_capabilities() {
    [ "${DROP_CAPS:-false}" = "true" ] || return 0

    if ! command_exists python3; then
        log_json WARN "drop_caps" \
            "python3 not found - capability drop skipped"
        return 0
    fi

    log_json INFO "drop_caps" \
        "dropping capabilities via prctl" \
        "retaining=cap_net_admin(12),cap_net_raw(13)"

    python3 - <<'PYCAPS'
import ctypes
import sys

libc = ctypes.CDLL(None, use_errno=True)

PR_CAPBSET_DROP = 24
CAP_NET_RAW = 13
CAP_NET_ADMIN = 12

KEEP = {CAP_NET_ADMIN, CAP_NET_RAW}
errors = []

for cap in range(40):
    if cap in KEEP:
        continue

    ret = libc.prctl(
        PR_CAPBSET_DROP,
        ctypes.c_ulong(cap),
        0,
        0,
        0
    )

    if ret != 0:
        err = ctypes.get_errno()

        if err != 22:
            errors.append(f"cap {cap}: errno {err}")

if errors:
    print(
        f"[drop_caps] some caps could not be dropped: {errors}",
        file=sys.stderr
    )
    sys.exit(1)

print(
    "[drop_caps] bounding set reduced - "
    "kept CAP_NET_ADMIN(12) CAP_NET_RAW(13)"
)
PYCAPS

    local rc=$?

    if [ "$rc" -eq 0 ]; then
        log_json INFO "drop_caps" \
            "capabilities dropped successfully" \
            "retained=cap_net_admin,cap_net_raw"
    else
        log_json WARN "drop_caps" \
            "capability drop had errors - check stderr above"
    fi
}

# ===========================================================================
# DNS
# ===========================================================================

configure_dnsmasq() {
    log_json INFO "configure_dnsmasq" \
        "Configuring dnsmasq"

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

        log_json INFO "configure_dnsmasq" \
            "DoT mode - upstream: 127.0.0.1#5053"
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

        if [ -n "${DNS_SPLIT:-}" ]; then
            local entries
            entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')

            local entry
            for entry in $entries; do
                local domain resolver res_ip res_port

                domain="${entry%%=*}"
                resolver="${entry#*=}"
                res_ip="${resolver%%:*}"
                res_port="${resolver##*:}"

                [ "$res_port" = "$res_ip" ] && res_port="53"
                [ -z "$domain" ] || [ -z "$res_ip" ] && continue

                echo "server=/${domain}/${res_ip}#${res_port}" \
                    >> "$DNSMASQ_CONF"

                log_json INFO "configure_dnsmasq" \
                    "split DNS" \
                    "domain=${domain}" \
                    "resolver=${res_ip}:${res_port}"
            done
        fi

        log_json INFO "configure_dnsmasq" \
            "upstream: ${DNS_SERVER_1}, ${DNS_SERVER_2}"
    fi
}

start_dnsmasq() {
    log_json INFO "start_dnsmasq" \
        "Starting dnsmasq"

    configure_dnsmasq

    echo "nameserver 127.0.0.1" > "$RESOLV_CONF" || {
        echo "nameserver 127.0.0.1" > /tmp/resolv.conf
        mount --bind /tmp/resolv.conf "$RESOLV_CONF" || true
    }

    if ! dnsmasq \
        --test \
        --conf-file="$DNSMASQ_CONF" \
        >/tmp/dnsmasq.test 2>&1; then

        log_json ERROR "start_dnsmasq" \
            "config test failed"

        sed -n '1,200p' /tmp/dnsmasq.test >&2 || true

        return 0
    fi

    dnsmasq \
        --no-daemon \
        --conf-file="$DNSMASQ_CONF" \
        --log-facility=- &

    SERVICE_PIDS[dnsmasq]=$!

    local bound=0
    local i

    # FIX STABILITÉ #2 : Improved dnsmasq startup check
    # Test both port availability AND actual DNS resolution
    for i in $(seq 1 10); do
        if nc -z -w 1 127.0.0.1 53 >/dev/null 2>&1; then
            # Port is open, now test actual resolution
            if nslookup example.com 127.0.0.1 >/dev/null 2>&1 || \
               dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
                bound=1
                break
            fi
        fi

        sleep 1
    done

    if [ "$bound" -eq 1 ]; then
        log_json INFO "start_dnsmasq" \
            "started" \
            "pid=${SERVICE_PIDS[dnsmasq]}" \
            "port=53"
    else
        log_json ERROR "start_dnsmasq" \
            "dnsmasq did not become fully operational"
    fi
}

start_dnsmasq_classic() {
    log_json INFO "start_dnsmasq_classic" \
        "Starting dnsmasq (classic upstreams)"

    local old_enable_dot="${ENABLE_DOT:-false}"

    export ENABLE_DOT="false"

    # FIX STABILITÉ #4 : Validate upstream DNS servers before starting
    local retry=0
    local max_retries=3
    
    for retry in $(seq 1 "$max_retries"); do
        # Quick check if DNS servers are reachable
        local dns_ok=0
        
        if command_exists timeout; then
            if timeout 3 bash -c "echo > /dev/tcp/${DNS_SERVER_1}/53" 2>/dev/null || \
               timeout 3 bash -c ": > /dev/udp/${DNS_SERVER_1}/53" 2>/dev/null; then
                dns_ok=1
            fi
        fi
        
        if [ "$dns_ok" -eq 0 ] && [ "$retry" -lt "$max_retries" ]; then
            log_json WARN "start_dnsmasq_classic" \
                "upstream DNS not responding, retry in 2s" \
                "dns_server=${DNS_SERVER_1}" \
                "retry=${retry}/${max_retries}"
            sleep 2
            continue
        fi
        
        break
    done

    start_dnsmasq

    export ENABLE_DOT="$old_enable_dot"
}

wait_for_dns_ready() {
    local max_wait="${1:-30}"

    log_json INFO "wait_for_dns_ready" \
        "waiting for local DNS" \
        "timeout=${max_wait}s"

    local i

    for i in $(seq 1 "$max_wait"); do
        # Test actual DNS resolution, not just port connectivity
        if nslookup example.com 127.0.0.1 >/dev/null 2>&1 || \
           dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
            
            log_json INFO "wait_for_dns_ready" \
                "local DNS is responsive" \
                "after=${i}s"

            return 0
        fi

        sleep 1
    done

    log_json WARN "wait_for_dns_ready" \
        "local DNS did not become ready" \
        "timeout=${max_wait}s"

    return 1
}

reconfigure_dnsmasq_to_unbound() {
    log_json INFO "reconfigure_dnsmasq" \
        "Reconfiguring dnsmasq to use unbound"

    kill_if_running "${SERVICE_PIDS[dnsmasq]}"

    SERVICE_PIDS[dnsmasq]=0

    start_dnsmasq
}

# ===========================================================================
# Proxy
# ===========================================================================

configure_privoxy_auth() {
    log_json INFO "configure_privoxy_auth" \
        "Configuring Privoxy authentication"

    local user="${PROXY_USER:-}"
    local pass="${PROXY_PASS:-}"

    if [ -n "$user" ] && [ -n "$pass" ]; then
        sed -i \
            's|^listen-address .*|listen-address 127.0.0.1:3129|' \
            "$PRIVOXY_CONF"

        log_json INFO "configure_privoxy_auth" \
            "auth enabled - privoxy on 127.0.0.1:3129"
    else
        sed -i \
            's|^listen-address .*|listen-address 0.0.0.0:3128|' \
            "$PRIVOXY_CONF"

        log_json INFO "configure_privoxy_auth" \
            "no auth - privoxy on 0.0.0.0:3128"
    fi
}

start_privoxy() {
    log_json INFO "start_privoxy" \
        "Starting Privoxy"

    configure_privoxy_auth

    /usr/sbin/privoxy \
        --no-daemon \
        "$PRIVOXY_CONF" &

    SERVICE_PIDS[privoxy]=$!
}

start_nginx_auth() {
    log_json INFO "start_nginx_auth" \
        "Starting nginx auth proxy"

    local user="${PROXY_USER:-}"
    local pass="${PROXY_PASS:-}"

    [ -n "$user" ] && [ -n "$pass" ] || return 0

    if ! command_exists nginx; then
        log_json WARN "start_nginx_auth" \
            "nginx not found - falling back to no-auth"

        sed -i \
            's|^listen-address .*|listen-address 0.0.0.0:3128|' \
            "$PRIVOXY_CONF"

        return 0
    fi

    local htpasswd_file="/etc/nginx/.proxy_htpasswd"

    mkdir -p /etc/nginx

    htpasswd -cbB "$htpasswd_file" "$user" "$pass"
    chmod 600 "$htpasswd_file"

    local i

    for i in 1 2 3 4 5; do
        if nc -z -w 1 127.0.0.1 3129 >/dev/null 2>&1; then
            break
        fi

        sleep 1
    done

    mkdir -p /run/nginx /var/log/nginx

    cat > /etc/nginx/nginx_proxy_auth.conf <<'NGINXCONF'
worker_processes 1;
error_log /dev/null crit;
pid /run/nginx/nginx_proxy_auth.pid;

events {
    worker_connections 64;
}

http {
    access_log off;

    proxy_connect_timeout 60s;
    proxy_read_timeout 300s;
    proxy_send_timeout 60s;

    server {
        listen 0.0.0.0:3128;

        auth_basic "Proxy Authentication Required";
        auth_basic_user_file /etc/nginx/.proxy_htpasswd;

        location / {
            proxy_pass http://127.0.0.1:3129;
            proxy_http_version 1.1;

            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header Connection "";
            proxy_set_header Authorization "";
        }
    }
}
NGINXCONF

    nginx \
        -c /etc/nginx/nginx_proxy_auth.conf \
        -g 'daemon off;' &

    SERVICE_PIDS[nginx]=$!

    log_json INFO "start_nginx_auth" \
        "started" \
        "pid=${SERVICE_PIDS[nginx]}" \
        "frontend=0.0.0.0:3128" \
        "backend=127.0.0.1:3129"
}

# ===========================================================================
# OpenVPN
# ===========================================================================

start_openvpn() {
    log_json INFO "start_openvpn" \
        "Starting OpenVPN"

    /usr/local/bin/openvpn.sh &

    SERVICE_PIDS[vpn]=$!
}

check_openvpn_routing() {
    command_exists ip || return 0
    vpn_tunnel_ready
}

restart_openvpn() {
    log_json WARN "supervisor" \
        "restarting openvpn" \
        "pid=${SERVICE_PIDS[vpn]:-unknown}"

    kill_if_running "${SERVICE_PIDS[vpn]}"

    if [ -n "${SERVICE_PIDS[vpn]}" ]; then
        wait "${SERVICE_PIDS[vpn]}" 2>/dev/null || true
    fi

    SERVICE_PIDS[vpn]=0

    cleanup_routes_on_restart
    start_openvpn

    local i

    for i in 1 2 3 4 5; do
        sleep 1

        if check_openvpn_routing; then
            log_json INFO "supervisor" \
                "openvpn routing restored" \
                "pid=${SERVICE_PIDS[vpn]}"

            return 0
        fi
    done

    log_json ERROR "supervisor" \
        "openvpn routing still not functional after restart"

    return 1
}

# ===========================================================================
# Healthcheck
# ===========================================================================

run_service_healthcheck() {
    local log_file="/tmp/healthcheck.log"
    local max_retries=3
    local retry=0
    local success=0

    while [ "$retry" -lt "$max_retries" ]; do
        if /usr/local/bin/healthcheck.sh \
            >"$log_file" 2>&1; then

            success=1
            break
        fi

        retry=$((retry + 1))

        log_json WARN "supervisor" \
            "healthcheck failed (attempt ${retry}/${max_retries}) - retrying in 5s"

        sleep 5
    done

    if [ "$success" -eq 0 ]; then
        cat "$log_file" >&2 || true

        log_json WARN "supervisor" \
            "healthcheck failed after ${max_retries} retries - restarting services"

        rm -f "$VPN_HEALTHY_FILE"

        METRIC_VPN_UP=0

        return 1
    fi

    return 0
}

# ===========================================================================
# Vérification IP VPN
# ===========================================================================

check_vpn_ip() {
    log_json INFO "check_vpn_ip" \
        "Checking VPN public IP"

    if ! command_exists curl; then
        log_json WARN "check_vpn_ip" \
            "curl not available, skipping public IP check"
        return 0
    fi

    local proxy_port
    proxy_port=$(get_privoxy_port)

    if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
        log_json WARN "check_vpn_ip" \
            "Privoxy not ready on port ${proxy_port}, skipping public IP check"
        return 0
    fi

    local public_ip
    local proxy_url="http://127.0.0.1:${proxy_port}"

    if [ -n "${PROXY_USER:-}" ] &&
        [ -n "${PROXY_PASS:-}" ]; then

        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${proxy_port}"
    fi

    public_ip=$(
        curl \
            -fsS \
            --max-time 20 \
            --retry 3 \
            --retry-delay 2 \
            --proxy "$proxy_url" \
            "https://api.ipify.org" \
            2>/dev/null || true
    )

    if [ -n "$public_ip" ]; then
        log_json INFO "check_vpn_ip" \
            "public IP via VPN confirmed" \
            "ip=${public_ip}"

        METRIC_VPN_UP=1
    else
        if ping -c 1 -W 5 "$HEALTHCHECK_IP" >/dev/null 2>&1; then
            log_json INFO "check_vpn_ip" \
                "VPN connectivity confirmed (ping to ${HEALTHCHECK_IP})"

            METRIC_VPN_UP=1
        else
            log_json WARN "check_vpn_ip" \
                "could not determine public IP (tunnel may still be initializing)"
        fi
    fi
}

# ===========================================================================
# Tailscale
# ===========================================================================

tailscale_has_state() {
    [ -s /var/lib/tailscale/tailscaled.state ]
}

tailscale_can_advertise_exit_node() {
    local ipv4_forward
    local ipv6_forward

    ipv4_forward=$(
        cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0
    )

    ipv6_forward=$(
        cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0
    )

    [ "$ipv4_forward" = "1" ] &&
        [ "$ipv6_forward" = "1" ]
}

build_tailscale_up_flags() {
    local up_flags="${TAILSCALE_FLAGS:-}"

    if [ "${TAILSCALE_ACCEPT_ROUTES:-false}" = "true" ]; then
        up_flags="$up_flags --accept-routes"
    fi

    if [ -n "${TAILSCALE_HOSTNAME:-}" ]; then
        up_flags="$up_flags --hostname=${TAILSCALE_HOSTNAME}"
    fi

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

    log_json INFO "start_tailscale" \
        "running 'tailscale up'"

    (
        # shellcheck disable=SC2086
        tailscale up \
            --accept-dns=false \
            $up_flags \
            > /var/log/tailscale-up.log 2>&1
    ) &
}

start_tailscale() {
    log_json INFO "start_tailscale" \
        "Starting Tailscale"

    [ "${ENABLE_TAILSCALE:-false}" = "true" ] || return 0

    if ! command_exists tailscaled; then
        log_json WARN "start_tailscale" \
            "tailscaled not installed - skipping"
        return 0
    fi

    mkdir -p \
        /var/lib/tailscale \
        "$TAILSCALE_RUN_DIR" || true

    log_json INFO "start_tailscale" \
        "starting tailscaled"

    tailscaled \
        --state="/var/lib/tailscale/tailscaled.state" \
        --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" \
        >/var/log/tailscaled.log 2>&1 &

    export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
    SERVICE_PIDS[tailscaled]=$!

    local waited=0

    until tailscale status >/dev/null 2>&1 ||
        [ "$waited" -ge 20 ]; do

        sleep 1
        waited=$((waited + 1))
    done

    if ! tailscale status >/dev/null 2>&1; then
        log_json WARN "start_tailscale" \
            "tailscale daemon socket not ready after wait window"
    fi

    local up_flags
    up_flags=$(build_tailscale_up_flags)

    if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
        up_flags="--authkey=${TAILSCALE_AUTHKEY} ${up_flags}"

        run_tailscale_up_async "$up_flags"

        return 0
    fi

    if tailscale_has_state; then
        log_json INFO "start_tailscale" \
            "existing tailscale state detected - refreshing settings without authkey"

        run_tailscale_up_async "$up_flags"

        return 0
    fi

    log_json WARN "start_tailscale" \
        "no authkey and no persisted state - skipping 'tailscale up'"
}

# ===========================================================================
# Superviseur principal
# ===========================================================================

supervise_all() {
    log_json INFO "supervisor" \
        "Starting supervisor" \
        "version=2.1.0"

    local attempt=0

    validate_environment

    cp "$RESOLV_CONF" \
        /tmp/resolv.conf.bak \
        2>/dev/null || true

    echo "nameserver ${DNS_SERVER_1}" > "$RESOLV_CONF"
    echo "nameserver ${DNS_SERVER_2}" >> "$RESOLV_CONF"

    while true; do
        attempt=$((attempt + 1))

        METRIC_RESTART_COUNT=$((attempt - 1))
        METRIC_LAST_RESTART_TS=$(date +%s)

        # -------------------------------------------------------------------
        # Phase 1 : DNS classique
        # -------------------------------------------------------------------

        start_dnsmasq_classic

        if ! wait_for_dns_ready 30; then
            log_json WARN "supervisor" \
                "classic dns not ready - continuing"
        else
            # FIX STABILITÉ #5 : Give classic DNS extra time to stabilize
            # before attempting to resolve DoT hostnames
            sleep 2
        fi

        # -------------------------------------------------------------------
        # Phase 2 : Unbound / DoT
        # -------------------------------------------------------------------

        start_unbound

        # start_unbound peut déjà avoir reconfiguré dnsmasq.
        # On ne fait donc PAS de seconde reconfiguration ici.
        #
        # C'est important : éviter deux redémarrages successifs de dnsmasq
        # pendant le démarrage initial.

        # FIX STABILITÉ #6 : Give Unbound/DoT extra time to stabilize
        if [ "${ENABLE_DOT:-false}" = "true" ] && [ -s "$DOT_FORWARD_ADDRS_FILE" ]; then
            log_json INFO "supervisor" \
                "DoT configured - waiting for stabilization..."
            sleep 3
        fi

        # -------------------------------------------------------------------
        # Vérification DNS
        # -------------------------------------------------------------------

        if [ "${ENABLE_DOT:-false}" = "true" ]; then
            log_json INFO "supervisor" \
                "waiting for DNS services to be ready..."

            local dns_ready=0
            local i

            # FIX STABILITÉ #7 : Extended timeout for DoT startup
            # and more flexible validation criteria
            for i in $(seq 1 90); do
                if nc -z -w 2 127.0.0.1 5053 >/dev/null 2>&1; then
                    # Unbound port is open, test if it's actually responsive
                    if test_unbound_dns_robust; then
                        dns_ready=1
                        log_json INFO "supervisor" \
                            "DoT DNS ready" \
                            "wait_cycles=${i}"
                        break
                    fi
                elif [ $((i % 10)) -eq 0 ]; then
                    # Log progress every 10 cycles to avoid log spam
                    log_json DEBUG "supervisor" \
                        "DoT DNS still initializing" \
                        "cycles=${i}"
                fi

                sleep 2
            done

            if [ "$dns_ready" -ne 1 ]; then
                log_json ERROR "supervisor" \
                    "DNS services (unbound/dnsmasq) not ready - retrying"

                kill_if_running "${SERVICE_PIDS[dnsmasq]}"
                kill_if_running "${SERVICE_PIDS[unbound]}"

                SERVICE_PIDS[dnsmasq]=0
                SERVICE_PIDS[unbound]=0

                sleep 5

                continue
            fi
        else
            local dns_ready=0
            local i

            # FIX STABILITÉ #8 : Better validation for classic DNS mode
            for i in $(seq 1 15); do
                if nslookup example.com 127.0.0.1 >/dev/null 2>&1 || \
                   dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
                    dns_ready=1
                    break
                fi

                sleep 1
            done

            if [ "$dns_ready" -ne 1 ]; then
                log_json ERROR "supervisor" \
                    "dnsmasq not ready after 15s - retrying"

                kill_if_running "${SERVICE_PIDS[dnsmasq]}"
                SERVICE_PIDS[dnsmasq]=0

                sleep 5

                continue
            fi
        fi

        # -------------------------------------------------------------------
        # Firewall
        # -------------------------------------------------------------------

        setup_iptables
        setup_ip6tables

        # -------------------------------------------------------------------
        # Proxy
        # -------------------------------------------------------------------

        start_privoxy
        start_nginx_auth

        # -------------------------------------------------------------------
        # VPN
        # -------------------------------------------------------------------

        start_openvpn

        # -------------------------------------------------------------------
        # Services auxiliaires
        # -------------------------------------------------------------------

        if [ "$attempt" -eq 1 ]; then
            start_metrics
            start_dot_ip_refresh
        fi

        # -------------------------------------------------------------------
        # Attente tunnel
        # -------------------------------------------------------------------

        log_json INFO "supervisor" \
            "waiting for OpenVPN tunnel..."

        local tun_ready=0

        if wait_for_vpn_tunnel 30; then
            tun_ready=1
        fi

        if [ "$tun_ready" -eq 1 ]; then
            setup_return_routes
            check_vpn_ip

            log_json INFO "supervisor" \
                "waiting for tunnel to be fully operational..."

            local full_ready=0

            for i in 1 2 3; do
                if check_vpn_ip &&
                    nslookup example.com 127.0.0.1 >/dev/null 2>&1; then

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
                log_json WARN "supervisor" \
                    "tunnel not fully operational after 15s - skipping Tailscale"

                rm -f "$VPN_HEALTHY_FILE"

                METRIC_VPN_UP=0
            fi
        else
            log_json WARN "supervisor" \
                "tunnel not ready after 30s - skipping return routes"

            rm -f "$VPN_HEALTHY_FILE"

            METRIC_VPN_UP=0
        fi

        # -------------------------------------------------------------------
        # Drop capabilities après le premier démarrage
        # -------------------------------------------------------------------

        if [ "$attempt" -eq 1 ]; then
            drop_capabilities
        fi

        update_metrics

        log_json INFO "supervisor" \
            "all services running" \
            "vpn=${SERVICE_PIDS[vpn]}" \
            "dnsmasq=${SERVICE_PIDS[dnsmasq]:-unknown}" \
            "privoxy=${SERVICE_PIDS[privoxy]:-unknown}" \
            "nginx_auth=${SERVICE_PIDS[nginx]:-disabled}" \
            "unbound=${SERVICE_PIDS[unbound]:-disabled}" \
            "metrics=${SERVICE_PIDS[metrics]:-disabled}" \
            "dot_refresh=${SERVICE_PIDS[dot_refresh]:-disabled}"

        # -------------------------------------------------------------------
        # Stabilisation initiale
        # -------------------------------------------------------------------

        log_json INFO "supervisor" \
            "waiting 40s before first healthcheck for stability..."

        sleep 40

        local fail=0
        local start_time
        start_time=$(date +%s)

        local stable_cycles=0

        # -------------------------------------------------------------------
        # Boucle de supervision / keepalive
        # -------------------------------------------------------------------

        log_json INFO "supervisor" \
            "entering keepalive loop - sentinel vpn_healthy will be maintained" \
            "interval=10s"

        local keepalive_cycles=0

        while true; do
            sleep 10

            keepalive_cycles=$((keepalive_cycles + 1))
            fail=0

            local current_time
            local elapsed_minutes

            current_time=$(date +%s)
            elapsed_minutes=$(( (current_time - start_time) / 60 ))

            # ---------------------------------------------------------------
            # FIX STABILITÉ #3 :
            # vérifier périodiquement le tunnel et maintenir le sentinel.
            #
            # Le sentinel est volontairement touché régulièrement afin
            # qu'un healthcheck externe qui vérifie son existence/activité
            # ne considère pas le VPN comme bloqué alors que le tunnel
            # fonctionne toujours.
            # ---------------------------------------------------------------

            if ! check_openvpn_routing; then
                log_json WARN "supervisor" \
                    "VPN tunnel is down"

                rm -f "$VPN_HEALTHY_FILE"
                METRIC_VPN_UP=0

                if restart_openvpn; then
                    setup_return_routes

                    if check_vpn_ip &&
                        nslookup example.com 127.0.0.1 >/dev/null 2>&1; then

                        touch "$VPN_HEALTHY_FILE"
                        METRIC_VPN_UP=1

                        log_json INFO "supervisor" \
                            "VPN tunnel recovered without full service restart"

                        update_metrics

                        continue
                    fi
                fi

                fail=1
            fi

            # ---------------------------------------------------------------
            # Sentinel + DNS keepalive
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ]; then
                local dns_ok=0

                if [ "${ENABLE_DOT:-false}" = "true" ]; then
                    if nc -z -w 2 127.0.0.1 5053 >/dev/null 2>&1 &&
                        test_unbound_dns_robust &&
                        nslookup example.com 127.0.0.1 >/dev/null 2>&1; then

                        dns_ok=1
                    fi
                else
                    # FIX STABILITÉ #9 : More robust DNS check in keepalive loop
                    # Try both classic and dig methods for better compatibility
                    if nslookup example.com 127.0.0.1 >/dev/null 2>&1 || \
                       dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
                        dns_ok=1
                    fi
                fi

                if [ "$dns_ok" -eq 1 ]; then
                    # FIX STABILITÉ #3 :
                    # maintenir le sentinel tant que VPN + DNS fonctionnent.
                    touch "$VPN_HEALTHY_FILE"

                    METRIC_VPN_UP=1

                    if [ $((keepalive_cycles % 6)) -eq 0 ]; then
                        log_json DEBUG "supervisor" \
                            "tunnel health confirmed" \
                            "cycles=${keepalive_cycles}" \
                            "vpn_healthy=true"
                    fi
                else
                    rm -f "$VPN_HEALTHY_FILE"
                    METRIC_VPN_UP=0

                    log_json WARN "supervisor" \
                        "local DNS health check failed"

                    fail=1
                fi
            fi

            # ---------------------------------------------------------------
            # Healthcheck retardé
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ] &&
                [ "$elapsed_minutes" -ge "$SKIP_HEALTHCHECK_FIRST_MINUTES" ]; then

                if ! run_service_healthcheck; then
                    fail=1
                fi
            elif [ "$elapsed_minutes" -lt "$SKIP_HEALTHCHECK_FIRST_MINUTES" ]; then
                log_json INFO "supervisor" \
                    "skipping healthcheck" \
                    "elapsed=${elapsed_minutes}min" \
                    "required=${SKIP_HEALTHCHECK_FIRST_MINUTES}min"
            fi

            # ---------------------------------------------------------------
            # OpenVPN process
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ] &&
                ! is_process_running "${SERVICE_PIDS[vpn]}"; then

                log_json ERROR "supervisor" \
                    "openvpn process died"

                fail=1
            fi

            # ---------------------------------------------------------------
            # Privoxy
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ]; then
                local proxy_port
                proxy_port=$(get_privoxy_port)

                if ! nc -z -w 3 \
                    127.0.0.1 \
                    "$proxy_port" \
                    >/dev/null 2>&1; then

                    log_json ERROR "supervisor" \
                        "privoxy not listening" \
                        "port=${proxy_port}"

                    fail=1
                fi
            fi

            # ---------------------------------------------------------------
            # nginx
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ] &&
                [ "${SERVICE_PIDS[nginx]}" -ne 0 ]; then

                if ! is_process_running "${SERVICE_PIDS[nginx]}"; then
                    log_json ERROR "supervisor" \
                        "nginx auth proxy died"

                    fail=1
                elif ! nc -z -w 3 127.0.0.1 3128 >/dev/null 2>&1; then
                    log_json ERROR "supervisor" \
                        "nginx auth proxy not listening"

                    fail=1
                fi
            fi

            # ---------------------------------------------------------------
            # Unbound
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ] &&
                [ "${ENABLE_DOT:-false}" = "true" ]; then

                if ! is_process_running "${SERVICE_PIDS[unbound]}"; then
                    log_json ERROR "supervisor" \
                        "unbound process died"

                    METRIC_DOT_ACTIVE=0
                    fail=1
                elif ! nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
                    log_json ERROR "supervisor" \
                        "unbound not listening on 5053"

                    METRIC_DOT_ACTIVE=0
                    fail=1
                fi
            fi

            # ---------------------------------------------------------------
            # dnsmasq
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ]; then
                if ! is_process_running "${SERVICE_PIDS[dnsmasq]}"; then
                    log_json ERROR "supervisor" \
                        "dnsmasq process died"

                    fail=1
                elif ! nslookup example.com 127.0.0.1 >/dev/null 2>&1 && \
                     ! dig @127.0.0.1 example.com +short 2>/dev/null | grep -q .; then
                    log_json ERROR "supervisor" \
                        "DNS resolution via 127.0.0.1 failed"

                    fail=1
                fi
            fi

            # ---------------------------------------------------------------
            # Tailscale
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ] &&
                [ "${SERVICE_PIDS[tailscaled]}" -ne 0 ]; then

                if ! is_process_running "${SERVICE_PIDS[tailscaled]}"; then
                    log_json ERROR "supervisor" \
                        "tailscaled process died"

                    fail=1
                fi
            fi

            # ---------------------------------------------------------------
            # Si tout est OK
            # ---------------------------------------------------------------

            if [ "$fail" -eq 0 ]; then
                update_metrics

                stable_cycles=$((stable_cycles + 1))

                if [ "$stable_cycles" -ge 6 ] &&
                    [ "$attempt" -gt 1 ]; then

                    attempt=1
                    stable_cycles=0

                    log_json INFO "supervisor" \
                        "services stable - backoff counter reset"
                fi

                continue
            fi

            # ---------------------------------------------------------------
            # Échec : sortir de la boucle keepalive
            # ---------------------------------------------------------------

            log_json ERROR "supervisor" \
                "failure detected - leaving keepalive loop" \
                "attempt=${attempt}"

            rm -f "$VPN_HEALTHY_FILE"

            METRIC_VPN_UP=0

            update_metrics

            break
        done

        # -------------------------------------------------------------------
        # Redémarrage complet
        # -------------------------------------------------------------------

        log_json ERROR "supervisor" \
            "failure detected - restarting services" \
            "attempt=${attempt}"

        rm -f "$VPN_HEALTHY_FILE"

        METRIC_VPN_UP=0
        METRIC_LAST_RESTART_TS=$(date +%s)

        update_metrics

        # Ne pas utiliser de pkill global ici.
        # On arrête uniquement les processus dont le superviseur connaît
        # le PID afin d'éviter de tuer le superviseur ou un autre service.

        kill_if_running "${SERVICE_PIDS[vpn]}"
        kill_if_running "${SERVICE_PIDS[privoxy]}"
        kill_if_running "${SERVICE_PIDS[nginx]}"
        kill_if_running "${SERVICE_PIDS[dnsmasq]}"
        kill_if_running "${SERVICE_PIDS[tailscaled]}"
        kill_if_running "${SERVICE_PIDS[unbound]}"

        # Attendre proprement les processus.
        local pids_to_wait=""

        local pid
        for pid in \
            "${SERVICE_PIDS[vpn]}" \
            "${SERVICE_PIDS[privoxy]}" \
            "${SERVICE_PIDS[nginx]}" \
            "${SERVICE_PIDS[dnsmasq]}" \
            "${SERVICE_PIDS[tailscaled]}" \
            "${SERVICE_PIDS[unbound]}"; do

            if [ -n "$pid" ] && [ "$pid" -ne 0 ]; then
                pids_to_wait="$pids_to_wait $pid"
            fi
        done

        if [ -n "$pids_to_wait" ]; then
            # shellcheck disable=SC2086
            wait $pids_to_wait 2>/dev/null || true
        fi

        # Nettoyage des routes/TUN avant le prochain cycle.
        cleanup_routes_on_restart

        # Réinitialiser les PIDs.
        SERVICE_PIDS[vpn]=0
        SERVICE_PIDS[privoxy]=0
        SERVICE_PIDS[nginx]=0
        SERVICE_PIDS[dnsmasq]=0
        SERVICE_PIDS[tailscaled]=0
        SERVICE_PIDS[unbound]=0

        DOT_RESOLVED_IPS=""
        unset DOT_HOST_IP_MAP
        declare -gA DOT_HOST_IP_MAP=()

        # -------------------------------------------------------------------
        # Backoff
        # -------------------------------------------------------------------

        local sleep_s
        sleep_s=$((5 + attempt * 10))

        if [ "$sleep_s" -gt 120 ]; then
            sleep_s=120
        fi

        log_json INFO "supervisor" \
            "stabilization wait ${sleep_s}s" \
            "attempt=${attempt}"

        sleep "$sleep_s"

        # Augmenter progressivement la période de grâce du healthcheck
        # après des redémarrages successifs.
        SKIP_HEALTHCHECK_FIRST_MINUTES=$(
            ((${SKIP_HEALTHCHECK_FIRST_MINUTES:-0} + 5))
        )
    done
}

# ===========================================================================
# Gestion des signaux
# ===========================================================================

cleanup() {
    log_json INFO "cleanup" \
        "Cleaning up services"

    rm -f "$VPN_HEALTHY_FILE"

    local service

    for service in "${!SERVICE_PIDS[@]}"; do
        kill_if_running "${SERVICE_PIDS[$service]}"
    done

    local all_pids=""

    local pid
    for pid in "${SERVICE_PIDS[@]}"; do
        if [ -n "$pid" ] && [ "$pid" -ne 0 ]; then
            all_pids="$all_pids $pid"
        fi
    done

    if [ -n "$all_pids" ]; then
        # shellcheck disable=SC2086
        wait $all_pids 2>/dev/null || true
    fi

    log_json INFO "cleanup" \
        "All services stopped"

    exit 0
}

trap cleanup INT TERM

# ===========================================================================
# Point d'entrée principal
# ===========================================================================

log_json INFO "start.sh" \
    "Starting openvpn_client_proxy" \
    "version=2.1.0"

mkdir -p "$METRICS_DIR"

supervise_all
