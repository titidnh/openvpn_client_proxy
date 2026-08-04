#!/bin/bash

set -eu
set -o pipefail

# ===========================================================================
# CONFIGURATION CENTRALISÉE
# ===========================================================================

declare -r CONFIG_FILE="/vpn/vpn.conf"
declare -r TAILSCALE_RUN_DIR="${TAILSCALE_RUN_DIR:-/var/run/tailscale}"
declare -r ROUTE_TEST_IP="${ROUTE_TEST_IP:-9.9.9.9}"

# Ports & services
declare -r PORT_PRIVOXY_MAIN=3128
declare -r PORT_PRIVOXY_INTERNAL=3129
declare -r PORT_UNBOUND=5053
declare -r PORT_DNS=53
declare -r PORT_METRICS=9100
declare -r PORT_NGINX=3128

# Timeouts (secondes)
declare -r TIMEOUT_SERVICE_BIND=5
declare -r TIMEOUT_TUNNEL_READY=30
declare -r TIMEOUT_CURL=10
declare -r BACKOFF_MAX_SECS=60
declare -r SLEEP_HEALTHCHECK_INTERVAL=10

# Paths
declare -r METRICS_HANDLER="/tmp/metrics_handler.sh"
declare -r DOT_IP_MAP_FILE="/tmp/dot_ip_map"
declare -r DOT_FORWARD_ADDRS_FILE="/tmp/dot_forward_addrs"
declare -r DNSMASQ_CONF="/etc/dnsmasq.conf"
declare -r UNBOUND_CONF="/etc/unbound/unbound.conf"
declare -r RESOLV_CONF="/etc/resolv.conf"
declare -r HEALTHCHECK_LOG="/tmp/healthcheck.log"
declare -r HTPASSWD_FILE="/etc/nginx/.proxy_htpasswd"

# ===========================================================================
# ÉTAT GLOBAL (PID & MÉTRIQUES)
# ===========================================================================

declare -g vpn_pid=""
declare -g privoxy_pid=""
declare -g nginx_pid=""
declare -g dnsmasq_pid=""
declare -g tailscaled_pid=""
declare -g unbound_pid=""
declare -g metrics_pid=""
declare -g dot_refresh_pid=""

# Métriques Prometheus
declare -g METRIC_RESTART_COUNT=0
declare -g METRIC_VPN_UP=0
declare -g METRIC_DOT_ACTIVE=0
declare -g METRIC_LAST_RESTART_TS=0
declare -g METRIC_START_TS=$(date +%s)

# DoT
declare -g DOT_RESOLVED_IPS=""
declare -gA DOT_HOST_IP_MAP

# ===========================================================================
# LOGGING
# ===========================================================================

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
        v="${v//\\/\\\\}"
        v="${v//\"/\\\"}"
        extra="${extra}, \"${k}\": \"${v}\""
    done

    printf '{"ts":"%s","level":"%s","component":"%s","msg":"%s"%s}\n' \
        "$ts" "$level" "$component" "$message" "$extra" >&2
}

# ===========================================================================
# HELPERS GÉNÉRAUX
# ===========================================================================

is_ipv6() {
    local ip="$1"
    [[ "$ip" =~ : ]] && return 0 || return 1
}

ipt6() {
    ip6tables "$@" 2>/dev/null || true
}

ipt_add_853() {
    local ip="$1"
    if is_ipv6 "$ip"; then
        ipt6 -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
    else
        iptables -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
    fi
}

ipt_del_853() {
    local ip="$1"
    if is_ipv6 "$ip"; then
        ipt6 -D OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
    else
        iptables -D OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
    fi
}

kill_pid() {
    local pid="$1"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
}

wait_for_port() {
    local host="$1" port="$2" timeout="${3:-$TIMEOUT_SERVICE_BIND}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        nc -z -w 1 "$host" "$port" >/dev/null 2>&1 && return 0
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

run_checked() {
    local desc="$1"
    shift
    if ! "$@" >/dev/null 2>&1; then
        log_json ERROR "run_checked" "$desc failed" "cmd=${*}"
        return 1
    fi
    return 0
}

# ===========================================================================
# CONFIGURATION OpenVPN
# ===========================================================================

get_vpn_port_proto() {
    VPN_PORT="1194"
    VPN_PROTO="udp"
    if [ -f "$CONFIG_FILE" ]; then
        VPN_PORT=$(awk '\
            /^remote / {\
                for (i=1; i<=NF; i++)\
                    if ($i ~ /:/) { split($i, a, ":"); print a[2]; exit }\
                if (NF >= 3) { print $3; exit }\
            }' "$CONFIG_FILE" | head -1 || true)
        VPN_PORT=${VPN_PORT:-1194}
        VPN_PROTO=$(awk '/^proto /{print $2; exit}' "$CONFIG_FILE" || true)
        VPN_PROTO=${VPN_PROTO:-udp}
    fi
}

get_dns_upstreams() {
    [ -f "$DNSMASQ_CONF" ] || return 0
    grep -E '^[[:space:]]*server=' "$DNSMASQ_CONF" \
        | sed 's/.*server=\([^#]*\).*/\1/' \
        | awk -F'[#@]' '{print $1}' || true
}

check_vpn_ip() {
    command -v curl >/dev/null 2>&1 || {
        log_json WARN "check_vpn_ip" "curl not available, skipping IP check"
        return 0
    }

    local proxy_port="$PORT_PRIVOXY_MAIN"
    if [ -f /etc/privoxy/privoxy.config ]; then
        local addr
        addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' \
            /etc/privoxy/privoxy.config || true)
        [ -n "$addr" ] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}' || true)
    fi

    local public_ip proxy_url
    proxy_url="http://127.0.0.1:${proxy_port}"
    if [ -n "${PROXY_USER:-}" ] && [ -n "${PROXY_PASS:-}" ]; then
        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${proxy_port}"
    fi

    public_ip=$(curl -fsS --max-time "$TIMEOUT_CURL" --proxy "$proxy_url" \
        https://api.ipify.org 2>/dev/null || true)

    if [ -n "$public_ip" ]; then
        log_json INFO "check_vpn_ip" "public IP confirmed" "ip=${public_ip}"
        METRIC_VPN_UP=1
    else
        log_json WARN "check_vpn_ip" "could not determine public IP"
        METRIC_VPN_UP=0
    fi
}

# ===========================================================================
# FIREWALL
# ===========================================================================

_setup_iptables_base() {
    iptables -F || true
    iptables -X || true
    iptables -t nat -F || true
    iptables -P INPUT DROP || true
    iptables -P FORWARD DROP || true
    iptables -P OUTPUT DROP || true
}

_setup_iptables_input() {
    local docker_network="${1:-}"
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    iptables -A INPUT -i lo -j ACCEPT || true
    [ -n "$docker_network" ] && iptables -A INPUT -s "$docker_network" -j ACCEPT || true
}

_setup_iptables_forward() {
    local docker_network="${1:-}"
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    iptables -A FORWARD -i lo -j ACCEPT || true
    [ -n "$docker_network" ] && {
        iptables -A FORWARD -s "$docker_network" -j ACCEPT || true
        iptables -A FORWARD -d "$docker_network" -j ACCEPT || true
    }
    iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT || true
    iptables -A FORWARD -i tailscale+ -o tap+ -j ACCEPT || true
    iptables -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    iptables -A FORWARD -i tap+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
}

_setup_iptables_output_dns() {
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport "$PORT_DNS" -j ACCEPT || true
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport "$PORT_DNS" -j ACCEPT || true
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport "$PORT_UNBOUND" -j ACCEPT || true
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport "$PORT_UNBOUND" -j ACCEPT || true

    grep -Fq "127.0.0.11" "$RESOLV_CONF" 2>/dev/null && {
        iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT || true
        iptables -A OUTPUT -p udp -d 127.0.0.11 --dport "$PORT_DNS" -j ACCEPT || true
        iptables -A OUTPUT -p tcp -d 127.0.0.11 --dport "$PORT_DNS" -j ACCEPT || true
    }
}

_setup_iptables_output_dot() {
    if [ -n "$DOT_RESOLVED_IPS" ]; then
        for dot_ip in $DOT_RESOLVED_IPS; do
            ipt_add_853 "$dot_ip"
            log_json INFO "setup_iptables" "DoT 853 allowed" "ip=${dot_ip}"
        done
    else
        log_json WARN "setup_iptables" "DoT: no resolved IPs"
    fi
    iptables -A OUTPUT -p udp ! -d 127.0.0.0/8 --dport "$PORT_DNS" -j DROP || true
    iptables -A OUTPUT -p tcp ! -d 127.0.0.0/8 --dport "$PORT_DNS" -j DROP || true
}

_setup_iptables_output_standard_dns() {
    for dns in "${DNS_SERVER_1:-}" "${DNS_SERVER_2:-}"; do
        [[ "$dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        iptables -A OUTPUT -p udp -d "$dns" --dport "$PORT_DNS" -j ACCEPT || true
        iptables -A OUTPUT -p tcp -d "$dns" --dport "$PORT_DNS" -j ACCEPT || true
    done
    while read -r dns; do
        [[ "$dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        iptables -A OUTPUT -p udp -d "$dns" --dport "$PORT_DNS" -j ACCEPT || true
        iptables -A OUTPUT -p tcp -d "$dns" --dport "$PORT_DNS" -j ACCEPT || true
    done < <(get_dns_upstreams || true)
}

setup_iptables() {
    local docker_network
    docker_network=$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet"{print $4}' || true)

    get_vpn_port_proto

    _setup_iptables_base
    _setup_iptables_input "$docker_network"
    _setup_iptables_forward "$docker_network"

    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    iptables -A OUTPUT -o lo -j ACCEPT || true
    iptables -A OUTPUT -o tun+ -j ACCEPT || true
    iptables -A OUTPUT -o tap+ -j ACCEPT || true
    iptables -A OUTPUT -o tailscale+ -j ACCEPT || true
    [ -n "$docker_network" ] && iptables -A OUTPUT -d "$docker_network" -j ACCEPT || true
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport "$PORT_METRICS" -j ACCEPT || true

    _setup_iptables_output_dns
    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        _setup_iptables_output_dot
        log_json INFO "setup_iptables" "DoT DNS leak prevention enabled"
    else
        _setup_iptables_output_standard_dns
    fi

    iptables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT || true
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true

    iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE || true
    iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE || true

    log_json INFO "setup_iptables" "IPv4 firewall configured" \
        "vpn_proto=${VPN_PROTO}" "vpn_port=${VPN_PORT}"
}

setup_ip6tables() {
    command -v ip6tables >/dev/null 2>&1 || {
        log_json WARN "setup_ip6tables" "ip6tables not installed"
        return 0
    }
    [ -f /proc/net/if_inet6 ] || {
        log_json WARN "setup_ip6tables" "IPv6 not available"
        return 0
    }

    local docker6_network
    docker6_network=$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet6"{print $4; exit}' || true)

    ipt6 -F || true
    ipt6 -X || true
    ipt6 -t nat -F || true
    ipt6 -P INPUT DROP || true
    ipt6 -P FORWARD DROP || true
    ipt6 -P OUTPUT DROP || true

    ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    ipt6 -A INPUT -p icmpv6 -j ACCEPT || true
    ipt6 -A INPUT -i lo -j ACCEPT || true
    [ -n "$docker6_network" ] && ipt6 -A INPUT -s "$docker6_network" -j ACCEPT || true

    ipt6 -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    ipt6 -A FORWARD -p icmpv6 -j ACCEPT || true
    ipt6 -A FORWARD -i lo -j ACCEPT || true
    [ -n "$docker6_network" ] && {
        ipt6 -A FORWARD -s "$docker6_network" -j ACCEPT || true
        ipt6 -A FORWARD -d "$docker6_network" -j ACCEPT || true
    }
    ipt6 -A FORWARD -i tailscale+ -o tun+ -j ACCEPT || true
    ipt6 -A FORWARD -i tailscale+ -o tap+ -j ACCEPT || true
    ipt6 -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    ipt6 -A FORWARD -i tap+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true

    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    ipt6 -A OUTPUT -o lo -j ACCEPT || true
    ipt6 -A OUTPUT -o tun+ -j ACCEPT || true
    ipt6 -A OUTPUT -o tap+ -j ACCEPT || true
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT || true
    [ -n "$docker6_network" ] && ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT || true

    ipt6 -A OUTPUT -p tcp -d ::1 --dport "$PORT_METRICS" -j ACCEPT || true
    ipt6 -A OUTPUT -p udp -d ::1 --dport "$PORT_DNS" -j ACCEPT || true
    ipt6 -A OUTPUT -p tcp -d ::1 --dport "$PORT_DNS" -j ACCEPT || true
    ipt6 -A OUTPUT -p udp -d ::1 --dport "$PORT_UNBOUND" -j ACCEPT || true
    ipt6 -A OUTPUT -p tcp -d ::1 --dport "$PORT_UNBOUND" -j ACCEPT || true

    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        ipt6 -A OUTPUT -p udp ! -d ::1 --dport "$PORT_DNS" -j DROP 2>/dev/null || true
        ipt6 -A OUTPUT -p tcp ! -d ::1 --dport "$PORT_DNS" -j DROP 2>/dev/null || true
    else
        while read -r dns; do
            is_ipv6 "$dns" || continue
            ipt6 -A OUTPUT -p udp -d "$dns" --dport "$PORT_DNS" -j ACCEPT || true
            ipt6 -A OUTPUT -p tcp -d "$dns" --dport "$PORT_DNS" -j ACCEPT || true
        done < <(get_dns_upstreams || true)
    fi

    ipt6 -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT || true
    ipt6 -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT || true
    ipt6 -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT || true
    ipt6 -t nat -A POSTROUTING -o tun+ -j MASQUERADE || true
    ipt6 -t nat -A POSTROUTING -o tap+ -j MASQUERADE || true

    log_json INFO "setup_ip6tables" "IPv6 firewall configured"
}

# ===========================================================================
# ROUTES RETOUR
# ===========================================================================

setup_return_routes() {
    local iface gw gw6 ips ip6s

    iface=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}' || true)
    [ -z "$iface" ] && {
        log_json WARN "setup_return_routes" "no default interface"
        return 0
    }

    gw=$(ip -4 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}' || true)
    gw6=$(ip -6 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}' || true)
    ips=$(ip -4 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet /{print $3}' || true)
    ip6s=$(ip -6 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet6.*global/{print $3}' || true)

    for ip in $ips; do
        ip -4 rule show table 10 2>/dev/null | grep -q "$ip" || \
            ip rule add from "$ip" lookup 10 2>/dev/null || true
        iptables -C INPUT -d "$ip" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -d "$ip" -j ACCEPT || true
    done
    [ -n "$gw" ] && {
        ip -4 route show table 10 2>/dev/null | grep -q "default" || \
            ip route add default via "$gw" table 10 2>/dev/null || true
    }

    for ip6 in $ip6s; do
        ip -6 rule show table 10 2>/dev/null | grep -q "$ip6" || \
            ip -6 rule add from "$ip6" lookup 10 2>/dev/null || true
        ipt6 -C INPUT -d "$ip6" -j ACCEPT 2>/dev/null || \
            ipt6 -A INPUT -d "$ip6" -j ACCEPT 2>/dev/null || true
    done
    [ -n "$gw6" ] && {
        ip -6 route show table 10 2>/dev/null | grep -q "default" || \
            ip -6 route add default via "$gw6" table 10 2>/dev/null || true
    }

    log_json INFO "setup_return_routes" "configured" "iface=${iface}"
}

# ===========================================================================
# DNS-over-TLS
# ===========================================================================

dot_ip_map_set() {
    local host="$1" ip="$2"
    DOT_HOST_IP_MAP["$host"]="$ip"
    local tmp
    tmp=$(mktemp /tmp/dot_ip_map.XXXXXX)
    [ -f "$DOT_IP_MAP_FILE" ] && grep -v "^${host}=" "$DOT_IP_MAP_FILE" > "$tmp" 2>/dev/null || true
    echo "${host}=${ip}" >> "$tmp"
    mv -f "$tmp" "$DOT_IP_MAP_FILE"
}

dot_ip_map_get() {
    local host="$1"
    if [ -n "${DOT_HOST_IP_MAP[$host]:-}" ]; then
        echo "${DOT_HOST_IP_MAP[$host]}"
    elif [ -f "$DOT_IP_MAP_FILE" ]; then
        grep "^${host}=" "$DOT_IP_MAP_FILE" 2>/dev/null | cut -d= -f2- | tail -1 || echo ""
    fi
}

resolve_dot_host() {
    local host="$1" ip
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '/STREAM/{print $1; exit}' || true)
    if [ -z "$ip" ]; then
        ip=$(nslookup "$host" 2>/dev/null | awk '/^Address: /{ if ($2 !~ /:/) {print $2; exit} }' || true)
    fi
    if [ -z "$ip" ]; then
        for dns in "${DNS_SERVER_1:-}" "${DNS_SERVER_2:-}"; do
            [ -z "$dns" ] && continue
            ip=$(nslookup "$host" "$dns" 2>/dev/null | \
                awk '/^Address: /{ if ($2 !~ /:/) {print $2; exit} }' || true)
            [ -n "$ip" ] && {
                log_json WARN "resolve_dot_host" "fallback DNS_SERVER" \
                    "host=${host}" "ip=${ip}" "via=${dns}"
                break
            }
        done
    fi
    echo "$ip"
}

parse_dot_servers() {
    local servers="${DOT_DNS_SERVERS:-tls://dns.adguard-dns.com}"
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
        [ -z "$host" ] && continue

        ip=$(resolve_dot_host "$host")

        if [ -n "$ip" ]; then
            DOT_RESOLVED_IPS="${DOT_RESOLVED_IPS}${ip} "
            DOT_HOST_IP_MAP["$host"]="$ip"
            echo "${host}=${ip}" >> "$tmp_map"
            [ "$proto" = "https" ] && \
                echo "        forward-addr: ${ip}@443#${host}" >> "$tmp_forward" || \
                echo "        forward-addr: ${ip}@853#${host}" >> "$tmp_forward"
            log_json INFO "parse_dot_servers" "resolved" \
                "host=${host}" "ip=${ip}" "proto=${proto}"
        else
            log_json WARN "parse_dot_servers" "could not resolve" "host=${host}"
        fi
    done

    [ -s "$tmp_map" ] && mv -f "$tmp_map" "$DOT_IP_MAP_FILE" || rm -f "$tmp_map"
    [ -s "$tmp_forward" ] && mv -f "$tmp_forward" "$DOT_FORWARD_ADDRS_FILE" || rm -f "$tmp_forward"
}

configure_unbound() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0
    command -v unbound >/dev/null 2>&1 || {
        log_json ERROR "configure_unbound" "unbound binary not found"
        return 1
    }

    parse_dot_servers

    [ -s "$DOT_FORWARD_ADDRS_FILE" ] || {
        log_json ERROR "configure_unbound" "no valid DoT servers"
        return 1
    }

    local conf_file dnssec_mode tls_cert_bundle
    conf_file=$(mktemp /tmp/unbound.conf.XXXXXX)
    dnssec_mode="val-permissive-mode: yes"
    tls_cert_bundle="/etc/ssl/certs/ca-certificates.crt"

    if [ "${ENABLE_DNSSEC:-false}" = "true" ]; then
        dnssec_mode="val-permissive-mode: no"
        mkdir -p /var/lib/unbound
        chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true
        unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
        log_json INFO "configure_unbound" "DNSSEC strict mode"
    fi

    [ -n "${DOT_TLS_CERT_BUNDLE:-}" ] && [ -f "${DOT_TLS_CERT_BUNDLE}" ] && \
        tls_cert_bundle="${DOT_TLS_CERT_BUNDLE}"

    local split_zones=""
    if [ -n "${DNS_SPLIT:-}" ]; then
        local split_entries
        split_entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')
        for entry in $split_entries; do
            local domain resolver res_ip res_port
            domain="${entry%%=*}"; resolver="${entry#*=}"
            res_ip="${resolver%%:*}"; res_port="${resolver##*:}"
            [ "$res_port" = "$res_ip" ] && res_port="53"
            [ -z "$domain" ] || [ -z "$res_ip" ] && continue
            split_zones="${split_zones}\
forward-zone:\
    name: \"${domain}\"\
    forward-tls-upstream: no\
    forward-addr: ${res_ip}@${res_port}"
        done
    fi

    mkdir -p /etc/unbound /var/lib/unbound
    chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true

    local forward_addrs
    forward_addrs=$(cat "$DOT_FORWARD_ADDRS_FILE" || true)

    cat > "$conf_file" <<EOF
server:
    interface: 127.0.0.1
    port: $PORT_UNBOUND
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

    [ "${ENABLE_DNSSEC:-false}" = "true" ] && [ -f /var/lib/unbound/root.key ] && \
        echo "    auto-trust-anchor-file: /var/lib/unbound/root.key" >> "$conf_file"

    cat >> "$conf_file" <<EOF

forward-zone:
    name: "."
    forward-tls-upstream: yes
${forward_addrs}
${split_zones}
EOF

    if ! unbound-checkconf "$conf_file" >/tmp/unbound.checkconf 2>&1; then
        log_json ERROR "configure_unbound" "config validation failed"
        cat /tmp/unbound.checkconf >&2 || true
        rm -f "$conf_file"
        return 1
    fi

    mv -f "$conf_file" "$UNBOUND_CONF"
    log_json INFO "configure_unbound" "config written" \
        "dnssec=${ENABLE_DNSSEC:-false}" "tls_bundle=${tls_cert_bundle}"
}

start_unbound() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0
    configure_unbound || return 0

    unbound -d -c "$UNBOUND_CONF" &
    unbound_pid=$!

    if wait_for_port 127.0.0.1 "$PORT_UNBOUND"; then
        METRIC_DOT_ACTIVE=1
        log_json INFO "start_unbound" "started" "pid=${unbound_pid}" "port=$PORT_UNBOUND"
    else
        log_json ERROR "start_unbound" "failed to bind"
        unbound_pid=""
        METRIC_DOT_ACTIVE=0
    fi
}

test_unbound_dns() {
    if command -v dig >/dev/null 2>&1; then
        dig @127.0.0.1 -p "$PORT_UNBOUND" example.com +short | grep -q . && return 0
    fi
    nslookup example.com 127.0.0.1 2>/dev/null | grep -q Address && return 0
    return 1
}

_dot_refresh_loop() {
    local interval="${DOT_IP_REFRESH_INTERVAL:-3600}"
    while true; do
        sleep "$interval"
        local servers="${DOT_DNS_SERVERS:-tls://dns.adguard-dns.com}"
        servers=$(echo "$servers" | tr ',' ' ')

        for entry in $servers; do
            local host new_ip old_ip
            host=$(echo "$entry" | sed 's|^[a-z]*://||' | awk -F'[:/]' '{print $1}')
            [ -z "$host" ] && continue

            new_ip=$(resolve_dot_host "$host")
            old_ip=$(dot_ip_map_get "$host")

            [ -z "$new_ip" ] && {
                log_json WARN "dot_refresh" "re-resolve failed" "host=${host}"
                continue
            }
            [ "$new_ip" = "$old_ip" ] && {
                log_json INFO "dot_refresh" "IP unchanged" "host=${host}" "ip=${new_ip}"
                continue
            }

            log_json INFO "dot_refresh" "IP changed" \
                "host=${host}" "old=${old_ip:-none}" "new=${new_ip}"
            ipt_add_853 "$new_ip"

            if configure_unbound; then
                local ub_pid
                ub_pid=$(pidof unbound | awk '{print $1}' || true)
                if [ -n "$ub_pid" ]; then
                    kill -HUP "$ub_pid" 2>/dev/null || true
                    sleep 1
                    if test_unbound_dns; then
                        [ -n "$old_ip" ] && ipt_del_853 "$old_ip"
                        dot_ip_map_set "$host" "$new_ip"
                        log_json INFO "dot_refresh" "unbound refreshed" \
                            "pid=${ub_pid}" "host=${host}" "new_ip=${new_ip}"
                    else
                        log_json ERROR "dot_refresh" "DNS validation failed"
                        ipt_del_853 "$new_ip"
                    fi
                fi
            else
                ipt_del_853 "$new_ip"
            fi
        done
    done
}

start_dot_ip_refresh() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0
    _dot_refresh_loop &
    dot_refresh_pid=$!
    log_json INFO "dot_refresh" "loop started" "pid=${dot_refresh_pid}" \
        "interval=${DOT_IP_REFRESH_INTERVAL:-3600}s"
}

# ===========================================================================
# MÉTRIQUES PROMETHEUS
# ===========================================================================

start_metrics() {
    [ "${ENABLE_METRICS:-false}" = "true" ] || return 0
    command -v nc >/dev/null 2>&1 || {
        log_json WARN "start_metrics" "nc not available"
        return 0
    }

    cat > "$METRICS_HANDLER" <<'HANDLER'
#!/bin/sh
vpn_up=$(cat /tmp/metric_vpn_up 2>/dev/null || echo 0)
restart_total=$(cat /tmp/metric_restart_count 2>/dev/null || echo 0)
dot_active=$(cat /tmp/metric_dot_active 2>/dev/null || echo 0)
start_ts=$(cat /tmp/metric_start_ts 2>/dev/null || echo 0)
last_restart=$(cat /tmp/metric_last_restart_ts 2>/dev/null || echo 0)
now=$(date +%s)
uptime_s=$((now - start_ts))

body="# HELP vpn_up VPN tunnel status\n# TYPE vpn_up gauge\nvpn_up ${vpn_up}\n# HELP vpn_restart_total Total supervisor restarts\n# TYPE vpn_restart_total counter\nvpn_restart_total ${restart_total}\n# HELP dot_active DNS-over-TLS status\n# TYPE dot_active gauge\ndot_active ${dot_active}\n# HELP process_uptime_seconds Container uptime\n# TYPE process_uptime_seconds gauge\nprocess_uptime_seconds ${uptime_s}\n# HELP last_restart_timestamp_seconds Last restart epoch\n# TYPE last_restart_timestamp_seconds gauge\nlast_restart_timestamp_seconds ${last_restart}\n"
len=${#body}
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$len" "$body"
HANDLER
    chmod +x "$METRICS_HANDLER"

    update_metrics

    if command -v socat >/dev/null 2>&1; then
        socat TCP-LISTEN:$PORT_METRICS,bind=127.0.0.1,reuseaddr,fork EXEC:"$METRICS_HANDLER" &
        metrics_pid=$!
    else
        (while true; do
            nc -l 127.0.0.1 $PORT_METRICS < <("$METRICS_HANDLER") 2>/dev/null || sleep 1
        done) &
        metrics_pid=$!
        log_json WARN "start_metrics" "socat not found, using nc fallback"
    fi
    log_json INFO "start_metrics" "started" "pid=${metrics_pid}" "port=$PORT_METRICS"
}

update_metrics() {
    printf '%s\n' "${METRIC_VPN_UP}" > /tmp/metric_vpn_up 2>/dev/null || true
    printf '%s\n' "${METRIC_RESTART_COUNT}" > /tmp/metric_restart_count 2>/dev/null || true
    printf '%s\n' "${METRIC_DOT_ACTIVE}" > /tmp/metric_dot_active 2>/dev/null || true
    printf '%s\n' "${METRIC_START_TS}" > /tmp/metric_start_ts 2>/dev/null || true
    printf '%s\n' "${METRIC_LAST_RESTART_TS}" > /tmp/metric_last_restart_ts 2>/dev/null || true
}

# ===========================================================================
# RÉDUCTION CAPABILITIES
# ===========================================================================

drop_capabilities() {
    [ "${DROP_CAPS:-false}" = "true" ] || return 0
    command -v python3 >/dev/null 2>&1 || {
        log_json WARN "drop_caps" "python3 not found"
        return 0
    }

    python3 - <<'PYCAPS'
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
PR_CAPBSET_DROP, CAP_NET_ADMIN, CAP_NET_RAW = 24, 12, 13
KEEP = {CAP_NET_ADMIN, CAP_NET_RAW}
errors = []
for cap in range(40):
    if cap not in KEEP:
        if libc.prctl(PR_CAPBSET_DROP, ctypes.c_ulong(cap), 0, 0, 0) != 0:
            if ctypes.get_errno() != 22:
                errors.append(f"cap {cap}")
if errors:
    print(f"failed caps: {errors}", file=sys.stderr)
    sys.exit(1)
PYCAPS

    log_json INFO "drop_caps" "capabilities dropped" "retained=cap_net_admin,cap_net_raw"
}

# ===========================================================================
# DNS SERVICES
# ===========================================================================

configure_dnsmasq() {
    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        cat > "$DNSMASQ_CONF" <<EOF
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=127.0.0.1#$PORT_UNBOUND
cache-size=1000
log-facility=/dev/null
EOF
        log_json INFO "configure_dnsmasq" "DoT mode"
    else
        local dns1="${DNS_SERVER_1:-94.140.14.14}"
        local dns2="${DNS_SERVER_2:-94.140.15.15}"
        cat > "$DNSMASQ_CONF" <<EOF
listen-address=127.0.0.1
bind-interfaces
no-resolv
server=${dns1}
server=${dns2}
cache-size=1000
log-facility=/dev/null
EOF
        if [ -n "${DNS_SPLIT:-}" ]; then
            local entries
            entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')
            for entry in $entries; do
                local domain resolver res_ip res_port
                domain="${entry%%=*}"; resolver="${entry#*=}"
                res_ip="${resolver%%:*}"; res_port="${resolver##*:}"
                [ "$res_port" = "$res_ip" ] && res_port="53"
                [ -z "$domain" ] || [ -z "$res_ip" ] && continue
                echo "server=/${domain}/${res_ip}#${res_port}" >> "$DNSMASQ_CONF"
            done
        fi
    fi
}

start_dnsmasq() {
    configure_dnsmasq

    echo "nameserver 127.0.0.1" > "$RESOLV_CONF" 2>/dev/null || {
        echo "nameserver 127.0.0.1" > /tmp/resolv.conf
        mount --bind /tmp/resolv.conf "$RESOLV_CONF" 2>/dev/null || true
    }

    dnsmasq --test --conf-file="$DNSMASQ_CONF" >/tmp/dnsmasq.test 2>&1 || {
        log_json ERROR "start_dnsmasq" "config test failed"
        sed -n '1,200p' /tmp/dnsmasq.test >&2 || true
        return 0
    }

    dnsmasq --no-daemon --conf-file="$DNSMASQ_CONF" --log-facility=- &
    dnsmasq_pid=$!

    if wait_for_port 127.0.0.1 "$PORT_DNS"; then
        log_json INFO "start_dnsmasq" "started" "pid=${dnsmasq_pid}" "port=$PORT_DNS"
    else
        log_json ERROR "start_dnsmasq" "failed to bind"
    fi
}

# ===========================================================================
# PROXY SERVICES
# ===========================================================================

configure_privoxy_auth() {
    local user="${PROXY_USER:-}" pass="${PROXY_PASS:-}"
    if [ -n "$user" ] && [ -n "$pass" ]; then
        sed -i "s|^listen-address .*|listen-address 127.0.0.1:$PORT_PRIVOXY_INTERNAL|" \
            /etc/privoxy/privoxy.config
        log_json INFO "configure_privoxy_auth" "auth enabled"
    else
        sed -i "s|^listen-address .*|listen-address 0.0.0.0:$PORT_PRIVOXY_MAIN|" \
            /etc/privoxy/privoxy.config
        log_json INFO "configure_privoxy_auth" "no auth"
    fi
}

start_privoxy() {
    configure_privoxy_auth
    /usr/sbin/privoxy --no-daemon /etc/privoxy/privoxy.config &
    privoxy_pid=$!
}

start_nginx_auth() {
    local user="${PROXY_USER:-}" pass="${PROXY_PASS:-}"
    [ -n "$user" ] && [ -n "$pass" ] || return 0
    command -v nginx >/dev/null 2>&1 || {
        sed -i "s|^listen-address .*|listen-address 0.0.0.0:$PORT_PRIVOXY_MAIN|" \
            /etc/privoxy/privoxy.config
        return 0
    }

    mkdir -p /etc/nginx
    htpasswd -cbB "$HTPASSWD_FILE" "$user" "$pass"
    chmod 600 "$HTPASSWD_FILE"

    wait_for_port 127.0.0.1 "$PORT_PRIVOXY_INTERNAL" || true

    mkdir -p /run/nginx /var/log/nginx
    cat > /etc/nginx/nginx_proxy_auth.conf <<'NGINXCONF'
worker_processes 1;
error_log /dev/null crit;
pid /run/nginx/nginx_proxy_auth.pid;
events { worker_connections 64; }
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

    nginx -c /etc/nginx/nginx_proxy_auth.conf -g 'daemon off;' &
    nginx_pid=$!
    log_json INFO "start_nginx_auth" "started" "pid=${nginx_pid}"
}

# ===========================================================================
# VPNCLIENT & TAILSCALE
# ===========================================================================

start_openvpn() {
    /usr/local/bin/openvpn.sh &
    vpn_pid=$!
}

start_tailscale() {
    [ "${ENABLE_TAILSCALE:-false}" = "true" ] || return 0
    command -v tailscaled >/dev/null 2>&1 || {
        log_json WARN "start_tailscale" "not installed"
        return 0
    }

    mkdir -p /var/lib/tailscale "$TAILSCALE_RUN_DIR" || true
    tailscaled --state=/var/lib/tailscale/tailscaled.state \
        --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" \
        >/var/log/tailscaled.log 2>&1 &
    export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
    tailscaled_pid=$!

    local waited=0
    until tailscale status >/dev/null 2>&1 || [ "$waited" -ge 20 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    [ -z "${TAILSCALE_AUTHKEY:-}" ] && {
        log_json WARN "start_tailscale" "no authkey"
        return 0
    }

    local up_flags="${TAILSCALE_FLAGS:-}"
    [ "${TAILSCALE_ACCEPT_ROUTES:-false}" = "true" ] && up_flags="$up_flags --accept-routes"
    [ -n "${TAILSCALE_HOSTNAME:-}" ] && up_flags="$up_flags --hostname=${TAILSCALE_HOSTNAME}"
    [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ] && {
        up_flags="$up_flags --advertise-exit-node"
        mkdir -p /etc/sysctl.d || true
        echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" > /etc/sysctl.d/99-tailscale.conf
        sysctl -p /etc/sysctl.d/99-tailscale.conf 2>/dev/null || true
    }

    (tailscale up --accept-dns=false --authkey="$TAILSCALE_AUTHKEY" $up_flags \
        > /var/log/tailscale-up.log 2>&1) &
}

# ===========================================================================
# HEALTH CHECKS
# ===========================================================================

check_openvpn_routing() {
    command -v ip >/dev/null 2>&1 || return 0
    local out dev
    out=$(ip route get "$ROUTE_TEST_IP" 2>/dev/null || true)
    dev=$(echo "$out" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
    [ -z "$dev" ] && return 1
    case "$dev" in tun*|tap*) return 0 ;; *) return 1 ;; esac
}

restart_openvpn() {
    log_json WARN "supervisor" "restarting openvpn" "pid=${vpn_pid:-unknown}"
    kill_pid "$vpn_pid"
    [ -n "$vpn_pid" ] && wait "$vpn_pid" 2>/dev/null || true
    vpn_pid=""
    start_openvpn

    local i
    for i in {1..5}; do
        sleep 1
        if check_openvpn_routing; then
            log_json INFO "supervisor" "openvpn routing restored" "pid=${vpn_pid}"
            return 0
        fi
    done
    log_json ERROR "supervisor" "openvpn routing failed after restart"
    return 1
}

run_service_healthcheck() {
    /usr/local/bin/healthcheck.sh >"$HEALTHCHECK_LOG" 2>&1 || {
        cat "$HEALTHCHECK_LOG" >&2 || true
        log_json WARN "supervisor" "healthcheck failed"
        rm -f /tmp/vpn_healthy
        METRIC_VPN_UP=0
        return 1
    }
    return 0
}

# ===========================================================================
# CLEANUP & PROCESS MANAGEMENT
# ===========================================================================

cleanup_processes() {
    for pid in "$vpn_pid" "$privoxy_pid" "$nginx_pid" "$dnsmasq_pid" "$tailscaled_pid" "$unbound_pid"; do
        kill_pid "$pid"
    done
    local pids_to_wait=""
    for pid in "$vpn_pid" "$privoxy_pid" "$nginx_pid" "$dnsmasq_pid" "$tailscaled_pid" "$unbound_pid"; do
        [ -n "$pid" ] && pids_to_wait="$pids_to_wait $pid"
    done
    [ -n "$pids_to_wait" ] && wait $pids_to_wait 2>/dev/null || true
}

reset_pids() {
    vpn_pid="" privoxy_pid="" nginx_pid="" dnsmasq_pid="" tailscaled_pid="" unbound_pid=""
    DOT_RESOLVED_IPS=""
    unset DOT_HOST_IP_MAP
    declare -gA DOT_HOST_IP_MAP
}

# ===========================================================================
# SUPERVISEUR PRINCIPAL
# ===========================================================================

supervise_all() {
    local attempt=0

    trap 'log_json INFO supervisor "trap caught"; cleanup_processes; exit 0' INT TERM

    while true; do
        attempt=$((attempt + 1))
        METRIC_RESTART_COUNT=$((attempt - 1))
        METRIC_LAST_RESTART_TS=$(date +%s)

        log_json INFO "supervisor" "startup cycle" "attempt=${attempt}"

        start_unbound
        start_dnsmasq
        setup_iptables
        setup_ip6tables
        start_privoxy
        start_nginx_auth
        start_openvpn
        start_tailscale

        if [ "$attempt" -eq 1 ]; then
            start_metrics
            start_dot_ip_refresh
        fi

        log_json INFO "supervisor" "waiting for OpenVPN tunnel..."
        local tun_ready=0 tun_wait=0
        while [ "$tun_wait" -lt "$TIMEOUT_TUNNEL_READY" ]; do
            if check_openvpn_routing; then
                tun_ready=1
                break
            fi
            sleep 1
            tun_wait=$((tun_wait + 1))
        done

        if [ "$tun_ready" -eq 1 ]; then
            setup_return_routes
            check_vpn_ip
            touch /tmp/vpn_healthy
            METRIC_VPN_UP=1
        else
            log_json WARN "supervisor" "tunnel not ready after ${TIMEOUT_TUNNEL_READY}s"
            rm -f /tmp/vpn_healthy
            METRIC_VPN_UP=0
        fi

        [ "$attempt" -eq 1 ] && drop_capabilities
        update_metrics

        log_json INFO "supervisor" "all services running" \
            "vpn=${vpn_pid}" "dnsmasq=${dnsmasq_pid:-unknown}"

        local fail=0 stable_cycles=0 healthcheck_failures=0
        while true; do
            sleep "$SLEEP_HEALTHCHECK_INTERVAL"
            fail=0

            if ! kill -0 "$vpn_pid" 2>/dev/null; then
                log_json ERROR "supervisor" "openvpn process died"
                fail=1
            elif ! check_openvpn_routing; then
                log_json WARN "supervisor" "openvpn routing failure"
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

            local proxy_port="$PORT_PRIVOXY_MAIN"
            if [ -f /etc/privoxy/privoxy.config ]; then
                local addr
                addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' \
                    /etc/privoxy/privoxy.config 2>/dev/null || true)
                [ -n "$addr" ] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}' || true)
            fi
            if ! nc -z -w 3 127.0.0.1 "$proxy_port" 2>/dev/null; then
                log_json ERROR "supervisor" "privoxy not listening" "port=${proxy_port}"
                fail=1
            fi

            if [ -n "$nginx_pid" ]; then
                if ! kill -0 "$nginx_pid" 2>/dev/null || \
                   ! nc -z -w 3 127.0.0.1 "$PORT_NGINX" 2>/dev/null; then
                    log_json ERROR "supervisor" "nginx not responding"
                    fail=1
                fi
            fi

            if [ "${ENABLE_DOT:-false}" = "true" ] && [ -n "$unbound_pid" ]; then
                if ! kill -0 "$unbound_pid" 2>/dev/null || \
                   ! nc -z -w 1 127.0.0.1 "$PORT_UNBOUND" 2>/dev/null; then
                    log_json ERROR "supervisor" "unbound not responding"
                    fail=1
                    METRIC_DOT_ACTIVE=0
                fi
            fi

            if [ -n "$dnsmasq_pid" ]; then
                if ! kill -0 "$dnsmasq_pid" 2>/dev/null; then
                    log_json ERROR "supervisor" "dnsmasq process died"
                    fail=1
                elif ! nslookup example.com 127.0.0.1 2>/dev/null | grep -q Address; then
                    log_json ERROR "supervisor" "DNS resolution failed"
                    fail=1
                fi
            fi

            if [ -n "$tailscaled_pid" ] && ! kill -0 "$tailscaled_pid" 2>/dev/null; then
                log_json ERROR "supervisor" "tailscaled process died"
                fail=1
            fi

            if [ "$fail" -eq 0 ]; then
                if run_service_healthcheck; then
                    healthcheck_failures=0
                else
                    healthcheck_failures=$((healthcheck_failures + 1))
                    if [ "$healthcheck_failures" -ge 3 ]; then
                        log_json WARN "supervisor" "healthcheck failed repeatedly" \
                            "failures=${healthcheck_failures}" "threshold=3"
                        fail=1
                    else
                        log_json WARN "supervisor" "healthcheck failed, keeping grace period" \
                            "failures=${healthcheck_failures}" "threshold=3"
                    fi
                fi
            fi

            [ "$fail" -eq 0 ] && {
                update_metrics
                stable_cycles=$((stable_cycles + 1))
                if [ "$stable_cycles" -ge 6 ] && [ "$attempt" -gt 1 ]; then
                    attempt=1
                    stable_cycles=0
                    log_json INFO "supervisor" "services stable — backoff reset"
                fi
                continue
            }

            break
        done

        log_json ERROR "supervisor" "failure detected — restarting" "attempt=${attempt}"
        rm -f /tmp/vpn_healthy
        METRIC_VPN_UP=0
        METRIC_LAST_RESTART_TS=$(date +%s)
        update_metrics

        cleanup_processes
        reset_pids

        local sleep_s=$((5 * attempt))
        [ "$sleep_s" -gt "$BACKOFF_MAX_SECS" ] && sleep_s="$BACKOFF_MAX_SECS"
        log_json INFO "supervisor" "restart backoff" "sleep_s=${sleep_s}"
        sleep "$sleep_s"
    done
}

# ===========================================================================
# ENTRY POINT
# ===========================================================================

supervise_all