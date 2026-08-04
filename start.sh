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
        VPN_PORT=$(awk '
            /^remote / {
                for (i=1; i<=NF; i++)
                    if ($i ~ /:/) { split($i, a, ":"); print a[2]; exit }
                if (NF >= 3) { print $3; exit }
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
    docker_network="$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet"{print $4}' || true)"

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
    docker6_network="$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet6"{print $4; exit}' || true)"

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
# SUPERVISEUR PRINCIPAL (Corrigé)
# ===========================================================================
supervise_all() {
    local attempt=0

    # Remplace le trap global pour éviter de tuer tous les processus
    trap 'log_json INFO supervisor "trap caught"; cleanup_processes; exit 0' INT TERM

    while true; do
        attempt=$((attempt + 1))
        METRIC_RESTART_COUNT=$((attempt - 1))
        METRIC_LAST_RESTART_TS=$(date +%s)

        log_json INFO "supervisor" "startup cycle" "attempt=${attempt}"

        # Démarrer services
        start_unbound
        start_dnsmasq
        setup_iptables
        setup_ip6tables
        start_privoxy
        start_nginx_auth
        start_openvpn
        start_tailscale

        # Services auxiliaires (1ère fois seulement)
        if [ "$attempt" -eq 1 ]; then
            start_metrics
            start_dot_ip_refresh
        fi

        # Attendre tunnel
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

        # Boucle de monitoring
        local fail=0 stable_cycles=0 healthcheck_failures=0
        while true; do
            sleep "$SLEEP_HEALTHCHECK_INTERVAL"
            fail=0

            # Check OpenVPN
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

            # Check Privoxy
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

            # Check nginx auth
            if [ -n "$nginx_pid" ]; then
                if ! kill -0 "$nginx_pid" 2>/dev/null || \
                   ! nc -z -w 3 127.0.0.1 "$PORT_NGINX" 2>/dev/null; then
                    log_json ERROR "supervisor" "nginx not responding"
                    fail=1
                fi
            fi

            # Check unbound
            if [ "${ENABLE_DOT:-false}" = "true" ] && [ -n "$unbound_pid" ]; then
                if ! kill -0 "$unbound_pid" 2>/dev/null || \
                   ! nc -z -w 1 127.0.0.1 "$PORT_UNBOUND" 2>/dev/null; then
                    log_json ERROR "supervisor" "unbound not responding"
                    fail=1
                    METRIC_DOT_ACTIVE=0
                fi
            fi

            # Check dnsmasq
            if [ -n "$dnsmasq_pid" ]; then
                if ! kill -0 "$dnsmasq_pid" 2>/dev/null; then
                    log_json ERROR "supervisor" "dnsmasq process died"
                    fail=1
                elif ! nslookup example.com 127.0.0.1 2>/dev/null | grep -q Address; then
                    log_json ERROR "supervisor" "DNS resolution failed"
                    fail=1
                fi
            fi

            # Check tailscale
            if [ -n "$tailscaled_pid" ] && ! kill -0 "$tailscaled_pid" 2>/dev/null; then
                log_json ERROR "supervisor" "tailscaled process died"
                fail=1
            fi

            # Healthcheck
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
# ENTRY POINT (Corrigé)
# ===========================================================================
# Supprime le trap global problématique
# trap 'kill 0 || true; exit 0' INT TERM  # <-- Supprimé

# Démarre le superviseur
supervise_all