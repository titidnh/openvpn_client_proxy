#!/bin/bash

set -eu
set -o pipefail

conf="/vpn/vpn.conf"
TAILSCALE_RUN_DIR="${TAILSCALE_RUN_DIR:-/var/run/tailscale}"

# PID variables — initialisées à vide pour éviter les erreurs avec set -eu
vpn_pid=""
privoxy_pid=""
dnsmasq_pid=""
tailscaled_pid=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Wrapper ip6tables : absorbe les erreurs (module absent, IPv6 indisponible)
ipt6() { ip6tables "$@" 2>/dev/null || true; }

# Tue un processus seulement si son PID est non vide
kill_if_running() {
    local pid="$1"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
}

# Lit le port et protocole OpenVPN depuis $conf (défauts : 1194/udp)
get_vpn_port_proto() {
    VPN_PORT="1194"
    VPN_PROTO="udp"
    if [ -f "$conf" ]; then
        VPN_PORT=$(awk '
            /^remote / {
                for (i=1; i<=NF; i++)
                    if ($i ~ /:/) { split($i, a, ":"); print a[2]; exit }
                if (NF >= 3) { print $3; exit }
            }' "$conf" | head -1)
        VPN_PORT=${VPN_PORT:-1194}
        VPN_PROTO=$(awk '/^proto /{print $2; exit}' "$conf")
        VPN_PROTO=${VPN_PROTO:-udp}
    fi
}

# Émet les IPs upstream déclarées dans dnsmasq.conf (une par ligne)
get_dns_upstreams() {
    [ -f /etc/dnsmasq.conf ] || return 0
    grep -E '^[[:space:]]*server=' /etc/dnsmasq.conf \
        | sed 's/.*server=\([^#]*\).*/\1/' \
        | awk -F'[#@]' '{print $1}'
}

# Vérifie et log l'IP publique via le proxy pour confirmer que le trafic
# sort bien par le VPN. Appelé une fois après que le tunnel est monté.
check_vpn_ip() {
    if ! command -v curl >/dev/null 2>&1; then
        echo "[check_vpn_ip] curl not available, skipping public IP check"
        return 0
    fi

    local proxy_port=3128
    if [ -f /etc/privoxy/privoxy.config ]; then
        local addr
        addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' /etc/privoxy/privoxy.config || true)
        [ -n "$addr" ] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
    fi

    local public_ip
    public_ip=$(curl -fsS --max-time 10 \
        --proxy "http://127.0.0.1:${proxy_port}" \
        https://api.ipify.org 2>/dev/null || true)

    if [ -n "$public_ip" ]; then
        echo "[check_vpn_ip] public IP via VPN: $public_ip"
    else
        echo "[check_vpn_ip] could not determine public IP (tunnel may still be initializing)"
    fi
}

# ---------------------------------------------------------------------------
# Firewall IPv4
# ---------------------------------------------------------------------------

setup_iptables() {
    local docker_network
    docker_network="$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet"{print $4}' || true)"

    get_vpn_port_proto

    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -P INPUT   DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT  DROP

    # INPUT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    [ -n "$docker_network" ] && iptables -A INPUT -s "$docker_network" -j ACCEPT

    # FORWARD — Docker + Tailscale exit-node vers tunnel VPN
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i lo -j ACCEPT
    [ -n "$docker_network" ] && iptables -A FORWARD -s "$docker_network" -j ACCEPT
    [ -n "$docker_network" ] && iptables -A FORWARD -d "$docker_network" -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i tap+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # OUTPUT — interfaces autorisées
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo         -j ACCEPT
    iptables -A OUTPUT -o tun+       -j ACCEPT
    iptables -A OUTPUT -o tap+       -j ACCEPT
    iptables -A OUTPUT -o tailscale+ -j ACCEPT
    [ -n "$docker_network" ] && iptables -A OUTPUT -d "$docker_network" -j ACCEPT

    # OUTPUT — DNS local (dnsmasq) + upstreams
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT
    while read -r dns; do
        [[ "$dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
    done < <(get_dns_upstreams)

    # OUTPUT — DNS Docker interne
    if grep -Fq "127.0.0.11" /etc/resolv.conf 2>/dev/null; then
        iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT
        iptables -A OUTPUT -p udp -d 127.0.0.11 --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d 127.0.0.11 --dport 53 -j ACCEPT
    fi

    # OUTPUT — trafic OpenVPN (port explicite + gid-owner en bonus)
    iptables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true

    # NAT — tout ce qui sort par le tunnel est masqué (couvre OpenVPN + Tailscale exit-node)
    iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    echo "[setup_iptables] IPv4 configured — kill switch active, VPN on $VPN_PROTO/$VPN_PORT"
}

# ---------------------------------------------------------------------------
# Firewall IPv6
# ---------------------------------------------------------------------------

setup_ip6tables() {
    if ! command -v ip6tables >/dev/null 2>&1; then
        echo "[setup_ip6tables] ip6tables not installed, skipping"
        return 0
    fi
    if [ ! -f /proc/net/if_inet6 ]; then
        echo "[setup_ip6tables] IPv6 not available, skipping"
        return 0
    fi

    local docker6_network
    docker6_network="$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet6"{print $4; exit}' || true)"

    # VPN_PORT and VPN_PROTO already set by setup_iptables

    ipt6 -F; ipt6 -X
    ipt6 -t nat -F
    ipt6 -P INPUT   DROP
    ipt6 -P FORWARD DROP
    ipt6 -P OUTPUT  DROP

    # INPUT
    ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A INPUT -p icmpv6 -j ACCEPT   # NDP indispensable
    ipt6 -A INPUT -i lo -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A INPUT -s "$docker6_network" -j ACCEPT

    # FORWARD — Docker + Tailscale exit-node vers tunnel VPN
    ipt6 -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -p icmpv6 -j ACCEPT
    ipt6 -A FORWARD -i lo -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A FORWARD -s "$docker6_network" -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A FORWARD -d "$docker6_network" -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    ipt6 -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    ipt6 -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i tap+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # OUTPUT — interfaces autorisées
    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A OUTPUT -o lo         -j ACCEPT
    ipt6 -A OUTPUT -o tun+       -j ACCEPT
    ipt6 -A OUTPUT -o tap+       -j ACCEPT
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT

    # OUTPUT — DNS local (dnsmasq) + upstreams IPv6
    ipt6 -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT
    while read -r dns; do
        [[ "$dns" =~ : ]] || continue   # IPv6 contient toujours ':'
        ipt6 -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
        ipt6 -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
    done < <(get_dns_upstreams)

    # OUTPUT — trafic OpenVPN (port explicite + gid-owner en bonus)
    ipt6 -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
    ipt6 -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT
    ipt6 -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT

    # NAT — tout ce qui sort par le tunnel est masqué (couvre OpenVPN + Tailscale exit-node)
    ipt6 -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    ipt6 -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    echo "[setup_ip6tables] IPv6 configured — kill switch active"
}

# ---------------------------------------------------------------------------
# Routes retour (appelé après que le tunnel tun est monté)
# ---------------------------------------------------------------------------

setup_return_routes() {
    local iface gw gw6 ips ip6s

    iface=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}')
    if [ -z "$iface" ]; then
        echo "[setup_return_routes] no default interface found, skipping"
        return 0
    fi

    gw=$(ip -4 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}')
    gw6=$(ip -6 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}')
    ips=$(ip -4 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet /{print $3}')
    ip6s=$(ip -6 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet6.*global/{print $3}')

    # Table 10 IPv4
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

    # Table 10 IPv6
    for ip6 in $ip6s; do
        ip -6 rule show table 10 2>/dev/null | grep -q "$ip6" || \
            ip -6 rule add from "$ip6" lookup 10 2>/dev/null || true
        ipt6 -C INPUT -d "$ip6" -j ACCEPT || ipt6 -A INPUT -d "$ip6" -j ACCEPT
    done
    [ -n "$gw6" ] && {
        ip -6 route show table 10 2>/dev/null | grep -q "default" || \
            ip -6 route add default via "$gw6" table 10 2>/dev/null || true
    }

    echo "[setup_return_routes] return routes configured via $iface"
}

# ---------------------------------------------------------------------------
# Démarrage des services
# ---------------------------------------------------------------------------

start_dnsmasq() {
    [ -f /etc/dnsmasq.conf ] || return 0

    echo "nameserver 127.0.0.1" > /etc/resolv.conf || {
        echo "nameserver 127.0.0.1" > /tmp/resolv.conf
        mount --bind /tmp/resolv.conf /etc/resolv.conf || true
    }

    if ! dnsmasq --test --conf-file=/etc/dnsmasq.conf >/tmp/dnsmasq.test 2>&1; then
        echo "[start_dnsmasq] config test failed:"
        sed -n '1,200p' /tmp/dnsmasq.test || true
        return 0
    fi

    dnsmasq --no-daemon --conf-file=/etc/dnsmasq.conf --log-facility=- &
    dnsmasq_pid=$!

    local bound=0 i
    for i in 1 2 3 4 5; do
        nc -z -w 1 127.0.0.1 53 >/dev/null 2>&1 && { bound=1; break; }
        sleep 1
    done

    if [ "$bound" -eq 1 ]; then
        echo "[start_dnsmasq] started (pid=$dnsmasq_pid) listening on 127.0.0.1:53"
    else
        echo "[start_dnsmasq] dnsmasq did not bind to 127.0.0.1:53"
    fi
}

start_privoxy() {
    /usr/sbin/privoxy --no-daemon /etc/privoxy/privoxy.config &
    privoxy_pid=$!
}

start_openvpn() {
    /usr/local/bin/openvpn.sh &
    vpn_pid=$!
}

start_tailscale() {
    [ "${ENABLE_TAILSCALE:-false}" = "true" ] || return 0

    if ! command -v tailscaled >/dev/null 2>&1; then
        echo "[start_tailscale] tailscaled not installed; skipping"
        return 0
    fi

    mkdir -p /var/lib/tailscale "$TAILSCALE_RUN_DIR" || true

    echo "[start_tailscale] starting tailscaled"
    tailscaled \
        --state="/var/lib/tailscale/tailscaled.state" \
        --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" \
        >/var/log/tailscaled.log 2>&1 &
    export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
    tailscaled_pid=$!

    local waited=0
    until tailscale status >/dev/null 2>&1 || [ "$waited" -ge 20 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    if [ -z "${TAILSCALE_AUTHKEY:-}" ]; then
        echo "[start_tailscale] no authkey provided; skipping 'tailscale up'"
        return 0
    fi

    local up_flags="${TAILSCALE_FLAGS:-}"
    [ "${TAILSCALE_ACCEPT_ROUTES:-false}"       = "true" ] && up_flags="$up_flags --accept-routes"
    [ -n "${TAILSCALE_HOSTNAME:-}" ]                       && up_flags="$up_flags --hostname=${TAILSCALE_HOSTNAME}"
    [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ] && {
        up_flags="$up_flags --advertise-exit-node"
        mkdir -p /etc/sysctl.d || true
        cat > /etc/sysctl.d/99-tailscale.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
        sysctl -p /etc/sysctl.d/99-tailscale.conf || true
        (tailscale set --advertise-exit-node=true >> /var/log/tailscale-up.log 2>&1) || true &
    }

    echo "[start_tailscale] running 'tailscale up'"
    # shellcheck disable=SC2086
    (tailscale up --accept-dns=false --authkey="$TAILSCALE_AUTHKEY" $up_flags \
        > /var/log/tailscale-up.log 2>&1) &
}

# ---------------------------------------------------------------------------
# Monitoring OpenVPN
# ---------------------------------------------------------------------------

check_openvpn_routing() {
    command -v ip >/dev/null 2>&1 || return 0
    local out dev
    out=$(ip route get 8.8.8.8 2>/dev/null || true)
    dev=$(echo "$out" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [ -z "$dev" ] && return 1
    case "$dev" in tun*|tap*) ;; *) return 1 ;; esac
    ip -4 addr show dev "$dev" >/dev/null 2>&1
}

restart_openvpn() {
    echo "[supervisor] restarting openvpn (pid=${vpn_pid:-unknown})"
    kill_if_running "$vpn_pid"
    wait "$vpn_pid" 2>/dev/null || true
    vpn_pid=""
    start_openvpn
    local i
    for i in 1 2 3 4 5; do
        sleep 1
        if check_openvpn_routing; then
            echo "[supervisor] openvpn routing restored (pid=$vpn_pid)"
            return 0
        fi
    done
    echo "[supervisor] openvpn routing still not functional after restart"
    return 1
}

# ---------------------------------------------------------------------------
# Superviseur principal
# ---------------------------------------------------------------------------

supervise_all() {
    local attempt=0

    while true; do
        attempt=$((attempt + 1))

        start_dnsmasq
        setup_iptables
        setup_ip6tables
        start_privoxy
        start_openvpn
        start_tailscale

        # Attendre que le tunnel tun soit monté avant d'ajouter les routes retour
        echo "[supervisor] waiting for OpenVPN tunnel..."
        local tun_ready=0 tun_wait=0
        while [ "$tun_wait" -lt 30 ]; do
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
        else
            echo "[supervisor] tunnel not ready after 30s, skipping return routes"
            rm -f /tmp/vpn_healthy
        fi

        echo "[supervisor] started: vpn=$vpn_pid dnsmasq=${dnsmasq_pid:-unknown} privoxy=${privoxy_pid:-unknown}"

        local fail=0 proxy_port addr stable_cycles=0
        while true; do
            sleep 10

            # OpenVPN process
            if ! kill -0 "$vpn_pid" >/dev/null 2>&1; then
                echo "[supervisor] openvpn process died"
                fail=1
            fi

            # OpenVPN routing
            if [ "$fail" -eq 0 ] && ! check_openvpn_routing; then
                echo "[supervisor] openvpn routing failure detected"
                rm -f /tmp/vpn_healthy
                if restart_openvpn; then
                    # Tunnel restauré — reconfigurer les routes retour au cas où
                    setup_return_routes
                    check_vpn_ip
                    touch /tmp/vpn_healthy
                    continue
                else
                    fail=1
                fi
            fi

            # Privoxy
            proxy_port=3128
            if [ -f /etc/privoxy/privoxy.config ]; then
                addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' /etc/privoxy/privoxy.config || true)
                [ -n "$addr" ] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
            fi
            if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
                echo "[supervisor] privoxy not listening on 127.0.0.1:$proxy_port"
                fail=1
            fi

            # dnsmasq
            if [ -n "$dnsmasq_pid" ]; then
                if ! kill -0 "$dnsmasq_pid" >/dev/null 2>&1; then
                    echo "[supervisor] dnsmasq process died"
                    fail=1
                elif ! nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                    echo "[supervisor] DNS resolution via 127.0.0.1 failed"
                    fail=1
                fi
            fi

            # Tailscale
            if [ -n "$tailscaled_pid" ] && ! kill -0 "$tailscaled_pid" >/dev/null 2>&1; then
                echo "[supervisor] tailscaled process died"
                fail=1
            fi

            [ "$fail" -eq 1 ] && break

            # Reset backoff counter after 6 consecutive stable cycles (~1 min)
            stable_cycles=$((stable_cycles + 1))
            if [ "$stable_cycles" -ge 6 ] && [ "$attempt" -gt 1 ]; then
                attempt=1
                stable_cycles=0
                echo "[supervisor] services stable — backoff counter reset"
            fi
        done

        echo "[supervisor] failure detected - killing services to restart"
        rm -f /tmp/vpn_healthy
        kill_if_running "$vpn_pid"
        kill_if_running "$privoxy_pid"
        kill_if_running "$dnsmasq_pid"
        kill_if_running "$tailscaled_pid"
        wait 2>/dev/null || true
        vpn_pid="" privoxy_pid="" dnsmasq_pid="" tailscaled_pid=""

        local sleep_s=$((5 * attempt))
        [ "$sleep_s" -gt 60 ] && sleep_s=60
        echo "[supervisor] restarting all services in ${sleep_s}s (attempt ${attempt})"
        sleep "$sleep_s"
    done
}

trap 'kill 0 || true; exit 0' INT TERM

supervise_all