#!/bin/bash
# Firewall helper functions extracted from start.sh

ipt_add_853() {
    local ip="$1"

    if [[ "$ip" =~ : ]]; then
        if command_exists ip6tables && [ -f /proc/net/if_inet6 ]; then
            if ! ip6tables -C OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null; then
                ip6tables -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null || true
            fi
        fi
    else
        if ! iptables -C OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT 2>/dev/null; then
            iptables -A OUTPUT -p tcp -d "$ip" --dport 853 -j ACCEPT
        fi
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
    #!/bin/bash
    # ============================================================================
    # lib/firewall.sh - Firewall rule management (iptables/ip6tables)
    # ============================================================================
    # This module handles all firewall configuration including:
    # - IPv4/IPv6 iptables rules
    # - Kill switch and DNS leak prevention
    # - Port 853 (DoT) firewall rules
    # - Return routes configuration
    # ============================================================================

    # ==========================================================================
    # Helpers for IPv6 support - wrapper around ip6tables
    # ===========================================================================

    ipt6() {
        if command -v ip6tables &>/dev/null; then
            ip6tables "$@"
            return $?
        else
            return 0
        fi
    }
        iptables -A FORWARD -d "$docker_network" -j ACCEPT
    fi

    iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o tap+ -j ACCEPT
    iptables -A FORWARD -i tailscale+ -o wg+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i tap+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i wg+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tun+ -j ACCEPT
    iptables -A OUTPUT -o tap+ -j ACCEPT
    iptables -A OUTPUT -o wg+ -j ACCEPT
    iptables -A OUTPUT -o tailscale+ -j ACCEPT

    if [ -n "$docker_network" ]; then
        iptables -A OUTPUT -d "$docker_network" -j ACCEPT
    fi

    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        iptables -A OUTPUT -p tcp --sport "$PROXY_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        log_json INFO "setup_iptables" \
            "Proxy response traffic allowed via eth0" \
            "port=${PROXY_PORT}"
    fi

    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 9100 -j ACCEPT

    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 5053 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 5053 -j ACCEPT

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

        iptables -A OUTPUT -p udp ! -d 127.0.0.0/8 --dport 53 -j DROP
        iptables -A OUTPUT -p tcp ! -d 127.0.0.0/8 --dport 53 -j DROP

        log_json INFO "setup_iptables" \
            "DoT DNS leak prevention: external port 53 blocked"
    else
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

    if grep -Fq "127.0.0.11" "$RESOLV_CONF" 2>/dev/null; then
        iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT
        iptables -A OUTPUT -p udp -d 127.0.0.11 --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d 127.0.0.11 --dport 53 -j ACCEPT
    fi

    if [ "${VPN_TYPE}" = "openvpn" ]; then
        iptables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
        iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
        iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE

        log_json INFO "setup_iptables" \
            "OpenVPN firewall rules configured" \
            "vpn_proto=${VPN_PROTO}" \
            "vpn_port=${VPN_PORT}"
    elif [ "${VPN_TYPE}" = "wireguard" ]; then
        iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT

        iptables -A OUTPUT -o wg+ -j ACCEPT
        iptables -t nat -A POSTROUTING -o wg+ -j MASQUERADE

        log_json INFO "setup_iptables" \
            "WireGuard firewall rules configured"
    fi

    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true

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

    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        ipt6 -A INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
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
    ipt6 -A FORWARD -i tailscale+ -o wg+ -j ACCEPT
    ipt6 -A FORWARD -i tun+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i tap+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i wg+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A OUTPUT -o lo -j ACCEPT
    ipt6 -A OUTPUT -o tun+ -j ACCEPT
    ipt6 -A OUTPUT -o tap+ -j ACCEPT
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT
    ipt6 -A OUTPUT -o wg+ -j ACCEPT

    if [ -n "$docker6_network" ]; then
        ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT
    fi

    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        ipt6 -A OUTPUT -p tcp --sport "$PROXY_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
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
    ipt6 -t nat -A POSTROUTING -o wg+ -j MASQUERADE

    log_json INFO "setup_ip6tables" \
        "IPv6 configured - kill switch active"
}

setup_proxy_routing() {
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" != "true" ]; then
        log_json INFO "setup_proxy_routing" \
            "Skipped - ALLOW_EXTERNAL_PROXY_ACCESS is not true"
        return 0
    fi

    log_json INFO "setup_proxy_routing" \
        "Configuring proxy routing to force responses via physical interface"

    if ! iptables -t mangle -C PREROUTING -p tcp --dport "$PROXY_PORT" -j CONNMARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A PREROUTING -p tcp --dport "$PROXY_PORT" -j CONNMARK --set-mark 0x1
    fi

    if ! iptables -t mangle -C OUTPUT -m connmark --mark 0x1 -j MARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A OUTPUT -m connmark --mark 0x1 -j MARK --set-mark 0x1
    fi

    if ! iptables -t mangle -C OUTPUT -p tcp --sport "$PROXY_PORT" -j MARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A OUTPUT -p tcp --sport "$PROXY_PORT" -j MARK --set-mark 0x1
    fi

    mkdir -p /etc/iproute2
    touch /etc/iproute2/rt_tables
    if ! grep -q "^100" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "100 proxy_rt" >> /etc/iproute2/rt_tables 2>/dev/null || true
    fi

    local main_gateway
    local main_iface
    main_gateway=$(ip route show | grep "^default" | grep -v "tun\|tap\|wg" | awk '{print $3}' | head -1)
    main_iface=$(ip route show | grep "^default" | grep -v "tun\|tap\|wg" | awk '{print $5}' | head -1)

    if [ -z "$main_gateway" ] || [ -z "$main_iface" ]; then
        log_json WARN "setup_proxy_routing" \
            "Could not determine main gateway or interface - skipping advanced routing"
        return 0
    fi

    ip route replace default via "$main_gateway" dev "$main_iface" table 100 2>/dev/null || true

    if ! ip rule show | grep -q "pref 100 .*fwmark 0x1 .*lookup proxy_rt\|pref 100 .*fwmark 0x1 .*lookup 100"; then
        ip rule add pref 100 fwmark 0x1 lookup 100 2>/dev/null || true
    fi

    log_json INFO "setup_proxy_routing" \
        "Proxy routing configured - connmark + fwmark policy active" \
        "gateway=${main_gateway}" \
        "interface=${main_iface}" \
        "mark=0x1" \
        "table=100"
}

setup_return_routes() {
    log_json INFO "setup_return_routes" "Configuring return routes"

    local iface gw gw6 ips ip6s ip

    iface=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}')

    if [ -z "$iface" ]; then
        log_json WARN "setup_return_routes" \
            "no default interface found, skipping"
        return 0
    fi

    gw=$(ip -4 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}')
    gw6=$(ip -6 route show dev "$iface" 2>/dev/null | awk '/default/{print $3; exit}')

    ips=$(ip -4 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet /{print $3}')
    ip6s=$(ip -6 addr show dev "$iface" 2>/dev/null | awk -F'[ /]+' '/inet6.*global/{print $3}')

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

    if [ -n "$tun_dev" ] && ip link show "$tun_dev" >/dev/null 2>&1; then
        log_json DEBUG "supervisor" \
            "cleaning up TUN device" \
            "dev=$tun_dev"

        timeout 3 ip addr flush dev "$tun_dev" 2>/dev/null || true
    fi

    timeout 3 ip route del default via 0.0.0.0 2>/dev/null || true
    timeout 3 ip route del 0.0.0.0/1 via 10.0.0.0 2>/dev/null || true
    timeout 3 ip route del 0.0.0.0/1 dev wg0 2>/dev/null || true
    timeout 3 ip route del 128.0.0.0/1 dev wg0 2>/dev/null || true
}
#!/bin/bash
# ============================================================================
# lib/firewall.sh - Firewall rule management (iptables/ip6tables)
# ============================================================================
# This module handles all firewall configuration including:
# - IPv4/IPv6 iptables rules
# - Kill switch and DNS leak prevention  
# - Port 853 (DoT) firewall rules
# - Return routes configuration
# ============================================================================

# ===========================================================================
# Helpers for IPv6 support - wrapper around ip6tables
# ===========================================================================

ipt6() {
    # Wrapper to use ip6tables if available, fallback to echo
    if command -v ip6tables &>/dev/null; then
        ip6tables "$@"
        return $?
    else
        return 0
    fi
}

# ===========================================================================
# DoT (DNS over TLS) - Firewall port 853 rules
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

# ===========================================================================
# IPv4 Firewall - Kill switch + DNS leak prevention
# ===========================================================================

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

    # External proxy access (if explicitly enabled)
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        iptables -A INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        log_json INFO "setup_iptables" \
            "Proxy port open to external access" \
            "port=${PROXY_PORT}"
    else
        log_json INFO "setup_iptables" \
            "Proxy port restricted to Docker network only" \
            "port=${PROXY_PORT}"
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
    iptables -A FORWARD -i tailscale+ -o wg+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i tap+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i wg+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # OUTPUT - interfaces autorisées
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -o tun+ -j ACCEPT
    iptables -A OUTPUT -o tap+ -j ACCEPT
    iptables -A OUTPUT -o wg+ -j ACCEPT
    iptables -A OUTPUT -o tailscale+ -j ACCEPT

    if [ -n "$docker_network" ]; then
        iptables -A OUTPUT -d "$docker_network" -j ACCEPT
    fi

    # Proxy responses (allow replies back when external access enabled)
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        iptables -A OUTPUT -p tcp --sport "$PROXY_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        log_json INFO "setup_iptables" \
            "Proxy response traffic allowed via eth0" \
            "port=${PROXY_PORT}"
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

    # VPN Configuration
    if [ "${VPN_TYPE}" = "openvpn" ]; then
        # OpenVPN
        iptables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
        iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
        iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE
        
        log_json INFO "setup_iptables" \
            "OpenVPN firewall rules configured" \
            "vpn_proto=${VPN_PROTO}" \
            "vpn_port=${VPN_PORT}"
            
    elif [ "${VPN_TYPE}" = "wireguard" ]; then
        # WireGuard - allow outgoing UDP packets to WireGuard endpoint (port 51820)
        iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT
        
        # Allow all traffic through wg interface
        iptables -A OUTPUT -o wg+ -j ACCEPT
        iptables -t nat -A POSTROUTING -o wg+ -j MASQUERADE
        
        log_json INFO "setup_iptables" \
            "WireGuard firewall rules configured"
    fi
    
    # Propriétaire du groupe vpn (pour les deux)
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true

    log_json INFO "setup_iptables" \
        "IPv4 configured - kill switch active" \
        "vpn_proto=${VPN_PROTO}" \
        "vpn_port=${VPN_PORT}"
}

# ===========================================================================
# IPv6 Firewall - Kill switch + DNS leak prevention
# ===========================================================================

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

    # External proxy access (if explicitly enabled)
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        ipt6 -A INPUT -p tcp --dport "$PROXY_PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
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
    ipt6 -A FORWARD -i tailscale+ -o wg+ -j ACCEPT
    ipt6 -A FORWARD -i tun+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i tap+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A FORWARD -i wg+ -o tailscale+ \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt6 -A OUTPUT -o lo -j ACCEPT
    ipt6 -A OUTPUT -o tun+ -j ACCEPT
    ipt6 -A OUTPUT -o tap+ -j ACCEPT
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT
    ipt6 -A OUTPUT -o wg+ -j ACCEPT

    if [ -n "$docker6_network" ]; then
        ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT
    fi

    # Proxy responses (allow replies back when external access enabled)
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" = "true" ]; then
        ipt6 -A OUTPUT -p tcp --sport "$PROXY_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
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
    ipt6 -t nat -A POSTROUTING -o wg+ -j MASQUERADE

    log_json INFO "setup_ip6tables" \
        "IPv6 configured - kill switch active"
}

# ===========================================================================
# Advanced proxy routing - force proxy responses via physical interface
# ===========================================================================

setup_proxy_routing() {
    if [ "${ALLOW_EXTERNAL_PROXY_ACCESS:-false}" != "true" ]; then
        log_json INFO "setup_proxy_routing" \
            "Skipped - ALLOW_EXTERNAL_PROXY_ACCESS is not true"
        return 0
    fi

    log_json INFO "setup_proxy_routing" \
        "Configuring proxy routing to force responses via physical interface"

    # Track proxy client connections in conntrack and mark response packets.
    # Using CONNMARK is more reliable than only matching source port in OUTPUT.
    if ! iptables -t mangle -C PREROUTING -p tcp --dport "$PROXY_PORT" -j CONNMARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A PREROUTING -p tcp --dport "$PROXY_PORT" -j CONNMARK --set-mark 0x1
    fi

    # Restore packet mark from connection mark for locally generated responses.
    if ! iptables -t mangle -C OUTPUT -m connmark --mark 0x1 -j MARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A OUTPUT -m connmark --mark 0x1 -j MARK --set-mark 0x1
    fi

    # Fallback: directly mark packets emitted from proxy port.
    if ! iptables -t mangle -C OUTPUT -p tcp --sport "$PROXY_PORT" -j MARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -A OUTPUT -p tcp --sport "$PROXY_PORT" -j MARK --set-mark 0x1
    fi

    # Create a new routing table for marked traffic
    # Use table 100 (avoid conflicts with default tables 0-252)
    # Ensure the rt_tables directory and file exist
    mkdir -p /etc/iproute2
    touch /etc/iproute2/rt_tables
    
    if ! grep -q "^100" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "100 proxy_rt" >> /etc/iproute2/rt_tables 2>/dev/null || true
    fi

    # Get the main gateway and interface (usually eth0)
    local main_gateway
    local main_iface
    main_gateway=$(ip route show | grep "^default" | grep -v "tun\|tap\|wg" | awk '{print $3}' | head -1)
    main_iface=$(ip route show | grep "^default" | grep -v "tun\|tap\|wg" | awk '{print $5}' | head -1)

    if [ -z "$main_gateway" ] || [ -z "$main_iface" ]; then
        log_json WARN "setup_proxy_routing" \
            "Could not determine main gateway or interface - skipping advanced routing"
        return 0
    fi

    # Keep proxy routing table in sync with current gateway/interface.
    ip route replace default via "$main_gateway" dev "$main_iface" table 100 2>/dev/null || true

    # Route marked packets via proxy routing table with high priority
    # so it wins over source-based rules (e.g. table 10).
    if ! ip rule show | grep -q "pref 100 .*fwmark 0x1 .*lookup proxy_rt\|pref 100 .*fwmark 0x1 .*lookup 100"; then
        ip rule add pref 100 fwmark 0x1 lookup 100 2>/dev/null || true
    fi

    log_json INFO "setup_proxy_routing" \
        "Proxy routing configured - connmark + fwmark policy active" \
        "gateway=${main_gateway}" \
        "interface=${main_iface}" \
        "mark=0x1" \
        "table=100"
}

# ===========================================================================
# Return routes configuration
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

# ===========================================================================
# Cleanup routes on restart
# ===========================================================================

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
    # Clean up WireGuard routes
    timeout 3 ip route del 0.0.0.0/1 dev wg0 2>/dev/null || true
    timeout 3 ip route del 128.0.0.0/1 dev wg0 2>/dev/null || true
}
