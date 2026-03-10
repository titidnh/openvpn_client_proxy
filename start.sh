#!/bin/bash

set -eu
set -o pipefail

conf="/vpn/vpn.conf"
TAILSCALE_RUN_DIR="${TAILSCALE_RUN_DIR:-/var/run/tailscale}"

# PID variables
vpn_pid=""
privoxy_pid=""
nginx_pid=""
dnsmasq_pid=""
tailscaled_pid=""
unbound_pid=""
metrics_pid=""
dot_refresh_pid=""

# Compteurs de métriques
METRIC_RESTART_COUNT=0
METRIC_VPN_UP=0
METRIC_DOT_ACTIVE=0
METRIC_LAST_RESTART_TS=0
METRIC_START_TS=$(date +%s)

# IPs DoT résolues avant que resolv.conf soit modifié par dnsmasq
DOT_RESOLVED_IPS=""
declare -A DOT_HOST_IP_MAP

# ===========================================================================
# Logging JSON structuré
# ===========================================================================
# Usage : log_json LEVEL component "message" [key=val ...]
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
        "$ts" "$level" "$component" "$message" "$extra"
}

# ===========================================================================
# Helpers généraux
# ===========================================================================

ipt6() { ip6tables "$@" 2>/dev/null || true; }

# ipt_add_853 / ipt_del_853 — ajoute/supprime une règle port 853
# en choisissant iptables (IPv4) ou ip6tables (IPv6) selon l'adresse
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

kill_if_running() {
    local pid="$1"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
}

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

get_dns_upstreams() {
    [ -f /etc/dnsmasq.conf ] || return 0
    grep -E '^[[:space:]]*server=' /etc/dnsmasq.conf \
        | sed 's/.*server=\([^#]*\).*/\1/' \
        | awk -F'[#@]' '{print $1}'
}

check_vpn_ip() {
    if ! command -v curl >/dev/null 2>&1; then
        log_json WARN check_vpn_ip "curl not available, skipping public IP check"
        return 0
    fi

    local proxy_port=3128
    if [ -f /etc/privoxy/privoxy.config ]; then
        local addr
        addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' /etc/privoxy/privoxy.config || true)
        [ -n "$addr" ] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
    fi

    local public_ip
    local proxy_url="http://127.0.0.1:${proxy_port}"
    if [ -n "${PROXY_USER:-}" ] && [ -n "${PROXY_PASS:-}" ]; then
        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${proxy_port}"
    fi
    public_ip=$(curl -fsS --max-time 10 --proxy "$proxy_url" \
        https://api.ipify.org 2>/dev/null || true)

    if [ -n "$public_ip" ]; then
        log_json INFO check_vpn_ip "public IP via VPN confirmed" "ip=${public_ip}"
        METRIC_VPN_UP=1
    else
        log_json WARN check_vpn_ip "could not determine public IP (tunnel may still be initializing)"
    fi
}

# ===========================================================================
# Firewall IPv4
# ===========================================================================

setup_iptables() {
    local docker_network
    docker_network="$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet"{print $4}' || true)"

    get_vpn_port_proto

    iptables -F; iptables -X; iptables -t nat -F
    iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP

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

    # OUTPUT — interfaces
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o lo         -j ACCEPT
    iptables -A OUTPUT -o tun+       -j ACCEPT
    iptables -A OUTPUT -o tap+       -j ACCEPT
    iptables -A OUTPUT -o tailscale+ -j ACCEPT
    [ -n "$docker_network" ] && iptables -A OUTPUT -d "$docker_network" -j ACCEPT

    # OUTPUT — métriques locales (loopback uniquement)
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 9100 -j ACCEPT

    # OUTPUT — DNS local
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53   -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53   -j ACCEPT
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 5053 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 5053 -j ACCEPT

    # Port 53 toujours autorisé uniquement vers DNS_SERVER_1/2 (DOT actif ou non)
    # Nécessaire au boot pour que parse_dot_servers() puisse résoudre les hostnames DoT
    # et pour que dnsmasq puisse contacter les upstreams.
    for _dns in "${DNS_SERVER_1:-}" "${DNS_SERVER_2:-}"; do
        [[ "$_dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        iptables -A OUTPUT -p udp -d "$_dns" --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "$_dns" --dport 53 -j ACCEPT
        log_json INFO setup_iptables "allowing port 53" "ip=${_dns}"
    done

    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        if [ -n "$DOT_RESOLVED_IPS" ]; then
            for dot_ip in $DOT_RESOLVED_IPS; do
                ipt_add_853 "$dot_ip"
                log_json INFO setup_iptables "DoT: allowing TCP 853" "ip=${dot_ip}"
            done
        else
            log_json WARN setup_iptables "DoT: no resolved IPs — TCP 853 not explicitly allowed"
        fi
        # Kill switch : bloquer tout DNS 53 externe sauf DNS_SERVER_1/2 déjà autorisés ci-dessus
        iptables -A OUTPUT -p udp ! -d 127.0.0.0/8 --dport 53 -j DROP
        iptables -A OUTPUT -p tcp ! -d 127.0.0.0/8 --dport 53 -j DROP
        log_json INFO setup_iptables "DoT DNS leak prevention: external port 53 blocked except DNS_SERVER_1/2"
    else
        # Mode non-DoT : autoriser aussi les upstreams dnsmasq (si différents de DNS_SERVER_1/2)
        while read -r dns; do
            [[ "$dns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams)
    fi

    # OUTPUT — DNS Docker interne
    if grep -Fq "127.0.0.11" /etc/resolv.conf 2>/dev/null; then
        iptables -A OUTPUT -d 127.0.0.11 -j ACCEPT
        iptables -A OUTPUT -p udp -d 127.0.0.11 --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d 127.0.0.11 --dport 53 -j ACCEPT
    fi

    # OUTPUT — OpenVPN
    iptables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
    iptables -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true
    iptables -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT 2>/dev/null || true

    # NAT
    iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    log_json INFO setup_iptables "IPv4 configured — kill switch active" \
        "vpn_proto=${VPN_PROTO}" "vpn_port=${VPN_PORT}"
}

# ===========================================================================
# Firewall IPv6
# ===========================================================================

setup_ip6tables() {
    if ! command -v ip6tables >/dev/null 2>&1; then
        log_json WARN setup_ip6tables "ip6tables not installed, skipping"; return 0
    fi
    if [ ! -f /proc/net/if_inet6 ]; then
        log_json WARN setup_ip6tables "IPv6 not available, skipping"; return 0
    fi

    local docker6_network
    docker6_network="$(ip -o addr show dev eth0 2>/dev/null | awk '$3=="inet6"{print $4; exit}' || true)"

    ipt6 -F; ipt6 -X; ipt6 -t nat -F
    ipt6 -P INPUT DROP; ipt6 -P FORWARD DROP; ipt6 -P OUTPUT DROP

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
    ipt6 -A OUTPUT -o lo         -j ACCEPT
    ipt6 -A OUTPUT -o tun+       -j ACCEPT
    ipt6 -A OUTPUT -o tap+       -j ACCEPT
    ipt6 -A OUTPUT -o tailscale+ -j ACCEPT
    [ -n "$docker6_network" ] && ipt6 -A OUTPUT -d "$docker6_network" -j ACCEPT

    # OUTPUT — métriques locales (loopback IPv6)
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 9100 -j ACCEPT

    ipt6 -A OUTPUT -p udp -d ::1 --dport 53   -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 53   -j ACCEPT
    ipt6 -A OUTPUT -p udp -d ::1 --dport 5053 -j ACCEPT
    ipt6 -A OUTPUT -p tcp -d ::1 --dport 5053 -j ACCEPT

    if [ "${ENABLE_DOT:-false}" = "true" ]; then
        ipt6 -A OUTPUT -p udp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true
        ipt6 -A OUTPUT -p tcp ! -d ::1 --dport 53 -j DROP 2>/dev/null || true
        log_json INFO setup_ip6tables "DoT DNS leak prevention: IPv6 port 53 blocked"
    else
        while read -r dns; do
            [[ "$dns" =~ : ]] || continue
            ipt6 -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
            ipt6 -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
        done < <(get_dns_upstreams)
    fi

    ipt6 -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT
    ipt6 -A OUTPUT -p tcp -m owner --gid-owner vpn -j ACCEPT
    ipt6 -A OUTPUT -p udp -m owner --gid-owner vpn -j ACCEPT

    ipt6 -t nat -A POSTROUTING -o tun+ -j MASQUERADE
    ipt6 -t nat -A POSTROUTING -o tap+ -j MASQUERADE

    log_json INFO setup_ip6tables "IPv6 configured — kill switch active"
}

# ===========================================================================
# Routes retour
# ===========================================================================

setup_return_routes() {
    local iface gw gw6 ips ip6s

    iface=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}')
    if [ -z "$iface" ]; then
        log_json WARN setup_return_routes "no default interface found, skipping"; return 0
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

    log_json INFO setup_return_routes "return routes configured" "iface=${iface}"
}

# ===========================================================================
# DNS-over-TLS via Unbound
# ===========================================================================

# ---------------------------------------------------------------------------
# parse_dot_servers — résout les hostnames DoT AVANT que dnsmasq prenne la
# main sur resolv.conf. Peuple DOT_RESOLVED_IPS et DOT_HOST_IP_MAP.
# Retourne les lignes forward-addr pour unbound.conf.
# ---------------------------------------------------------------------------
# Fichier persistant pour les IPs DoT — lisible depuis les subshells (dot_refresh)
DOT_IP_MAP_FILE="/tmp/dot_ip_map"

# dot_ip_map_set HOST IP — écrit dans le fichier et met à jour le tableau associatif
dot_ip_map_set() {
    local host="$1" ip="$2"
    DOT_HOST_IP_MAP["$host"]="$ip"
    # Écriture atomique via tmp + mv
    local tmp; tmp=$(mktemp /tmp/dot_ip_map.XXXXXX)
    # Recopie les entrées existantes en excluant cet host
    [ -f "$DOT_IP_MAP_FILE" ] && grep -v "^${host}=" "$DOT_IP_MAP_FILE" > "$tmp" || true
    echo "${host}=${ip}" >> "$tmp"
    mv -f "$tmp" "$DOT_IP_MAP_FILE"
}

# dot_ip_map_get HOST — retourne l'IP ou vide
dot_ip_map_get() {
    local host="$1"
    # Priorité : tableau en mémoire (process courant), sinon fichier (subshells)
    if [ -n "${DOT_HOST_IP_MAP[$host]:-}" ]; then
        echo "${DOT_HOST_IP_MAP[$host]}"
    elif [ -f "$DOT_IP_MAP_FILE" ]; then
        grep "^${host}=" "$DOT_IP_MAP_FILE" | cut -d= -f2- | tail -1
    fi
}

# Fichier pour les forward-addr unbound (évite le subshell dans configure_unbound)
DOT_FORWARD_ADDRS_FILE="/tmp/dot_forward_addrs"

parse_dot_servers() {
    local servers="${DOT_DNS_SERVERS:-tls://dns.adguard-dns.com}"
    servers=$(echo "$servers" | tr ',' ' ')
    # Réinitialiser IPs, fichier de map et forward-addr à chaque appel
    DOT_RESOLVED_IPS=""
    : > "$DOT_IP_MAP_FILE"
    : > "$DOT_FORWARD_ADDRS_FILE"

    for entry in $servers; do
        local proto host
        proto=$(echo "$entry" | awk -F'://' '{print $1}')
        host=$(echo "$entry"  | sed 's|^[a-z]*://||' | awk -F'[:/]' '{print $1}')
        [ -z "$host" ] && continue

        # Forcer IPv4 uniquement — unbound a do-ip6:no, les adresses IPv6
        # comme forwarders seraient silencieusement ignorées.
        local ip
        ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '/STREAM/{print $1; exit}' || true)
        [ -z "$ip" ] && ip=$(nslookup "$host" 2>/dev/null | \
            awk '/^Address: /{ if ($2 !~ /:/) {print $2; exit} }' || true)

        # --- FALLBACK : résolution IPv4 via DNS_SERVER_1/2 fournis par l'utilisateur ---
        # Au boot, dnsmasq n'est pas encore lancé donc getent/nslookup peut échouer.
        # On réessaie explicitement via les serveurs DNS configurés (DNS_SERVER_1/2).
        if [ -z "$ip" ]; then
            local dns1 dns2
            dns1="${DNS_SERVER_1:-}"
            dns2="${DNS_SERVER_2:-}"
            for _dns in $dns1 $dns2; do
                [ -z "$_dns" ] && continue
                ip=$(nslookup "$host" "$_dns" 2>/dev/null | \
                    awk '/^Address: /{ if ($2 !~ /:/) {print $2; exit} }' || true)
                if [ -n "$ip" ]; then
                    log_json WARN parse_dot_servers \
                        "resolved via fallback DNS_SERVER (IPv4)" \
                        "host=${host}" "ip=${ip}" "via=${_dns}" >&2
                    break
                fi
            done
        fi
        # -----------------------------------------------------------------------

        if [ -n "$ip" ]; then
            DOT_RESOLVED_IPS="${DOT_RESOLVED_IPS}${ip} "
            dot_ip_map_set "$host" "$ip"
            # Écriture dans le fichier (pas stdout) pour survivre hors subshell
            if [ "$proto" = "https" ]; then
                echo "        forward-addr: ${ip}@443#${host}" >> "$DOT_FORWARD_ADDRS_FILE"
            else
                echo "        forward-addr: ${ip}@853#${host}" >> "$DOT_FORWARD_ADDRS_FILE"
            fi
            log_json INFO parse_dot_servers "resolved" \
                "host=${host}" "ip=${ip}" "proto=${proto}" >&2
        else
            log_json WARN parse_dot_servers \
                "could not resolve, skipping unresolved DoT server" "host=${host}" >&2
            continue
        fi
    done
}

# ---------------------------------------------------------------------------
# configure_unbound — génère /etc/unbound/unbound.conf avec :
#   - DNSSEC (optionnel, ENABLE_DNSSEC=true)
#   - TLS cert bundle / pinning (DOT_TLS_CERT_BUNDLE)
#   - Split DNS (DNS_SPLIT="corp.local=10.0.0.53,internal.net=10.0.1.53")
#   - Support DoH via https:// prefix dans DOT_DNS_SERVERS
# ---------------------------------------------------------------------------
configure_unbound() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    if ! command -v unbound >/dev/null 2>&1; then
        log_json ERROR configure_unbound "unbound binary not found — DoT disabled"
        return 1
    fi

    # Appel direct (pas subshell) pour que DOT_RESOLVED_IPS soit peuplé dans le process parent
    parse_dot_servers

    if [ ! -s "$DOT_FORWARD_ADDRS_FILE" ]; then
        log_json ERROR configure_unbound "no valid DoT servers parsed — DoT disabled"
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
        log_json INFO configure_unbound "DNSSEC strict validation enabled"
    fi

    # TLS cert bundle — système par défaut, overridable pour pinning
    local tls_cert_bundle="/etc/ssl/certs/ca-certificates.crt"
    if [ -n "${DOT_TLS_CERT_BUNDLE:-}" ] && [ -f "${DOT_TLS_CERT_BUNDLE}" ]; then
        tls_cert_bundle="${DOT_TLS_CERT_BUNDLE}"
        log_json INFO configure_unbound "TLS cert bundle (pinning)" "bundle=${tls_cert_bundle}"
    fi

    # Split DNS : zones forwardées vers un resolver interne, sans TLS
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
            log_json INFO configure_unbound "split DNS zone" \
                "domain=${domain}" "resolver=${res_ip}:${res_port}"
        done
    fi

    mkdir -p /etc/unbound /var/lib/unbound
    chown -R unbound:unbound /var/lib/unbound 2>/dev/null || true

    cat > /etc/unbound/unbound.conf <<EOF
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

    # TLS — vérification du certificat serveur DoT (chain complète)
    tls-cert-bundle: ${tls_cert_bundle}

    # DNSSEC
    ${dnssec_mode}
EOF

    if [ "${ENABLE_DNSSEC:-false}" = "true" ] && [ -f /var/lib/unbound/root.key ]; then
        echo "    auto-trust-anchor-file: /var/lib/unbound/root.key" \
            >> /etc/unbound/unbound.conf
    fi

    # Zone principale → DoT
    cat >> /etc/unbound/unbound.conf <<EOF

forward-zone:
    name: "."
    forward-tls-upstream: yes
${forward_addrs}
EOF

    # Zones split DNS (override, sans TLS)
    [ -n "$split_zones" ] && echo "$split_zones" >> /etc/unbound/unbound.conf

    log_json INFO configure_unbound "config written" \
        "dnssec=${ENABLE_DNSSEC:-false}" \
        "tls_bundle=${tls_cert_bundle}" \
        "split_dns=${DNS_SPLIT:-none}"
}

# ---------------------------------------------------------------------------
# start_unbound
# ---------------------------------------------------------------------------
start_unbound() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    configure_unbound || return 0

    if ! unbound-checkconf /etc/unbound/unbound.conf >/tmp/unbound.test 2>&1; then
        log_json ERROR start_unbound "config test failed"
        cat /tmp/unbound.test >&2 || true
        return 1
    fi

    unbound -d -c /etc/unbound/unbound.conf &
    unbound_pid=$!

    local bound=0 i
    for i in 1 2 3 4 5 6; do
        nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1 && { bound=1; break; }
        sleep 1
    done

    if [ "$bound" -eq 1 ]; then
        METRIC_DOT_ACTIVE=1
        log_json INFO start_unbound "started — DoT active" "pid=${unbound_pid}" "port=5053"
    else
        log_json ERROR start_unbound "unbound did not bind to 127.0.0.1:5053"
        unbound_pid=""
        METRIC_DOT_ACTIVE=0
    fi
}

# _dot_refresh_loop — boucle de re-résolution périodique des IPs DoT.
# Définie ici (scope global bash) et lancée en background par start_dot_ip_refresh.
# La communication avec le superviseur parent se fait via DOT_IP_MAP_FILE.
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

            # IPv4 uniquement (cohérent avec parse_dot_servers)
            new_ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '/STREAM/{print $1; exit}' || true)
            old_ip=$(dot_ip_map_get "$host")

            if [ -z "$new_ip" ]; then
                log_json WARN dot_refresh "re-resolve failed" "host=${host}"
                continue
            fi

            if [ "$new_ip" = "$old_ip" ]; then
                log_json INFO dot_refresh "IP unchanged" "host=${host}" "ip=${new_ip}"
                continue
            fi

            log_json INFO dot_refresh "IP changed — updating iptables"                 "host=${host}" "old=${old_ip:-none}" "new=${new_ip}"

            # Ajout avant suppression = zéro interruption de connectivité DoT
            ipt_add_853 "$new_ip"
            [ -n "$old_ip" ] && ipt_del_853 "$old_ip"

            # Mise à jour du fichier partagé et du tableau associatif
            dot_ip_map_set "$host" "$new_ip"
        done
    done
}

# ===========================================================================
# Refresh dynamique des IPs DoT
# ===========================================================================
# Re-résout les hostnames DoT périodiquement (DOT_IP_REFRESH_INTERVAL, défaut 3600s).
# Si une IP change : ajoute la nouvelle règle iptables AVANT de supprimer l'ancienne
# (zéro interruption de connectivité DoT).
# Ce sous-processus survit aux cycles de restart du superviseur principal.
# ===========================================================================
start_dot_ip_refresh() {
    [ "${ENABLE_DOT:-false}" = "true" ] || return 0

    local interval="${DOT_IP_REFRESH_INTERVAL:-3600}"
    log_json INFO dot_refresh "starting periodic IP refresh" "interval=${interval}s"

    # Lance la boucle de refresh (fonction définie avant start_dot_ip_refresh,
    # visible globalement — les fonctions bash ne sont jamais vraiment "locales").
    _dot_refresh_loop &
    dot_refresh_pid=$!
    log_json INFO dot_refresh "refresh loop started" "pid=${dot_refresh_pid}"
}

# ===========================================================================
# Endpoint métriques Prometheus (127.0.0.1:9100)
# ===========================================================================
# Format text/plain compatible Prometheus (exposition via nc en boucle).
# Activé par ENABLE_METRICS=true. Loopback uniquement (iptables le garantit).
#
# Métriques :
#   vpn_up                          1=tunnel actif
#   vpn_restart_total               cycles de restart superviseur
#   dot_active                      1=DoT actif
#   process_uptime_seconds          uptime du conteneur
#   last_restart_timestamp_seconds  epoch du dernier restart
# ===========================================================================
start_metrics() {
    [ "${ENABLE_METRICS:-false}" = "true" ] || return 0

    if ! command -v nc >/dev/null 2>&1; then
        log_json WARN start_metrics "nc not available — metrics disabled"; return 0
    fi

    # Script de réponse HTTP — lu à chaque requête depuis les fichiers d'état
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

    # socat fork : chaque connexion sur :9100 exécute metrics_handler.sh
    # socat est utilisé car netcat-openbsd (Alpine) ne supporte pas -e.
    if command -v socat >/dev/null 2>&1; then
        socat TCP-LISTEN:9100,bind=127.0.0.1,reuseaddr,fork EXEC:/tmp/metrics_handler.sh &
        metrics_pid=$!
    else
        # Fallback : boucle nc sans -e (netcat-openbsd)
        # Content-Length calculé à chaque requête, réponse via pipe
        (
            while true; do
                nc -l 127.0.0.1 9100 < <(/tmp/metrics_handler.sh) 2>/dev/null || sleep 1
            done
        ) &
        metrics_pid=$!
        log_json WARN start_metrics "socat not found, using nc fallback (one request at a time)"
    fi
    log_json INFO start_metrics "metrics endpoint started" \
        "pid=${metrics_pid}" "addr=127.0.0.1:9100"
}

update_metrics() {
    printf '%s\n' "${METRIC_VPN_UP}"          > /tmp/metric_vpn_up          2>/dev/null || true
    printf '%s\n' "${METRIC_RESTART_COUNT}"   > /tmp/metric_restart_count   2>/dev/null || true
    printf '%s\n' "${METRIC_DOT_ACTIVE}"      > /tmp/metric_dot_active      2>/dev/null || true
    printf '%s\n' "${METRIC_START_TS}"        > /tmp/metric_start_ts        2>/dev/null || true
    printf '%s\n' "${METRIC_LAST_RESTART_TS}" > /tmp/metric_last_restart_ts 2>/dev/null || true
}

# ===========================================================================
# Drop capabilities post-démarrage
# ===========================================================================
# Après démarrage de tous les services, supprime les capacités Linux
# non nécessaires du superviseur. NET_ADMIN + NET_RAW sont conservées.
# Activé par DROP_CAPS=true. Nécessite libcap2 (capsh) dans l'image.
# ===========================================================================
drop_capabilities() {
    [ "${DROP_CAPS:-false}" = "true" ] || return 0

    # capsh --drop=... -- -c "cmd" modifie seulement le child process, pas le bash courant.
    # La seule façon de modifier les capabilities du processus bash courant est via
    # prctl(PR_CAPBSET_DROP, cap) appelé directement en Python3 (ctypes → libc).
    #
    # Capabilities conservées : CAP_NET_ADMIN (12) = iptables/routes
    #                            CAP_NET_RAW   (13) = ping, healthcheck
    # Toutes les autres sont supprimées du bounding set.
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
CAP_NET_RAW     = 13
CAP_NET_ADMIN   = 12  # Linux CAP_NET_ADMIN
CAP_NET_RAW     = 13  # Linux CAP_NET_RAW
KEEP = {CAP_NET_ADMIN, CAP_NET_RAW}

errors = []
for cap in range(40):  # Linux defines caps 0-39
    if cap in KEEP:
        continue
    ret = libc.prctl(PR_CAPBSET_DROP, ctypes.c_ulong(cap), 0, 0, 0)
    if ret != 0:
        err = ctypes.get_errno()
        # EINVAL (22) = cap not supported on this kernel — not an error
        if err != 22:
            errors.append(f"cap {cap}: errno {err}")

if errors:
    print(f"[drop_caps] some caps could not be dropped: {errors}", file=sys.stderr)
    sys.exit(1)
else:
    print(f"[drop_caps] bounding set reduced — kept CAP_NET_ADMIN(12) CAP_NET_RAW(13)")
PYCAPS

    local rc=$?
    if [ $rc -eq 0 ]; then
        log_json INFO drop_caps "capabilities dropped successfully"             "retained=cap_net_admin,cap_net_raw"
    else
        log_json WARN drop_caps "capability drop had errors — check stderr above"
    fi
}

# ===========================================================================
# Démarrage des services DNS
# ===========================================================================

configure_dnsmasq() {
    if [ "${ENABLE_DOT:-false}" = "true" ]; then
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
        local dns1="${DNS_SERVER_1:-94.140.14.14}"
        local dns2="${DNS_SERVER_2:-94.140.15.15}"
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
        # Split DNS en mode classique via dnsmasq (server=/domain/resolver)
        if [ -n "${DNS_SPLIT:-}" ]; then
            local entries
            entries=$(echo "${DNS_SPLIT}" | tr ',' ' ')
            for entry in $entries; do
                local domain resolver res_ip res_port
                domain="${entry%%=*}"; resolver="${entry#*=}"
                res_ip="${resolver%%:*}"; res_port="${resolver##*:}"
                [ "$res_port" = "$res_ip" ] && res_port="53"
                [ -z "$domain" ] || [ -z "$res_ip" ] && continue
                echo "server=/${domain}/${res_ip}#${res_port}" >> /etc/dnsmasq.conf
                log_json INFO configure_dnsmasq "split DNS" \
                    "domain=${domain}" "resolver=${res_ip}:${res_port}"
            done
        fi
        log_json INFO configure_dnsmasq "upstream: ${dns1}, ${dns2}"
    fi
}

start_dnsmasq() {
    configure_dnsmasq

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

    local bound=0 i
    for i in 1 2 3 4 5; do
        nc -z -w 1 127.0.0.1 53 >/dev/null 2>&1 && { bound=1; break; }
        sleep 1
    done

    if [ "$bound" -eq 1 ]; then
        log_json INFO start_dnsmasq "started" "pid=${dnsmasq_pid}" "port=53"
    else
        log_json ERROR start_dnsmasq "dnsmasq did not bind to 127.0.0.1:53"
    fi
}

# ===========================================================================
# Proxy auth (nginx Basic Auth devant Privoxy)
# ===========================================================================

configure_privoxy_auth() {
    local user="${PROXY_USER:-}" pass="${PROXY_PASS:-}"
    if [ -n "$user" ] && [ -n "$pass" ]; then
        sed -i 's|^listen-address .*|listen-address 127.0.0.1:3129|' /etc/privoxy/privoxy.config
        log_json INFO configure_privoxy_auth "auth enabled — privoxy on 127.0.0.1:3129"
    else
        sed -i 's|^listen-address .*|listen-address 0.0.0.0:3128|' /etc/privoxy/privoxy.config
        log_json INFO configure_privoxy_auth "no auth — privoxy on 0.0.0.0:3128"
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

    if ! command -v nginx >/dev/null 2>&1; then
        log_json WARN start_nginx_auth "nginx not found — falling back to no-auth"
        sed -i 's|^listen-address .*|listen-address 0.0.0.0:3128|' /etc/privoxy/privoxy.config
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
    nginx_pid=$!
    log_json INFO start_nginx_auth "started" \
        "pid=${nginx_pid}" "frontend=0.0.0.0:3128" "backend=127.0.0.1:3129"
}

start_openvpn() {
    /usr/local/bin/openvpn.sh &
    vpn_pid=$!
}

start_tailscale() {
    [ "${ENABLE_TAILSCALE:-false}" = "true" ] || return 0

    if ! command -v tailscaled >/dev/null 2>&1; then
        log_json WARN start_tailscale "tailscaled not installed — skipping"; return 0
    fi

    mkdir -p /var/lib/tailscale "$TAILSCALE_RUN_DIR" || true
    log_json INFO start_tailscale "starting tailscaled"

    tailscaled \
        --state="/var/lib/tailscale/tailscaled.state" \
        --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" \
        >/var/log/tailscaled.log 2>&1 &
    export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
    tailscaled_pid=$!

    local waited=0
    until tailscale status >/dev/null 2>&1 || [ "$waited" -ge 20 ]; do
        sleep 1; waited=$((waited + 1))
    done

    [ -z "${TAILSCALE_AUTHKEY:-}" ] && {
        log_json WARN start_tailscale "no authkey — skipping 'tailscale up'"; return 0
    }

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

    log_json INFO start_tailscale "running 'tailscale up'"
    # shellcheck disable=SC2086
    (tailscale up --accept-dns=false --authkey="$TAILSCALE_AUTHKEY" $up_flags \
        > /var/log/tailscale-up.log 2>&1) &
}

# ===========================================================================
# Monitoring OpenVPN
# ===========================================================================

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
    log_json WARN supervisor "restarting openvpn" "pid=${vpn_pid:-unknown}"
    kill_if_running "$vpn_pid"
    [ -n "$vpn_pid" ] && wait "$vpn_pid" 2>/dev/null || true
    vpn_pid=""
    start_openvpn
    local i
    for i in 1 2 3 4 5; do
        sleep 1
        if check_openvpn_routing; then
            log_json INFO supervisor "openvpn routing restored" "pid=${vpn_pid}"
            return 0
        fi
    done
    log_json ERROR supervisor "openvpn routing still not functional after restart"
    return 1
}

# ===========================================================================
# Superviseur principal
# ===========================================================================

supervise_all() {
    local attempt=0

    while true; do
        attempt=$((attempt + 1))
        METRIC_RESTART_COUNT=$((attempt - 1))
        METRIC_LAST_RESTART_TS=$(date +%s)

        # Ordre préservé — start_unbound en tête pour résoudre les IPs DoT
        # avant que start_dnsmasq ne remplace /etc/resolv.conf
        start_unbound
        start_dnsmasq
        setup_iptables
        setup_ip6tables
        start_privoxy
        start_nginx_auth
        start_openvpn
        start_tailscale

        # Services auxiliaires : démarrés une seule fois, survivent aux restarts
        if [ "$attempt" -eq 1 ]; then
            start_metrics
            start_dot_ip_refresh
        fi

        log_json INFO supervisor "waiting for OpenVPN tunnel..."
        local tun_ready=0 tun_wait=0
        while [ "$tun_wait" -lt 30 ]; do
            if check_openvpn_routing; then tun_ready=1; break; fi
            sleep 1; tun_wait=$((tun_wait + 1))
        done

        if [ "$tun_ready" -eq 1 ]; then
            setup_return_routes
            check_vpn_ip
            touch /tmp/vpn_healthy
            METRIC_VPN_UP=1
        else
            log_json WARN supervisor "tunnel not ready after 30s — skipping return routes"
            rm -f /tmp/vpn_healthy
            METRIC_VPN_UP=0
        fi

        # Drop capabilities après le 1er démarrage complet
        [ "$attempt" -eq 1 ] && drop_capabilities

        update_metrics

        log_json INFO supervisor "all services running" \
            "vpn=${vpn_pid}" \
            "dnsmasq=${dnsmasq_pid:-unknown}" \
            "privoxy=${privoxy_pid:-unknown}" \
            "nginx_auth=${nginx_pid:-disabled}" \
            "unbound=${unbound_pid:-disabled}" \
            "metrics=${metrics_pid:-disabled}" \
            "dot_refresh=${dot_refresh_pid:-disabled}"

        local fail=0 proxy_port addr stable_cycles=0
        while true; do
            sleep 10

            # OpenVPN process
            if ! kill -0 "$vpn_pid" >/dev/null 2>&1; then
                log_json ERROR supervisor "openvpn process died"; fail=1
            fi

            # OpenVPN routing
            if [ "$fail" -eq 0 ] && ! check_openvpn_routing; then
                log_json WARN supervisor "openvpn routing failure"
                rm -f /tmp/vpn_healthy; METRIC_VPN_UP=0
                if restart_openvpn; then
                    setup_return_routes; check_vpn_ip
                    touch /tmp/vpn_healthy; METRIC_VPN_UP=1
                    update_metrics; continue
                else
                    fail=1
                fi
            fi

            # Privoxy
            proxy_port=3128
            if [ -f /etc/privoxy/privoxy.config ]; then
                addr=$(awk '/^[[:space:]]*listen-address/{print $2; exit}' \
                    /etc/privoxy/privoxy.config || true)
                [ -n "$addr" ] && proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
            fi
            if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
                log_json ERROR supervisor "privoxy not listening" "port=${proxy_port}"; fail=1
            fi

            # nginx auth proxy
            if [ -n "$nginx_pid" ]; then
                if ! kill -0 "$nginx_pid" >/dev/null 2>&1; then
                    log_json ERROR supervisor "nginx auth proxy died"; fail=1
                elif ! nc -z -w 3 127.0.0.1 3128 >/dev/null 2>&1; then
                    log_json ERROR supervisor "nginx auth proxy not listening"; fail=1
                fi
            fi

            # unbound
            if [ "${ENABLE_DOT:-false}" = "true" ] && [ -n "$unbound_pid" ]; then
                if ! kill -0 "$unbound_pid" >/dev/null 2>&1; then
                    log_json ERROR supervisor "unbound process died"
                    fail=1; METRIC_DOT_ACTIVE=0
                elif ! nc -z -w 1 127.0.0.1 5053 >/dev/null 2>&1; then
                    log_json ERROR supervisor "unbound not listening on 5053"
                    fail=1; METRIC_DOT_ACTIVE=0
                fi
            fi

            # dnsmasq
            if [ -n "$dnsmasq_pid" ]; then
                if ! kill -0 "$dnsmasq_pid" >/dev/null 2>&1; then
                    log_json ERROR supervisor "dnsmasq process died"; fail=1
                elif ! nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
                    log_json ERROR supervisor "DNS resolution via 127.0.0.1 failed"; fail=1
                fi
            fi

            # Tailscale
            if [ -n "$tailscaled_pid" ] && ! kill -0 "$tailscaled_pid" >/dev/null 2>&1; then
                log_json ERROR supervisor "tailscaled process died"; fail=1
            fi

            [ "$fail" -eq 1 ] && break

            update_metrics

            stable_cycles=$((stable_cycles + 1))
            if [ "$stable_cycles" -ge 6 ] && [ "$attempt" -gt 1 ]; then
                attempt=1; stable_cycles=0
                log_json INFO supervisor "services stable — backoff counter reset"
            fi
        done

        log_json ERROR supervisor "failure detected — restarting services" \
            "attempt=${attempt}"
        rm -f /tmp/vpn_healthy
        METRIC_VPN_UP=0; METRIC_LAST_RESTART_TS=$(date +%s)
        update_metrics

        kill_if_running "$vpn_pid"
        kill_if_running "$privoxy_pid"
        kill_if_running "$nginx_pid"
        kill_if_running "$dnsmasq_pid"
        kill_if_running "$tailscaled_pid"
        kill_if_running "$unbound_pid"
        # metrics_pid et dot_refresh_pid ne sont pas tués :
        # ils survivent aux cycles de restart
        # Attendre uniquement les PIDs non-vides (wait avec PID vide = erreur sous set -eu)
        local pids_to_wait=""
        for _pid in "$vpn_pid" "$privoxy_pid" "$nginx_pid"                     "$dnsmasq_pid" "$tailscaled_pid" "$unbound_pid"; do
            [ -n "$_pid" ] && pids_to_wait="$pids_to_wait $_pid"
        done
        # shellcheck disable=SC2086
        [ -n "$pids_to_wait" ] && wait $pids_to_wait 2>/dev/null || true

        vpn_pid="" privoxy_pid="" nginx_pid="" dnsmasq_pid="" \
            tailscaled_pid="" unbound_pid=""
        DOT_RESOLVED_IPS=""
        # Réinitialiser la map des IPs DoT pour le prochain cycle de démarrage
        unset DOT_HOST_IP_MAP; declare -A DOT_HOST_IP_MAP

        local sleep_s=$((5 * attempt))
        [ "$sleep_s" -gt 60 ] && sleep_s=60
        log_json INFO supervisor "restarting in ${sleep_s}s" "attempt=${attempt}"
        sleep "$sleep_s"
    done
}

trap 'kill 0 || true; exit 0' INT TERM

supervise_all