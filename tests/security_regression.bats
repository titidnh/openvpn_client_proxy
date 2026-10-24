#!/usr/bin/env bats
# ============================================================================
# Security regression tests (docs/SECURITY_REVIEW.md : S1 S2 S3 S4 S5 S10 B1).
# Aucun root ni reseau requis : iptables/ip6tables/ip sont remplaces par des
# fonctions qui journalisent leurs arguments dans un fichier.
# ============================================================================

bats_require_minimum_version 1.5.0

setup() {
    REPO="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    export IPT_LOG="$BATS_TEST_TMPDIR/iptables.log"
    export IPT6_LOG="$BATS_TEST_TMPDIR/ip6tables.log"
    : > "$IPT_LOG"
    : > "$IPT6_LOG"

    export DNS_SERVER_1="94.140.14.14"
    export DNS_SERVER_2="94.140.15.15"
    export HEALTHCHECK_IP="9.9.9.9"
    export PROXY_PORT="3128"
    export ALLOW_EXTERNAL_PROXY_ACCESS="false"
    export ENABLE_DOT="false"
    export VPN_TYPE="openvpn"
    export VPN_CONF="$BATS_TEST_TMPDIR/vpn.conf"
    export RESOLV_CONF="$BATS_TEST_TMPDIR/resolv.conf"
    export DNSMASQ_CONF="$BATS_TEST_TMPDIR/dnsmasq.conf"
    export VPN_REMOTE_IPS="203.0.113.10|1194|udp"
    export DOT_RESOLVED_IPS="94.140.14.49 "
    echo "nameserver 127.0.0.1" > "$RESOLV_CONF"
    printf 'server=94.140.14.14\nserver=94.140.15.15\n' > "$DNSMASQ_CONF"

    # shellcheck source=/dev/null
    source "$REPO/lib/common.sh" 2>/dev/null
    # shellcheck source=/dev/null
    source "$REPO/lib/firewall.sh" 2>/dev/null
    init_environment 2>/dev/null

    # Mocks : -C (test d'existence) repond "absente" pour exercer le chemin -A.
    iptables() {
        echo "iptables $*" >> "$IPT_LOG"
        [ "${1:-}" = "-C" ] && return 1
        return 0
    }
    ip6tables() {
        echo "ip6tables $*" >> "$IPT6_LOG"
        [ "${1:-}" = "-C" ] && return 1
        return 0
    }
    ip() { return 0; }
    # IPv6 absent par defaut ; les tests S5 surchargent ces deux fonctions.
    ipv6_in_use() { return 1; }
    ip6tables_usable() { return 0; }
}

# Lignes ACCEPT 53/853 qui ne sont NI vers le loopback NI liees a une
# interface (-o ...). Doit etre vide apres le kill switch final.
leaky_dns_rules() {
    grep -E -- '--dport (53|853) .*-j ACCEPT' "$1" |
        grep -vE -- '-d 127\.|-d ::1|-o (lo|tun\+|tap\+|wg\+)' || true
}

# ---------------------------------------------------------------- S1 -------

@test "S1: setup_iptables (plain DNS) adds no interface-less port 53 ACCEPT" {
    export ENABLE_DOT=false
    setup_iptables 2>/dev/null
    [ -z "$(leaky_dns_rules "$IPT_LOG")" ]
}

@test "S1: setup_iptables (DoT) adds no interface-less port 853/53 ACCEPT" {
    export ENABLE_DOT=true
    setup_iptables 2>/dev/null
    [ -z "$(leaky_dns_rules "$IPT_LOG")" ]
}

@test "S1: setup_iptables adds no rule for HEALTHCHECK_IP" {
    setup_iptables 2>/dev/null
    run ! grep -q -- "-d ${HEALTHCHECK_IP} " "$IPT_LOG"
}

@test "S1: setup_iptables still allows the tunnel and the pinned VPN remote" {
    setup_iptables 2>/dev/null
    grep -q -- '-A OUTPUT -o tun+ -j ACCEPT' "$IPT_LOG"
    grep -q -- '-A OUTPUT -o wg+ -j ACCEPT' "$IPT_LOG"
    grep -q -- '-d 203.0.113.10 -p udp --dport 1194 -j ACCEPT' "$IPT_LOG"
}

@test "S1: ipt_add_853 is a no-op once the final kill switch is set" {
    FW_TUNNEL_ONLY=1
    ipt_add_853 "94.140.14.49"
    [ ! -s "$IPT_LOG" ]
}

@test "S1: ipt_add_853 still adds the bootstrap rule before the kill switch" {
    FW_TUNNEL_ONLY=0
    ipt_add_853 "94.140.14.49"
    grep -q -- '-A OUTPUT -p tcp -d 94.140.14.49 --dport 853 -j ACCEPT' "$IPT_LOG"
}

@test "S1: firewall_open_bootstrap_dns re-opens DNS and leaves tunnel-only mode" {
    FW_TUNNEL_ONLY=1
    firewall_open_bootstrap_dns 2>/dev/null
    [ "$FW_TUNNEL_ONLY" = "0" ]
    grep -q -- '-A OUTPUT -p udp -d 94.140.14.14 --dport 53 -j ACCEPT' "$IPT_LOG"
    grep -q -- '-A OUTPUT -p tcp -d 94.140.15.15 --dport 53 -j ACCEPT' "$IPT_LOG"
}

@test "S1: the supervisor re-opens bootstrap DNS on restart cycles" {
    grep -q 'firewall_open_bootstrap_dns' "$REPO/lib/supervisor.sh"
}

# ---------------------------------------------------------------- S2 -------

@test "S2: external access without credentials is refused" {
    export ALLOW_EXTERNAL_PROXY_ACCESS=true PROXY_USER="" PROXY_PASS=""
    export ALLOW_UNAUTHENTICATED_EXTERNAL_PROXY=false
    run check_proxy_exposure
    [ "$status" -eq 1 ]
}

@test "S2: external access with credentials is accepted" {
    export ALLOW_EXTERNAL_PROXY_ACCESS=true PROXY_USER="alice" PROXY_PASS="s3cret"
    run check_proxy_exposure
    [ "$status" -eq 0 ]
}

@test "S2: explicit override allows an open proxy" {
    export ALLOW_EXTERNAL_PROXY_ACCESS=true PROXY_USER="" PROXY_PASS=""
    export ALLOW_UNAUTHENTICATED_EXTERNAL_PROXY=true
    run check_proxy_exposure
    [ "$status" -eq 0 ]
}

@test "S2: default (no external access) is accepted" {
    export ALLOW_EXTERNAL_PROXY_ACCESS=false PROXY_USER="" PROXY_PASS=""
    run check_proxy_exposure
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------- S3 -------

@test "S3: proxy egress filter blocks tailnet and private ranges for the proxy user" {
    export PROXY_RUN_USER=vpn PROXY_ALLOW_PRIVATE_NETWORKS=false
    setup_iptables 2>/dev/null
    grep -q -- '-I OUTPUT 1 -m owner --uid-owner vpn -m conntrack --ctstate NEW -j PROXY_EGRESS' "$IPT_LOG"
    grep -q -- '-A PROXY_EGRESS -d 100.64.0.0/10 -j REJECT' "$IPT_LOG"
    grep -q -- '-A PROXY_EGRESS -d 172.16.0.0/12 -j REJECT' "$IPT_LOG"
    grep -q -- '-A PROXY_EGRESS -d 127.0.0.1 -p udp --dport 53 -j RETURN' "$IPT_LOG"
}

@test "S3: PROXY_ALLOW_PRIVATE_NETWORKS=true disables the egress filter" {
    export PROXY_ALLOW_PRIVATE_NETWORKS=true
    setup_iptables 2>/dev/null
    run ! grep -q 'PROXY_EGRESS' "$IPT_LOG"
}

@test "S3: privoxy is started as an unprivileged user" {
    grep -q -- '--user "${PROXY_RUN_USER:-vpn}"' "$REPO/scripts/start.sh"
}

# ---------------------------------------------------------------- S4 -------

@test "S4: the fake python prctl capability drop is gone" {
    run ! grep -q 'PR_CAPBSET_DROP = 24' "$REPO/scripts/start.sh"
    run ! grep -qE '^[[:space:]]+python3 \\$' "$REPO/Dockerfile"
}

# ---------------------------------------------------------------- S5 -------

@test "S5: early lockdown fails closed when IPv6 is active but ip6tables is unusable" {
    ipv6_in_use() { return 0; }
    ip6tables_usable() { return 1; }
    resolve_vpn_ips() { echo "203.0.113.10"; }
    run firewall_early_lockdown
    [ "$status" -eq 1 ]
}

@test "S5: setup_ip6tables fails closed when IPv6 is active but ip6tables is unusable" {
    ipv6_in_use() { return 0; }
    ip6tables_usable() { return 1; }
    run setup_ip6tables
    [ "$status" -eq 1 ]
}

@test "S5: the supervisor treats a setup_ip6tables failure as fatal" {
    grep -q 'if ! setup_ip6tables; then' "$REPO/lib/supervisor.sh"
}

# ---------------------------------------------------------------- S10 ------

@test "S10: validate_environment rejects an arithmetic-injection PROXY_PORT" {
    export PROXY_PORT='x[$(touch /tmp/pwned)]'
    run validate_environment
    [ "$status" -eq 1 ]
}

@test "S10: validate_environment rejects invalid DNS IPs" {
    export DNS_SERVER_1="999.1.1.1"
    run validate_environment
    [ "$status" -eq 1 ]
    export DNS_SERVER_1="abc"
    run validate_environment
    [ "$status" -eq 1 ]
}

@test "S10: validate_environment rejects non-numeric intervals" {
    export VPN_REMOTE_REFRESH_INTERVAL='1;id'
    run validate_environment
    [ "$status" -eq 1 ]
}

@test "S10: validate_environment accepts the default configuration" {
    run validate_environment
    [ "$status" -eq 0 ]
}

@test "S10: validate_environment accepts a valid IPv6 DNS server" {
    export DNS_SERVER_2="2a10:50c0::ad1:ff"
    run validate_environment
    [ "$status" -eq 0 ]
}

@test "S10: the supervisor no longer ignores validation failures" {
    run ! grep -q 'validate_environment || true' "$REPO/lib/supervisor.sh"
}

@test "S10: DNS_SERVER_1 is never interpolated into bash -c" {
    run ! grep -q 'bash -c "echo > /dev/tcp/${DNS_SERVER_1}' "$REPO/lib/dns_runtime.sh"
}

# ---------------------------------------------------------------- B1 -------

@test "B1: WireGuard endpoint host route uses 'ip route replace' (restart-safe)" {
    run ! grep -qE 'ip (-6 )?route add "\$endpoint_ip"' "$REPO/lib/wireguard.sh"
    grep -qE 'ip route replace "\$endpoint_ip"' "$REPO/lib/wireguard.sh"
}

@test "S10: validate_environment rejects an invalid DNS_BYPASS_VPN" {
    export DNS_BYPASS_VPN="maybe"
    run validate_environment
    [ "$status" -eq 1 ]
    export DNS_BYPASS_VPN="true"
    run validate_environment
    [ "$status" -eq 0 ]
}

# ---------------------------------------------------------------------------
# DNS Blocklist : le fragment compile doit etre charge quel que soit le mode
# (DoT on/off x DNSSEC on/off). Regression : le blocage ne doit jamais
# dependre de ces options.
# ---------------------------------------------------------------------------

@test "blocklist fragment is loaded by dnsmasq in classic mode (DoT off, DNSSEC irrelevant)" {
    source "$REPO/lib/dns_runtime.sh"

    ENABLE_DOT="false"
    ENABLE_DNS_BLOCKLIST="true"
    DNS_BLOCKLIST_COMPILED_DNSMASQ="$BATS_TEST_TMPDIR/blocklist_dnsmasq.conf"
    printf 'address=/ads.example.com/0.0.0.0\n' > "$DNS_BLOCKLIST_COMPILED_DNSMASQ"

    local sec
    for sec in false true; do
        ENABLE_DNSSEC="$sec"
        configure_dnsmasq
        grep -q "conf-file=${DNS_BLOCKLIST_COMPILED_DNSMASQ}" "$DNSMASQ_CONF"
    done
}


@test "blocklist fragment is included by unbound in DoT mode with and without DNSSEC" {
    source "$REPO/lib/dns_runtime.sh"
    source "$REPO/lib/dot.sh"

    ENABLE_DOT="true"
    ENABLE_DNS_BLOCKLIST="true"
    DNS_BLOCKLIST_COMPILED_UNBOUND="$BATS_TEST_TMPDIR/blocklist_unbound.conf"
    DOT_FORWARD_ADDRS_FILE="$BATS_TEST_TMPDIR/dot_forward_addrs"
    DOT_IP_MAP_FILE="$BATS_TEST_TMPDIR/dot_ip_map"
    UNBOUND_CONF="$BATS_TEST_TMPDIR/unbound.conf"
    printf 'local-zone: "ads.example." always_nxdomain\n' > "$DNS_BLOCKLIST_COMPILED_UNBOUND"
    printf '        forward-addr: 94.140.14.49@853#dns.adguard-dns.com\n' > "$DOT_FORWARD_ADDRS_FILE"

    # Pas de reseau : la resolution des hotes DoT est neutralisee.
    parse_dot_servers() { return 0; }
    # unbound est "present", unbound-checkconf "absent" (chemin ecriture seule).
    command_exists() { [ "$1" = "unbound" ] && return 0; return 1; }
    # Side effects systeme neutralises : le test ne doit pas exiger le root.
    mkdir() { return 0; }
    chown() { return 0; }
    unbound-anchor() { return 0; }

    local sec
    for sec in false true; do
        ENABLE_DNSSEC="$sec"
        : > "$UNBOUND_CONF"
        configure_unbound
        grep -q "include: \"${DNS_BLOCKLIST_COMPILED_UNBOUND}\"" "$UNBOUND_CONF"
    done
}

# ------------------------------------------------------------- Metrics ------
# L'endpoint Prometheus doit rester injoignable du reseau tant que
# METRICS_BIND n'est pas explicitement ouvert (opt-in) - cf. README
# "Prometheus Metrics". METRICS_PORT doit etre honore partout (listener,
# regles OUTPUT loopback, regle INPUT opt-in).

@test "metrics INPUT stays closed with the default loopback bind" {
    export ENABLE_METRICS="true"
    export METRICS_BIND="127.0.0.1"
    setup_iptables 2>/dev/null
    run ! grep -q -- '-A INPUT -p tcp --dport 9100 -j ACCEPT' "$IPT_LOG"
}

@test "metrics INPUT opens only with explicit METRICS_BIND and honors METRICS_PORT" {
    export ENABLE_METRICS="true"
    export METRICS_BIND="0.0.0.0"
    export METRICS_PORT="9200"
    setup_iptables 2>/dev/null
    # Regle INPUT ouverte uniquement pour le port configure
    grep -q -- '-A INPUT -p tcp --dport 9200 -j ACCEPT' "$IPT_LOG"
    run ! grep -q -- '--dport 9100 ' "$IPT_LOG"
    # La regle OUTPUT loopback suit aussi METRICS_PORT
    grep -q -- '-A OUTPUT -p tcp -d 127.0.0.1 --dport 9200 -j ACCEPT' "$IPT_LOG"
}

# Regression : le handler doit consommer la requete HTTP avant de repondre.
# Un handler qui repond sans lire laisse socat fermer le socket avec des
# donnees non lues -> RST -> "read(...): Connection reset by peer" en boucle
# dans docker logs a chaque scrape.
@test "metrics handler drains the HTTP request before answering (no socat RST noise)" {
    # Reconstruit le handler genere par scripts/start.sh (heredoc HANDLER)
    awk "/^ *cat <<'HANDLER'\$/{flag=1;next} /^HANDLER\$/{flag=0} flag" \
        "$REPO/scripts/start.sh" > "$BATS_TEST_TMPDIR/handler.body"
    [ -s "$BATS_TEST_TMPDIR/handler.body" ]

    mkdir -p "$BATS_TEST_TMPDIR/metrics"
    echo 1 > "$BATS_TEST_TMPDIR/metrics/metric_vpn_up"
    echo 2 > "$BATS_TEST_TMPDIR/metrics/metric_restart_count"
    echo 0 > "$BATS_TEST_TMPDIR/metrics/metric_dot_active"
    echo 1700000000 > "$BATS_TEST_TMPDIR/metrics/metric_start_ts"
    echo 0 > "$BATS_TEST_TMPDIR/metrics/metric_last_restart_ts"

    {
        printf '#!/bin/sh\nMETRICS_DIR=%s\n' "$BATS_TEST_TMPDIR/metrics"
        cat "$BATS_TEST_TMPDIR/handler.body"
    } > "$BATS_TEST_TMPDIR/handler.sh"

    # Requete HTTP complete : les en-tetes doivent etre consommes puis la
    # reponse emise (HTTP 200 + payload Prometheus).
    printf 'GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: test\r\n\r\n' \
        > "$BATS_TEST_TMPDIR/req"

    run sh "$BATS_TEST_TMPDIR/handler.sh" < "$BATS_TEST_TMPDIR/req"
    [ "$status" -eq 0 ]
    grep -q 'HTTP/1.1 200 OK' <<< "$output"
    grep -qx 'vpn_up 1' <<< "$output"
    grep -qx 'vpn_restart_total 2' <<< "$output"
    grep -q 'Content-Length: ' <<< "$output"

    # Client muet (EOF immediat) : reponse quand meme, pas de blocage.
    run sh "$BATS_TEST_TMPDIR/handler.sh" < /dev/null
    [ "$status" -eq 0 ]
    grep -q 'HTTP/1.1 200 OK' <<< "$output"
}
