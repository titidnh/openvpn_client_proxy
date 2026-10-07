#!/usr/bin/env bats
# Tests for lib/camouflage.sh - Mode Camouflage (obfuscation TLS via stunnel)

setup() {
    source "$(dirname "$BATS_TEST_FILENAME")/../lib/common.sh"
    source "$(dirname "$BATS_TEST_FILENAME")/../lib/camouflage.sh"

    export ENABLE_CAMOUFLAGE="true"
    export CAMOUFLAGE_PORT="443"
    export CAMOUFLAGE_LOCAL_PORT="1194"
    export CAMOUFLAGE_TLS_VERIFY="true"
    export VPN_REMOTE_IPS="1.2.3.4|443|tcp 5.6.7.8|443|tcp"
    export VPN_REMOTE_MAP="vpn.example.com=1.2.3.4,5.6.7.8"
    export CAMOUFLAGE_STUNNEL_CONF="$(mktemp)"
    export CAMOUFLAGE_STUNNEL_PID="$(mktemp -d)/stunnel.pid"
}

teardown() {
    rm -f "${CAMOUFLAGE_STUNNEL_CONF:-}"
}

@test "camouflage module has all required functions" {
    declare -f camouflage_enabled >/dev/null || return 1
    declare -f generate_stunnel_conf >/dev/null || return 1
    declare -f build_camouflaged_openvpn_conf >/dev/null || return 1
    declare -f start_stunnel >/dev/null || return 1
    declare -f stop_stunnel >/dev/null || return 1
}

@test "camouflage_enabled reflects ENABLE_CAMOUFLAGE" {
    camouflage_enabled
    ENABLE_CAMOUFLAGE="false" run camouflage_enabled
    [ "$status" -ne 0 ]
}

@test "generate_stunnel_conf writes a TLS client config for port 443" {
    generate_stunnel_conf "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^client = yes$' "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^accept = 127.0.0.1:1194$' "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^connect = 1.2.3.4:443$' "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^connect = 5.6.7.8:443$' "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^sni = vpn.example.com$' "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^verifyChain = yes$' "$CAMOUFLAGE_STUNNEL_CONF"
}

@test "generate_stunnel_conf fails with no VPN endpoints" {
    VPN_REMOTE_IPS=""
    run generate_stunnel_conf "$CAMOUFLAGE_STUNNEL_CONF"
    [ "$status" -ne 0 ]
}

@test "generate_stunnel_conf disables verification when CAMOUFLAGE_TLS_VERIFY=false" {
    CAMOUFLAGE_TLS_VERIFY="false"
    generate_stunnel_conf "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^verify = 0$' "$CAMOUFLAGE_STUNNEL_CONF"
    run grep -q 'verifyChain' "$CAMOUFLAGE_STUNNEL_CONF"
    [ "$status" -ne 0 ]
}

@test "build_camouflaged_openvpn_conf strips remote/proto and connects to stunnel" {
    src="$(mktemp)"
    cat > "$src" <<'CONF'
client
dev tun
proto udp
remote vpn.example.com 1194
rport 1194
<connection>
remote vpn.example.com 443 tcp
</connection>
remote-cert-tls server
auth-user-pass vpn.auth
CONF
    out="$(mktemp)"
    build_camouflaged_openvpn_conf "$src" "$out"
    grep -q '^proto tcp-client$' "$out"
    grep -q '^remote 127.0.0.1 1194$' "$out"
    run grep -q 'vpn.example.com 1194' "$out"
    [ "$status" -ne 0 ]
    run grep -q '^<connection>$' "$out"
    [ "$status" -ne 0 ]
    run grep -q '^rport' "$out"
    [ "$status" -ne 0 ]
    grep -q '^route 1.2.3.4 255.255.255.255 net_gateway$' "$out"
    grep -q '^route 5.6.7.8 255.255.255.255 net_gateway$' "$out"
    grep -q '^auth-user-pass vpn.auth$' "$out"
    rm -f "$src" "$out"
}

@test "build_camouflaged_openvpn_conf fails on missing source" {
    out="$(mktemp)"
    run build_camouflaged_openvpn_conf "/nonexistent/vpn.conf" "$out"
    [ "$status" -ne 0 ]
    rm -f "$out"
}

@test "stop_stunnel is a no-op without a pid file" {
    rm -f "$CAMOUFLAGE_STUNNEL_PID"
    run stop_stunnel
    [ "$status" -eq 0 ]
}

@test "generate_stunnel_conf ignores non-camouflage endpoints (fallback pins)" {
    VPN_REMOTE_IPS="1.2.3.4|443|tcp 1.2.3.4|1194|udp"
    generate_stunnel_conf "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^connect = 1.2.3.4:443$' "$CAMOUFLAGE_STUNNEL_CONF"
    run grep -q '^connect = .*:1194$' "$CAMOUFLAGE_STUNNEL_CONF"
    [ "$status" -ne 0 ]
}

@test "generate_stunnel_conf always sets CAfile when verifying (no host)" {
    VPN_REMOTE_MAP=""
    generate_stunnel_conf "$CAMOUFLAGE_STUNNEL_CONF"
    grep -q '^CAfile = ' "$CAMOUFLAGE_STUNNEL_CONF"
    run grep -q '^verify = 2$' "$CAMOUFLAGE_STUNNEL_CONF"
    [ "$status" -ne 0 ]
}

@test "generate_stunnel_conf skips checkHost with several hostnames" {
    VPN_REMOTE_MAP="a.example.com=1.2.3.4 b.example.com=5.6.7.8"
    generate_stunnel_conf "$CAMOUFLAGE_STUNNEL_CONF"
    run grep -q '^checkHost' "$CAMOUFLAGE_STUNNEL_CONF"
    [ "$status" -ne 0 ]
    grep -q '^verifyChain = yes$' "$CAMOUFLAGE_STUNNEL_CONF"
}

@test "build_camouflaged_openvpn_conf strips UDP-only options" {
    src="$(mktemp)"
    printf 'client\nproto udp\nremote h 1194\nfast-io\nfragment 1300\nexplicit-exit-notify 2\nverb 3\n' > "$src"
    out="$(mktemp)"
    build_camouflaged_openvpn_conf "$src" "$out"
    run grep -Eq '^(fast-io|fragment|explicit-exit-notify)' "$out"
    [ "$status" -ne 0 ]
    grep -q '^verb 3$' "$out"
    rm -f "$src" "$out"
}

@test "camouflage_select_endpoints fails when no server speaks TLS" {
    camouflage_probe_tls() { return 1; }
    run camouflage_select_endpoints
    [ "$status" -ne 0 ]
}

@test "camouflage_select_endpoints keeps only TLS-capable endpoints" {
    camouflage_probe_tls() { [ "$1" = "5.6.7.8" ]; }
    camouflage_select_endpoints
    [ "$CAMOUFLAGE_ENDPOINTS" = "5.6.7.8|443|tcp" ]
}
