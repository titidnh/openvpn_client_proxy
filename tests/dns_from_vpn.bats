#!/usr/bin/env bats
# Tests for DNS_FROM_VPN feature
#
# Covers:
# 1. Defaults and validation (common.sh: init_environment, validate_environment)
# 2. apply_vpn_pushed_dns (lib/dns_runtime.sh) - switching, idempotence,
#    fallback and hostile input handling
# 3. OpenVPN hook scripts/vpn-dns-up.sh (foreign_option parsing)
# 4. WireGuard DNS line extraction (wg_get_value)

setup() {
    export TEST_TMP=$(mktemp -d)
    export VPN_PUSHED_DNS_FILE="$TEST_TMP/vpn-pushed-dns"
    export DNS_FROM_VPN="false"
    export DNS_SERVER_1="8.8.8.8"
    export DNS_SERVER_2="8.8.4.4"
    export ENABLE_DOT="false"
    export DNS_BYPASS_VPN="false"

    mkdir -p "$TEST_TMP"

    # Source required libraries
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/common.sh
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/dns_runtime.sh
}

teardown() {
    rm -rf "$TEST_TMP"
}

# ============================================================================
# Test Group 1: Defaults (init_environment)
# ============================================================================

@test "init_environment defaults DNS_FROM_VPN to false" {
    unset DNS_FROM_VPN

    init_environment

    [ "$DNS_FROM_VPN" = "false" ]
}

@test "init_environment keeps explicit DNS_FROM_VPN=true" {
    export DNS_FROM_VPN="true"

    init_environment

    [ "$DNS_FROM_VPN" = "true" ]
}

@test "init_environment defaults VPN_PUSHED_DNS_FILE to /run/vpn-pushed-dns" {
    unset VPN_PUSHED_DNS_FILE

    init_environment

    [ "$VPN_PUSHED_DNS_FILE" = "/run/vpn-pushed-dns" ]
}

# ============================================================================
# Test Group 2: Validation (validate_environment)
# ============================================================================

@test "validate_environment accepts DNS_FROM_VPN=true with ENABLE_DOT=false" {
    export DNS_FROM_VPN="true"
    export ENABLE_DOT="false"

    run validate_environment
    [ "$status" -eq 0 ]
}

@test "validate_environment rejects DNS_FROM_VPN=true combined with ENABLE_DOT=true" {
    export DNS_FROM_VPN="true"
    export ENABLE_DOT="true"

    run validate_environment
    [ "$status" -ne 0 ]
}

@test "validate_environment rejects invalid DNS_FROM_VPN value" {
    export DNS_FROM_VPN="maybe"

    run validate_environment
    [ "$status" -ne 0 ]
}

# ============================================================================
# Test Group 3: apply_vpn_pushed_dns - guards
# ============================================================================

@test "apply_vpn_pushed_dns is idempotent-safe no-op when DNS_FROM_VPN=false" {
    export DNS_FROM_VPN="false"
    printf '1.2.3.4\n' > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns

    [ "$reconfig_calls" -eq 0 ]
    [ "$DNS_SERVER_1" = "8.8.8.8" ]
}

@test "apply_vpn_pushed_dns is a no-op when pushed DNS file is missing" {
    export DNS_FROM_VPN="true"
    rm -f "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns

    [ "$reconfig_calls" -eq 0 ]
    [ "$DNS_SERVER_1" = "8.8.8.8" ]
}

@test "apply_vpn_pushed_dns is a no-op when pushed DNS file is empty" {
    export DNS_FROM_VPN="true"
    : > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns

    [ "$reconfig_calls" -eq 0 ]
    [ "$DNS_SERVER_1" = "8.8.8.8" ]
}

# ============================================================================
# Test Group 4: apply_vpn_pushed_dns - upstream switching
# ============================================================================

@test "apply_vpn_pushed_dns switches DNS_SERVER_1/2 to pushed servers" {
    export DNS_FROM_VPN="true"
    printf '162.252.172.57\n149.154.159.92\n' > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns

    [ "$DNS_SERVER_1" = "162.252.172.57" ]
    [ "$DNS_SERVER_2" = "149.154.159.92" ]
    [ "$reconfig_calls" -eq 1 ]
}

@test "apply_vpn_pushed_dns is idempotent - no reconfig on second call" {
    export DNS_FROM_VPN="true"
    printf '162.252.172.57\n149.154.159.92\n' > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns
    apply_vpn_pushed_dns

    [ "$reconfig_calls" -eq 1 ]
}

@test "apply_vpn_pushed_dns with a single pushed server keeps DNS_SERVER_2 as fallback" {
    export DNS_FROM_VPN="true"
    printf '162.252.172.57\n' > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns

    [ "$DNS_SERVER_1" = "162.252.172.57" ]
    [ "$DNS_SERVER_2" = "8.8.4.4" ]
    [ "$reconfig_calls" -eq 1 ]
}

@test "apply_vpn_pushed_dns accepts IPv6 pushed servers" {
    export DNS_FROM_VPN="true"
    printf '2001:4860:4860::8888\n' > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns

    [ "$DNS_SERVER_1" = "2001:4860:4860::8888" ]
    [ "$reconfig_calls" -eq 1 ]
}

# ============================================================================
# Test Group 5: apply_vpn_pushed_dns - hostile input
# ============================================================================

@test "apply_vpn_pushed_dns ignores garbage lines and keeps valid ones" {
    export DNS_FROM_VPN="true"
    printf 'not-an-ip\n162.252.172.57\n0.0.0.0.0\n' > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns

    [ "$DNS_SERVER_1" = "162.252.172.57" ]
    [ "$reconfig_calls" -eq 1 ]
}

@test "apply_vpn_pushed_dns keeps current upstreams when file has no usable server" {
    export DNS_FROM_VPN="true"
    printf 'not-a-server\n1.2.3\n' > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns
    [ "$?" -eq 1 ]
    [ "$reconfig_calls" -eq 0 ]
}

@test "apply_vpn_pushed_dns uses only the first two usable servers" {
    export DNS_FROM_VPN="true"
    printf '1.1.1.1\n2.2.2.2\n3.3.3.3\n' > "$VPN_PUSHED_DNS_FILE"

    local reconfig_calls=0
    reconfigure_dnsmasq_to_unbound() { reconfig_calls=$((reconfig_calls + 1)); }

    apply_vpn_pushed_dns

    [ "$DNS_SERVER_1" = "1.1.1.1" ]
    [ "$DNS_SERVER_2" = "2.2.2.2" ]
    [ "$reconfig_calls" -eq 1 ]
}

# ============================================================================
# Test Group 6: OpenVPN hook - scripts/vpn-dns-up.sh
# ============================================================================

@test "vpn-dns-up.sh extracts dhcp-option DNS from foreign_option_*" {
    run env \
        foreign_option_1="dhcp-option DNS 162.252.172.57" \
        foreign_option_2="dhcp-option DNS 149.154.159.92" \
        foreign_option_3="dhcp-option DOMAIN example.com" \
        VPN_PUSHED_DNS_FILE="$VPN_PUSHED_DNS_FILE" \
        bash "$(dirname "$BATS_TEST_FILENAME")"/../scripts/vpn-dns-up.sh
    [ "$status" -eq 0 ]

    [ "$(wc -l < "$VPN_PUSHED_DNS_FILE")" -eq 2 ]
    grep -qx "162.252.172.57" "$VPN_PUSHED_DNS_FILE"
    grep -qx "149.154.159.92" "$VPN_PUSHED_DNS_FILE"
}

@test "vpn-dns-up.sh rejects malformed dhcp-option values" {
    run env \
        foreign_option_1="dhcp-option DNS not-an-ip" \
        foreign_option_2="dhcp-option DNS 1.2.3.4.5" \
        VPN_PUSHED_DNS_FILE="$VPN_PUSHED_DNS_FILE" \
        bash "$(dirname "$BATS_TEST_FILENAME")"/../scripts/vpn-dns-up.sh
    [ "$status" -eq 0 ]

    # Nothing usable pushed: file must not be written
    [ ! -f "$VPN_PUSHED_DNS_FILE" ] || [ ! -s "$VPN_PUSHED_DNS_FILE" ]
}

@test "vpn-dns-up.sh deduplicates pushed servers" {
    run env \
        foreign_option_1="dhcp-option DNS 162.252.172.57" \
        foreign_option_2="dhcp-option DNS 162.252.172.57" \
        VPN_PUSHED_DNS_FILE="$VPN_PUSHED_DNS_FILE" \
        bash "$(dirname "$BATS_TEST_FILENAME")"/../scripts/vpn-dns-up.sh
    [ "$status" -eq 0 ]

    [ "$(wc -l < "$VPN_PUSHED_DNS_FILE")" -eq 1 ]
    grep -qx "162.252.172.57" "$VPN_PUSHED_DNS_FILE"
}

@test "vpn-dns-up.sh accepts IPv6 pushed servers" {
    run env \
        foreign_option_1="dhcp-option DNS 2001:4860:4860::8888" \
        VPN_PUSHED_DNS_FILE="$VPN_PUSHED_DNS_FILE" \
        bash "$(dirname "$BATS_TEST_FILENAME")"/../scripts/vpn-dns-up.sh
    [ "$status" -eq 0 ]

    grep -qx "2001:4860:4860::8888" "$VPN_PUSHED_DNS_FILE"
}

@test "vpn-dns-up.sh without foreign_option writes nothing and exits 0" {
    rm -f "$VPN_PUSHED_DNS_FILE"

    run env \
        VPN_PUSHED_DNS_FILE="$VPN_PUSHED_DNS_FILE" \
        bash "$(dirname "$BATS_TEST_FILENAME")"/../scripts/vpn-dns-up.sh
    [ "$status" -eq 0 ]

    [ ! -f "$VPN_PUSHED_DNS_FILE" ] || [ ! -s "$VPN_PUSHED_DNS_FILE" ]
}

@test "vpn-dns-up.sh leaves no temp file behind" {
    run env \
        foreign_option_1="dhcp-option DNS 162.252.172.57" \
        VPN_PUSHED_DNS_FILE="$VPN_PUSHED_DNS_FILE" \
        bash "$(dirname "$BATS_TEST_FILENAME")"/../scripts/vpn-dns-up.sh
    [ "$status" -eq 0 ]

    # No leftover tmp files in the target directory
    [ -z "$(find "$TEST_TMP" -name '*.tmp.*' -print -quit)" ]
}

# ============================================================================
# Test Group 7: WireGuard - DNS line extraction (wg_get_value)
# ============================================================================

@test "wg_get_value extracts single DNS entry from wg0.conf" {
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/wireguard.sh
    cat > "$TEST_TMP/wg0.conf" <<'EOF'
[Interface]
PrivateKey = redacted
Address = 10.14.0.2/16
DNS = 162.252.172.57

[Peer]
PublicKey = redacted
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = example.com:51820
EOF

    local dns_value
    dns_value=$(wg_get_value "$TEST_TMP/wg0.conf" "DNS")

    [ "$dns_value" = "162.252.172.57" ]
}

@test "wg_get_value extracts comma-separated DNS entries from wg0.conf" {
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/wireguard.sh
    cat > "$TEST_TMP/wg0.conf" <<'EOF'
[Interface]
PrivateKey = redacted
Address = 10.14.0.2/16
DNS = 162.252.172.57, 149.154.159.92

[Peer]
PublicKey = redacted
Endpoint = example.com:51820
EOF

    local dns_value
    dns_value=$(wg_get_value "$TEST_TMP/wg0.conf" "DNS")

    [ "$dns_value" = "162.252.172.57, 149.154.159.92" ]
}

@test "wg_get_value returns empty when wg0.conf has no DNS line" {
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/wireguard.sh
    cat > "$TEST_TMP/wg0.conf" <<'EOF'
[Interface]
PrivateKey = redacted
Address = 10.14.0.2/16

[Peer]
PublicKey = redacted
Endpoint = example.com:51820
EOF

    local dns_value
    dns_value=$(wg_get_value "$TEST_TMP/wg0.conf" "DNS")

    [ -z "$dns_value" ]
}
