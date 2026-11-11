#!/usr/bin/env bats
# Tests for scripts/openvpn.sh (OpenVPN launch)
#
# Regression guard for the v3.1.0 bug: the DNS_FROM_VPN block had been
# inserted in the middle of the final log_json call, leaving "config=" and
# "dir=" as orphan command fragments. The fragments are syntactically valid
# (invisible to bash -n and shellcheck), but at runtime bash tried to
# execute `config=/dev/shm/vpn.resolved.XXX` as a command path:
# `line 149: config=/dev/shm/vpn.resolved.XXXXXX: No such file or
#  directory` (exit 127), so `exec openvpn` was never reached — the tunnel
# never came up and the supervisor looped on restarts.
#
# Strategy: run a copy of scripts/openvpn.sh (source path rewritten to a
# minimal stub of lib/common.sh) with a stub openvpn binary that records
# its arguments. No root required: the stub init_environment points
# DEFAULT_VPN_DIR at the test tmpdir.

setup() {
    TEST_TMP="$(mktemp -d)"
    export TEST_TMP
    REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    export REPO_ROOT

    # Stub openvpn: record its arguments, exit 0
    mkdir -p "$TEST_TMP/bin"
    cat > "$TEST_TMP/bin/openvpn" <<'STUB'
#!/bin/bash
printf '%s\n' "$@" > "$TEST_TMP/openvpn_args"
exit 0
STUB
    chmod +x "$TEST_TMP/bin/openvpn"
    export PATH="$TEST_TMP/bin:$PATH"

    # Minimal stub of lib/common.sh: only the functions openvpn.sh uses
    cat > "$TEST_TMP/common.sh" <<'STUB'
log_json() {
    level="$1"; component="$2"; shift 2
    printf 'log_json %s %s %s\n' "$level" "$component" "$*"
}
command_exists() { command -v "$1" >/dev/null 2>&1; }
init_environment() {
    DEFAULT_VPN_DIR="${TEST_VPN_DIR}"
    VPN_PUSHED_DNS_FILE="${VPN_PUSHED_DNS_FILE:-/run/vpn-pushed-dns}"
}
STUB

    # Copy of the script under test, source path rewritten to the stub
    sed "s|^source \"/usr/local/lib/common.sh\"|source \"${TEST_TMP}/common.sh\"|" \
        "$REPO_ROOT/scripts/openvpn.sh" > "$TEST_TMP/openvpn.sh"

    # Config fixture: a remote hostname plus inline secrets
    mkdir -p "$TEST_TMP/vpn"
    cat > "$TEST_TMP/vpn/vpn.conf" <<'CONF'
client
dev tun
proto udp
remote vpn.example.net 443 udp
resolv-retry infinite
nobind
<auth-user-pass>
secret-user
secret-pass
</auth-user-pass>
CONF

    export TEST_VPN_DIR="$TEST_TMP/vpn"
    export OPENVPN_DROP_PRIVILEGES="true"
    unset VPN_REMOTE_MAP DNS_FROM_VPN VPN_PUSHED_DNS_FILE
}

teardown() {
    rm -rf "$TEST_TMP"
    rm -f /dev/shm/vpn.resolved.* 2>/dev/null || true
}

# Helper: last --config value passed to the stubbed openvpn
config_arg() {
    awk 'prev=="--config" { print; exit } { prev=$0 }' "$TEST_TMP/openvpn_args"
}

# ============================================================================
# Test Group 1: Syntax
# ============================================================================

@test "scripts/openvpn.sh passes bash -n" {
    run bash -n "$REPO_ROOT/scripts/openvpn.sh"
    [ "$status" -eq 0 ]
}

# ============================================================================
# Test Group 2: Launch (regression: the old script died at exit 127 before
# reaching exec openvpn, so every test in this group failed on main)
# ============================================================================

@test "openvpn.sh launches OpenVPN and exits 0 (no orphan fragments)" {
    run bash "$TEST_TMP/openvpn.sh"
    [ "$status" -eq 0 ]
    # No stray 'config=...: No such file or directory' fragment execution
    [[ "$output" != *"No such file or directory"* ]]
    # openvpn was actually exec'd with the original config
    [ -f "$TEST_TMP/openvpn_args" ]
    [ "$(config_arg)" = "$TEST_TMP/vpn/vpn.conf" ]
}

@test "openvpn.sh passes --cd and the privilege-drop flags by default" {
    run bash "$TEST_TMP/openvpn.sh"
    [ "$status" -eq 0 ]
    grep -qx -- "--cd" "$TEST_TMP/openvpn_args"
    grep -qx -- "$TEST_TMP/vpn" "$TEST_TMP/openvpn_args"
    grep -qx -- "--user" "$TEST_TMP/openvpn_args"
    grep -qx -- "vpn" "$TEST_TMP/openvpn_args"
    grep -qx -- "--group" "$TEST_TMP/openvpn_args"
    grep -qx -- "--persist-tun" "$TEST_TMP/openvpn_args"
    grep -qx -- "--persist-key" "$TEST_TMP/openvpn_args"
}

@test "OPENVPN_DROP_PRIVILEGES=false omits --user/--group flags" {
    export OPENVPN_DROP_PRIVILEGES="false"
    run bash "$TEST_TMP/openvpn.sh"
    [ "$status" -eq 0 ]
    ! grep -qx -- "--user" "$TEST_TMP/openvpn_args"
    ! grep -qx -- "--persist-tun" "$TEST_TMP/openvpn_args"
}

@test "openvpn.sh logs the final config and dir in the Starting OpenVPN entry" {
    run bash "$TEST_TMP/openvpn.sh"
    [ "$status" -eq 0 ]
    # The restored log_json call carries config= and dir= (they used to be
    # the orphan fragments)
    [[ "$output" == *"Starting OpenVPN"* ]]
    [[ "$output" == *"config=$TEST_TMP/vpn/vpn.conf"* ]]
    [[ "$output" == *"dir=$TEST_TMP/vpn"* ]]
}

# ============================================================================
# Test Group 3: VPN_REMOTE_MAP (firewall-resolved remotes)
# ============================================================================

@test "VPN_REMOTE_MAP switches to the resolved config with pinned IPs" {
    export VPN_REMOTE_MAP="vpn.example.net=203.0.113.1,203.0.113.2"
    run bash "$TEST_TMP/openvpn.sh"
    [ "$status" -eq 0 ]

    # openvpn runs with the resolved config, not the original one
    resolved="$(config_arg)"
    [ "$resolved" != "$TEST_TMP/vpn/vpn.conf" ]
    [ -s "$resolved" ]

    # remotes rewritten to the pinned IPs (hostname never re-resolved)
    grep -q "^remote 203.0.113.1 443 udp$" "$resolved"
    grep -q "^remote 203.0.113.2 443 udp$" "$resolved"
    ! grep -q "vpn.example.net" "$resolved"

    # inline secrets survive the rewrite, --cd stays on the original dir
    grep -q "secret-user" "$resolved"
    grep -qx -- "--cd" "$TEST_TMP/openvpn_args"
    grep -qx -- "$TEST_TMP/vpn" "$TEST_TMP/openvpn_args"
}

@test "resolved config is created with mode 600" {
    export VPN_REMOTE_MAP="vpn.example.net=203.0.113.1,203.0.113.2"
    run bash "$TEST_TMP/openvpn.sh"
    [ "$status" -eq 0 ]
    resolved="$(config_arg)"
    [ "$(stat -c '%a' "$resolved")" = "600" ]
}

# ============================================================================
# Test Group 4: DNS_FROM_VPN hooks
# ============================================================================

@test "DNS_FROM_VPN=true adds script-security and up/route-up hooks" {
    export DNS_FROM_VPN="true"
    export VPN_PUSHED_DNS_FILE="$TEST_TMP/vpn-pushed-dns"
    run bash "$TEST_TMP/openvpn.sh"
    [ "$status" -eq 0 ]
    grep -qx -- "--script-security" "$TEST_TMP/openvpn_args"
    grep -qx -- "2" "$TEST_TMP/openvpn_args"
    grep -qx -- "--up" "$TEST_TMP/openvpn_args"
    grep -qx -- "/usr/local/bin/vpn-dns-up.sh" "$TEST_TMP/openvpn_args"
    grep -qx -- "--route-up" "$TEST_TMP/openvpn_args"
    # privilege-drop flags still present alongside the hooks
    grep -qx -- "--persist-tun" "$TEST_TMP/openvpn_args"
}

@test "DNS_FROM_VPN=false omits the hooks" {
    export DNS_FROM_VPN="false"
    run bash "$TEST_TMP/openvpn.sh"
    [ "$status" -eq 0 ]
    ! grep -qx -- "--script-security" "$TEST_TMP/openvpn_args"
    ! grep -qx -- "--up" "$TEST_TMP/openvpn_args"
}
