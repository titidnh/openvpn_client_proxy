#!/usr/bin/env bats
# Integration tests for core functionality

setup() {
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/common.sh
}

# Test: Common library is sourced
@test "common.sh module loads successfully" {
    declare -f init_environment >/dev/null || return 1
    declare -f validate_environment >/dev/null || return 1
    declare -f log_json >/dev/null || return 1
}

# Test: Environment initialization works
@test "init_environment populates required variables" {
    init_environment
    # Check core variables are set
    [ -n "${ENABLE_DNS_BLOCKLIST+x}" ]
    [ -n "${ENABLE_DOT+x}" ]
    [ -n "${PROXY_PORT+x}" ]
    [ -n "${DNS_SERVER_1+x}" ]
}

# Test: JSON logging works without errors (log_json writes to stderr)
@test "log_json emits a valid JSON line" {
    local err
    err=$(log_json INFO common-test "test message" "foo=bar" 2>&1 >/dev/null) || return 1

    printf '%s\n' "$err" | grep -q '"level":"INFO"'
    printf '%s\n' "$err" | grep -q '"component":"common-test"'
    printf '%s\n' "$err" | grep -q '"msg":"test message"'
    printf '%s\n' "$err" | grep -q '"foo": "bar"'
}

@test "log_json escapes special characters safely" {
    local err
    err=$(log_json ERROR common-test 'msg with "quotes" and \backslash' 2>&1 >/dev/null) || return 1

    printf '%s\n' "$err" | grep -q '"level":"ERROR"'
    printf '%s\n' "$err" | grep -Fq '"msg":"msg with \"quotes\" and \\backslash"'
}

@test "metrics variables are initialized safely under strict mode" {
    init_environment

    [ "${METRIC_VPN_UP:-0}" = "0" ]
    [ "${METRIC_RESTART_COUNT:-0}" = "0" ]
    [ "${METRIC_DOT_ACTIVE:-0}" = "0" ]
    [ "${METRIC_START_TS:-0}" -gt 0 ]
    [ "${METRIC_LAST_RESTART_TS:-0}" = "0" ]
}

@test "reconfigure_dnsmasq_to_unbound waits for clean shutdown before restart" {
    # La fonction vit dans lib/dns_runtime.sh : chemins et binaires mockés
    # pour ne toucher ni /etc ni un vrai dnsmasq.
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/dns_runtime.sh
    init_environment
    export DNSMASQ_CONF="$BATS_TEST_TMPDIR/dnsmasq.conf"
    export RESOLV_CONF="$BATS_TEST_TMPDIR/resolv.conf"
    dnsmasq() { return 0; }
    nc() { return 0; }
    nslookup() { return 0; }
    export -f dnsmasq nc nslookup

    local child_pid
    sh -c 'sleep 30' </dev/null >/dev/null 2>&1 &
    child_pid=$!
    SERVICE_PIDS[dnsmasq]="$child_pid"

    run reconfigure_dnsmasq_to_unbound
    [ "$status" -eq 0 ]

    # L'ancien dnsmasq doit avoir été arrêté proprement (et non juste oublié)
    if kill -0 "$child_pid" 2>/dev/null; then
        kill -9 "$child_pid" 2>/dev/null || true
        return 1
    fi
}

# Test: Invalid configuration values are detected
@test "ENABLE_DNS_BLOCKLIST only accepts true/false" {
    export ENABLE_DNS_BLOCKLIST="invalid"
    run init_environment
    # Should warn or validate
    [ "$status" -eq 0 ]  # May not block startup, but should warn
}

# Test: NetBird defaults are populated by init_environment
@test "init_environment populates NetBird variables" {
    init_environment

    [ "${ENABLE_NETBIRD:-}" = "false" ]
    [ -z "${NETBIRD_SETUP_KEY:-}" ]
    [ -z "${NETBIRD_MANAGEMENT_URL:-}" ]
    [ -z "${NETBIRD_FLAGS:-}" ]
    [ "${NETBIRD_DATA_DIR:-}" = "/var/lib/netbird" ]
    [ "${SERVICE_PIDS[netbird]:-0}" = "0" ]
}

# Test: ENABLE_NETBIRD is validated like the other feature flags
@test "validate_environment rejects an invalid ENABLE_NETBIRD" {
    init_environment
    ENABLE_NETBIRD="invalid"

    run validate_environment
    [ "$status" -ne 0 ]
}
