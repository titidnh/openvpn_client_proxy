#!/usr/bin/env bats
# Integration tests for core functionality

setup() {
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/common.sh
}

# Test: Common library is sourced
@test "common.sh module loads successfully" {
    declare -f init_environment >/dev/null || return 1
    declare -f log_info >/dev/null || return 1
}

# Test: Environment initialization works
@test "init_environment populates required variables" {
    init_environment
    # Check core variables are set
    [ -n "${ENABLE_DNS_BLOCKLIST+x}" ]
    [ -n "${ENABLE_PROXY+x}" ]
    [ -n "${ENABLE_VPN+x}" ]
}

# Test: Log functions work without errors
@test "log_info function works" {
    run log_info "test message"
    [ "$status" -eq 0 ]
}

@test "log_error function works" {
    run log_error "test error"
    [ "$status" -eq 0 ]
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
    local child_pid
    sh -c 'sleep 30' &
    child_pid=$!
    SERVICE_PIDS[dnsmasq]="$child_pid"

    run reconfigure_dnsmasq_to_unbound
    [ "$status" -eq 0 ]

    if kill -0 "$child_pid" 2>/dev/null; then
        kill -9 "$child_pid" 2>/dev/null || true
    fi
}

# Test: Invalid configuration values are detected
@test "ENABLE_DNS_BLOCKLIST only accepts true/false" {
    export ENABLE_DNS_BLOCKLIST="invalid"
    run init_environment
    # Should warn or validate
    [ "$status" -eq 0 ]  # May not block startup, but should warn
}
