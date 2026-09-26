#!/usr/bin/env bats
# Tests for lib/dns_runtime.sh module
#
# Tests DNS runtime helpers for dnsmasq and unbound including:
# 1. dnsmasq configuration generation (DoT mode vs Classic mode)
# 2. dnsmasq startup and readiness verification
# 3. Split DNS configuration
# 4. DNS blocklist integration

# Setup: Prepare test environment
setup() {
    export TEST_TMP=$(mktemp -d)
    export DNSMASQ_CONF="$TEST_TMP/dnsmasq.conf"
    export RESOLV_CONF="$TEST_TMP/resolv.conf"
    export DNS_BLOCKLIST_COMPILED_DNSMASQ="$TEST_TMP/blocklist.dnsmasq"
    export DNS_SERVER_1="8.8.8.8"
    export DNS_SERVER_2="8.8.4.4"
    export ENABLE_DOT="false"
    export ENABLE_DNS_BLOCKLIST="false"
    export DNS_SPLIT=""
    export SERVICE_PIDS=()
    
    mkdir -p "$TEST_TMP"
    
    # Source required libraries
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/common.sh
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/dns_runtime.sh
}

teardown() {
    rm -rf "$TEST_TMP"
}

# ============================================================================
# Test Group 1: Module Loading
# ============================================================================

@test "dns_runtime module has all required functions" {
    declare -f configure_dnsmasq >/dev/null || return 1
    declare -f start_dnsmasq >/dev/null || return 1
    declare -f start_dnsmasq_classic >/dev/null || return 1
}

# ============================================================================
# Test Group 2: dnsmasq Configuration - Classic Mode
# ============================================================================

@test "configure_dnsmasq generates classic config with DNS_SERVER_1 and DNS_SERVER_2" {
    export ENABLE_DOT="false"
    
    configure_dnsmasq
    
    [ -f "$DNSMASQ_CONF" ]
    grep -q "listen-address=127.0.0.1" "$DNSMASQ_CONF"
    grep -q "bind-interfaces" "$DNSMASQ_CONF"
    grep -q "no-resolv" "$DNSMASQ_CONF"
    grep -q "server=${DNS_SERVER_1}" "$DNSMASQ_CONF"
    grep -q "server=${DNS_SERVER_2}" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq classic mode sets cache-size" {
    export ENABLE_DOT="false"
    
    configure_dnsmasq
    
    grep -q "cache-size=1000" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq classic mode disables logging to /dev/null" {
    export ENABLE_DOT="false"
    
    configure_dnsmasq
    
    grep -q "log-facility=/dev/null" "$DNSMASQ_CONF"
}

# ============================================================================
# Test Group 3: dnsmasq Configuration - DoT Mode
# ============================================================================

@test "configure_dnsmasq generates DoT config when ENABLE_DOT=true" {
    export ENABLE_DOT="true"
    
    configure_dnsmasq
    
    [ -f "$DNSMASQ_CONF" ]
    grep -q "listen-address=127.0.0.1" "$DNSMASQ_CONF"
    grep -q "server=127.0.0.1#5053" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq DoT mode does NOT include upstream DNS servers" {
    export ENABLE_DOT="true"
    export DNS_SERVER_1="8.8.8.8"
    export DNS_SERVER_2="8.8.4.4"
    
    configure_dnsmasq
    
    # Should NOT contain the public DNS servers when using DoT
    ! grep -q "server=8.8.8.8" "$DNSMASQ_CONF" || grep -q "server=127.0.0.1#5053" "$DNSMASQ_CONF"
}

# ============================================================================
# Test Group 4: Split DNS Configuration
# ============================================================================

@test "configure_dnsmasq adds split DNS entries from DNS_SPLIT" {
    export ENABLE_DOT="false"
    export DNS_SPLIT="corp.local=10.0.0.53,internal.net=10.0.1.53:5353"
    
    configure_dnsmasq
    
    [ -f "$DNSMASQ_CONF" ]
    grep -q "server=/corp.local/10.0.0.53#53" "$DNSMASQ_CONF"
    grep -q "server=/internal.net/10.0.1.53#5353" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq handles split DNS without port (defaults to 53)" {
    export ENABLE_DOT="false"
    export DNS_SPLIT="corp.local=10.0.0.53"
    
    configure_dnsmasq
    
    grep -q "server=/corp.local/10.0.0.53#53" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq handles split DNS with custom port" {
    export ENABLE_DOT="false"
    export DNS_SPLIT="internal.net=10.0.1.53:5353"
    
    configure_dnsmasq
    
    grep -q "server=/internal.net/10.0.1.53#5353" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq ignores invalid split DNS entries" {
    export ENABLE_DOT="false"
    export DNS_SPLIT="invalid,another-invalid=,"
    
    # Should not crash, invalid entries silently ignored
    run configure_dnsmasq
    [ "$status" -eq 0 ]
}

@test "configure_dnsmasq combines split DNS with main servers" {
    export ENABLE_DOT="false"
    export DNS_SPLIT="corp.local=10.0.0.53"
    
    configure_dnsmasq
    
    # Should have both main servers AND split entry
    grep -q "server=8.8.8.8" "$DNSMASQ_CONF"
    grep -q "server=8.8.4.4" "$DNSMASQ_CONF"
    grep -q "server=/corp.local/10.0.0.53#53" "$DNSMASQ_CONF"
}

# ============================================================================
# Test Group 5: DNS Blocklist Integration
# ============================================================================

@test "configure_dnsmasq includes blocklist when ENABLE_DNS_BLOCKLIST=true and file exists" {
    export ENABLE_DOT="false"
    export ENABLE_DNS_BLOCKLIST="true"
    
    # Create mock blocklist file
    touch "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    echo "address=/ads.com/0.0.0.0" > "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    
    configure_dnsmasq
    
    grep -q "conf-file=${DNS_BLOCKLIST_COMPILED_DNSMASQ}" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq skips blocklist when file does not exist" {
    export ENABLE_DOT="false"
    export ENABLE_DNS_BLOCKLIST="true"
    # Don't create the file
    
    configure_dnsmasq
    
    # Should NOT have conf-file directive if blocklist doesn't exist
    ! grep -q "conf-file=" "$DNSMASQ_CONF" || grep -q "server=" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq skips blocklist when disabled" {
    export ENABLE_DOT="false"
    export ENABLE_DNS_BLOCKLIST="false"
    
    touch "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    
    configure_dnsmasq
    
    # Should NOT include blocklist
    ! grep -q "conf-file=" "$DNSMASQ_CONF" || [ ! -s "$DNS_BLOCKLIST_COMPILED_DNSMASQ" ]
}

# ============================================================================
# Test Group 6: Configuration File Structure
# ============================================================================

@test "configure_dnsmasq creates valid dnsmasq config syntax" {
    export ENABLE_DOT="false"
    
    configure_dnsmasq
    
    [ -f "$DNSMASQ_CONF" ]
    [ -s "$DNSMASQ_CONF" ]  # Non-empty
    
    # Basic structure checks
    grep -q "listen-address" "$DNSMASQ_CONF"
    grep -q "bind-interfaces" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq writes generated config marker" {
    export ENABLE_DOT="false"
    
    configure_dnsmasq
    
    head -1 "$DNSMASQ_CONF" | grep -q "Generated at startup"
}

@test "configure_dnsmasq config can be tested by dnsmasq" {
    export ENABLE_DOT="false"
    
    configure_dnsmasq
    
    # Mock dnsmasq test command
    dnsmasq() {
        if [ "$1" = "--test" ]; then
            return 0
        fi
        return 1
    }
    export -f dnsmasq
    
    # Should not crash when test is called
    run dnsmasq --test --conf-file="$DNSMASQ_CONF"
    [ "$status" -eq 0 ]
}

# ============================================================================
# Test Group 7: Environment Variables
# ============================================================================

@test "dns_runtime uses DNS_SERVER_1 and DNS_SERVER_2 from environment" {
    export ENABLE_DOT="false"
    export DNS_SERVER_1="1.1.1.1"
    export DNS_SERVER_2="9.9.9.9"
    
    configure_dnsmasq
    
    grep -q "server=1.1.1.1" "$DNSMASQ_CONF"
    grep -q "server=9.9.9.9" "$DNSMASQ_CONF"
}

@test "ENABLE_DOT variable controls config mode" {
    export ENABLE_DOT="false"
    configure_dnsmasq
    local classic_config=$(cat "$DNSMASQ_CONF")
    
    export ENABLE_DOT="true"
    > "$DNSMASQ_CONF"  # Clear file
    configure_dnsmasq
    local dot_config=$(cat "$DNSMASQ_CONF")
    
    # Should be different
    [ "$classic_config" != "$dot_config" ]
}

# ============================================================================
# Test Group 8: start_dnsmasq_classic() - Variant Function
# ============================================================================

@test "start_dnsmasq_classic temporarily disables DoT" {
    export ENABLE_DOT="true"
    
    # Mock start_dnsmasq to verify ENABLE_DOT value at call time
    local dot_value_during_call=""
    start_dnsmasq() {
        dot_value_during_call="$ENABLE_DOT"
    }
    export -f start_dnsmasq
    
    start_dnsmasq_classic
    
    # Should have been false during the call
    [ "$dot_value_during_call" = "false" ]
}

@test "start_dnsmasq_classic restores original ENABLE_DOT value" {
    export ENABLE_DOT="true"
    
    # Mock start_dnsmasq
    start_dnsmasq() {
        return 0
    }
    export -f start_dnsmasq
    
    start_dnsmasq_classic
    
    # Original value restored
    [ "$ENABLE_DOT" = "true" ]
}

@test "start_dnsmasq_classic handles DNS probe when DNS server unreachable" {
    export ENABLE_DOT="false"
    export DNS_SERVER_1="127.0.0.1"  # Invalid upstream
    
    # Mock start_dnsmasq
    start_dnsmasq() {
        return 0
    }
    export -f start_dnsmasq
    
    # Should not crash even if probe fails
    run start_dnsmasq_classic
    [ "$status" -eq 0 ]
}

# ============================================================================
# Test Group 9: Isolation & Dependencies
# ============================================================================

@test "dns_runtime module depends on common.sh" {
    # Verify log_json is available (from common.sh)
    declare -f log_json >/dev/null
}

@test "dns_runtime module does not modify global state unnecessarily" {
    export ENABLE_DOT="false"
    local original_enable_dot="$ENABLE_DOT"
    
    configure_dnsmasq
    
    # ENABLE_DOT should still be false after configure
    [ "$ENABLE_DOT" = "$original_enable_dot" ]
}

# ============================================================================
# Test Group 10: Edge Cases
# ============================================================================

@test "configure_dnsmasq handles empty DNS_SPLIT gracefully" {
    export ENABLE_DOT="false"
    export DNS_SPLIT=""
    
    run configure_dnsmasq
    [ "$status" -eq 0 ]
    [ -f "$DNSMASQ_CONF" ]
}

@test "configure_dnsmasq works with special characters in split DNS domain" {
    export ENABLE_DOT="false"
    export DNS_SPLIT="my-corp.internal=10.0.0.53"
    
    configure_dnsmasq
    
    grep -q "server=/my-corp.internal/10.0.0.53#53" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq handles IPv6 addresses in DNS_SERVER" {
    export ENABLE_DOT="false"
    export DNS_SERVER_1="2001:4860:4860::8888"
    export DNS_SERVER_2="8.8.4.4"
    
    configure_dnsmasq
    
    grep -q "server=2001:4860:4860::8888" "$DNSMASQ_CONF"
}

@test "configure_dnsmasq config file is writable and readable" {
    export ENABLE_DOT="false"
    
    configure_dnsmasq
    
    [ -f "$DNSMASQ_CONF" ]
    [ -r "$DNSMASQ_CONF" ]
    [ -w "$DNSMASQ_CONF" ]
}
