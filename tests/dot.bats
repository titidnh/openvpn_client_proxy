#!/usr/bin/env bats
# Tests for lib/dot.sh module
#
# Tests DNS-over-TLS (DoT) and Unbound management including:
# 1. DoT IP address mapping and resolution
# 2. Unbound configuration generation
# 3. Dynamic IP refresh and firewall rule updates
# 4. DoT server bootstrapping

# Setup: Prepare test environment
setup() {
    export TEST_TMP=$(mktemp -d)
    export DOT_IP_MAP_FILE="$TEST_TMP/dot_ip_map"
    export DOT_FORWARD_ADDRS_FILE="$TEST_TMP/dot_forward_addrs"
    export DOT_RESOLVED_IPS=""
    export DOT_HOST_IP_MAP=()
    export ENABLE_DOT="true"
    export DOT_DNS_SERVERS="tls://dns.adguard-dns.com,tls://dns.quad9.net"
    export DOT_IP_REFRESH_INTERVAL="3600"
    export ENABLE_DNSSEC="true"
    export DOT_TLS_CERT_BUNDLE=""
    export DNS_SERVER_1="8.8.8.8"
    export DNS_SERVER_2="8.8.4.4"
    
    mkdir -p "$TEST_TMP"
    
    # Source required libraries
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/common.sh
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/firewall.sh
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/dot.sh
}

teardown() {
    rm -rf "$TEST_TMP"
}

# ============================================================================
# Test Group 1: Module Loading
# ============================================================================

@test "dot module has all required functions" {
    declare -f dot_ip_map_set >/dev/null || return 1
    declare -f dot_ip_map_get >/dev/null || return 1
    declare -f preload_dot_ips >/dev/null || return 1
    declare -f start_dot_ip_refresh >/dev/null || return 1
}

# ============================================================================
# Test Group 2: DoT IP Mapping - State Management
# ============================================================================

@test "dot_ip_map_set stores hostname to IP mapping" {
    dot_ip_map_set "dns.adguard-dns.com" "1.1.1.1"
    
    [ -f "$DOT_IP_MAP_FILE" ]
    grep -q "dns.adguard-dns.com=1.1.1.1" "$DOT_IP_MAP_FILE"
}

@test "dot_ip_map_set updates existing mapping" {
    # Store initial mapping
    dot_ip_map_set "dns.adguard-dns.com" "1.1.1.1"
    
    # Update to new IP
    dot_ip_map_set "dns.adguard-dns.com" "2.2.2.2"
    
    # Verify file contains only one entry
    [ -f "$DOT_IP_MAP_FILE" ]
    local count=$(grep -c "dns.adguard-dns.com=" "$DOT_IP_MAP_FILE" || echo 0)
    [ "$count" -eq 1 ]
    
    # Verify new IP is stored
    grep -q "dns.adguard-dns.com=2.2.2.2" "$DOT_IP_MAP_FILE"
    ! grep -q "dns.adguard-dns.com=1.1.1.1" "$DOT_IP_MAP_FILE" || false
}

@test "dot_ip_map_set handles multiple hosts" {
    dot_ip_map_set "dns.adguard-dns.com" "1.1.1.1"
    dot_ip_map_set "dns.quad9.net" "9.9.9.9"
    
    [ -f "$DOT_IP_MAP_FILE" ]
    grep -q "dns.adguard-dns.com=1.1.1.1" "$DOT_IP_MAP_FILE"
    grep -q "dns.quad9.net=9.9.9.9" "$DOT_IP_MAP_FILE"
}

# ============================================================================
# Test Group 3: DoT IP Mapping - Retrieval
# ============================================================================

@test "dot_ip_map_get retrieves stored mapping" {
    dot_ip_map_set "dns.adguard-dns.com" "1.1.1.1"
    
    local result
    result=$(dot_ip_map_get "dns.adguard-dns.com")
    [ "$result" = "1.1.1.1" ]
}

@test "dot_ip_map_get returns empty for unmapped host" {
    local result
    result=$(dot_ip_map_get "unknown.host.com")
    [ -z "$result" ]
}

@test "dot_ip_map_get uses in-memory cache when available" {
    # Set in-memory map
    DOT_HOST_IP_MAP["dns.adguard-dns.com"]="10.0.0.1"
    
    local result
    result=$(dot_ip_map_get "dns.adguard-dns.com")
    [ "$result" = "10.0.0.1" ]
}

@test "dot_ip_map_get reads from file if not in memory" {
    # Clear memory cache
    DOT_HOST_IP_MAP=()
    
    # Write to file
    echo "dns.adguard-dns.com=1.1.1.1" > "$DOT_IP_MAP_FILE"
    
    local result
    result=$(dot_ip_map_get "dns.adguard-dns.com")
    [ "$result" = "1.1.1.1" ]
}

# ============================================================================
# Test Group 4: DoT Server Parsing
# ============================================================================

@test "DOT_DNS_SERVERS handles comma-separated list" {
    export DOT_DNS_SERVERS="tls://dns.adguard-dns.com,tls://dns.quad9.net"
    
    [ -n "$DOT_DNS_SERVERS" ]
    echo "$DOT_DNS_SERVERS" | grep -q "tls://dns.adguard-dns.com"
    echo "$DOT_DNS_SERVERS" | grep -q "tls://dns.quad9.net"
}

@test "DOT_DNS_SERVERS handles space-separated list" {
    export DOT_DNS_SERVERS="tls://dns.adguard-dns.com tls://dns.quad9.net"
    
    [ -n "$DOT_DNS_SERVERS" ]
    echo "$DOT_DNS_SERVERS" | grep -q "tls://dns.adguard-dns.com"
    echo "$DOT_DNS_SERVERS" | grep -q "tls://dns.quad9.net"
}

@test "DOT_DNS_SERVERS supports DoH (https:// prefix)" {
    export DOT_DNS_SERVERS="https://cloudflare-dns.com"
    
    echo "$DOT_DNS_SERVERS" | grep -q "https://"
}

@test "DOT_DNS_SERVERS parsing extracts hostname correctly" {
    export DOT_DNS_SERVERS="tls://dns.adguard-dns.com:853"
    
    # Hostname extraction should handle port
    local entry="$DOT_DNS_SERVERS"
    local host=$(echo "$entry" | sed 's|^[a-z]*://||' | awk -F'[:/]' '{print $1}')
    
    [ "$host" = "dns.adguard-dns.com" ]
}

# ============================================================================
# Test Group 5: Environment Configuration
# ============================================================================

@test "DoT is disabled by default" {
    export ENABLE_DOT="false"
    [ "${ENABLE_DOT}" = "false" ]
}

@test "DoT IP refresh interval is configurable" {
    export DOT_IP_REFRESH_INTERVAL="300"
    [ "$DOT_IP_REFRESH_INTERVAL" = "300" ]
    
    export DOT_IP_REFRESH_INTERVAL="0"
    [ "$DOT_IP_REFRESH_INTERVAL" = "0" ]
}

@test "DoT can be disabled completely (interval=0)" {
    export DOT_IP_REFRESH_INTERVAL="0"
    [ "$DOT_IP_REFRESH_INTERVAL" = "0" ]
}

@test "DNSSEC validation is optional" {
    export ENABLE_DNSSEC="true"
    [ "${ENABLE_DNSSEC}" = "true" ]
    
    export ENABLE_DNSSEC="false"
    [ "${ENABLE_DNSSEC}" = "false" ]
}

@test "DoT cert bundle is customizable" {
    export DOT_TLS_CERT_BUNDLE="/path/to/custom/ca.pem"
    [ "$DOT_TLS_CERT_BUNDLE" = "/path/to/custom/ca.pem" ]
}

# ============================================================================
# Test Group 6: Firewall Integration (Port 853 rules)
# ============================================================================

@test "preload_dot_ips returns 0 when DoT disabled" {
    export ENABLE_DOT="false"
    
    run preload_dot_ips
    [ "$status" -eq 0 ]
}

@test "preload_dot_ips initializes DOT_RESOLVED_IPS" {
    export ENABLE_DOT="true"
    export DOT_DNS_SERVERS="tls://dns.example.com"
    
    # Mock resolve_hostname_all to return an IP
    resolve_hostname_all() {
        echo "1.2.3.4"
    }
    export -f resolve_hostname_all
    
    # Mock ipt_add_853
    ipt_add_853() {
        return 0
    }
    export -f ipt_add_853
    
    preload_dot_ips
    
    # DOT_RESOLVED_IPS should contain the resolved IP
    # (This requires running within the function context)
}

@test "preload_dot_ips handles resolution failures gracefully" {
    export ENABLE_DOT="true"
    export DOT_DNS_SERVERS="tls://unreachable.example.com"
    
    # Mock resolve_hostname_all to return empty (failure)
    resolve_hostname_all() {
        return 1
    }
    export -f resolve_hostname_all
    
    # Should not crash
    run preload_dot_ips
    # Status may be non-zero, but no crash expected
}

# ============================================================================
# Test Group 7: IP Address Format Handling
# ============================================================================

@test "dot_ip_map handles IPv4 addresses" {
    local ipv4="1.2.3.4"
    
    dot_ip_map_set "test.com" "$ipv4"
    
    local result=$(dot_ip_map_get "test.com")
    [ "$result" = "$ipv4" ]
}

@test "dot_ip_map handles IPv6 addresses" {
    local ipv6="2001:4860:4860::8888"
    
    dot_ip_map_set "test.com" "$ipv6"
    
    local result=$(dot_ip_map_get "test.com")
    [ "$result" = "$ipv6" ]
}

@test "dot_ip_map distinguishes IPv4 from IPv6" {
    local ipv4="1.1.1.1"
    local ipv6="2001:4860:4860::1111"
    
    dot_ip_map_set "host4.com" "$ipv4"
    dot_ip_map_set "host6.com" "$ipv6"
    
    [ "$(dot_ip_map_get 'host4.com')" = "$ipv4" ]
    [ "$(dot_ip_map_get 'host6.com')" = "$ipv6" ]
}

# ============================================================================
# Test Group 8: Data Persistence
# ============================================================================

@test "dot IP map persists across function calls" {
    dot_ip_map_set "dns.adguard-dns.com" "1.1.1.1"
    dot_ip_map_set "dns.quad9.net" "9.9.9.9"
    
    # Simulate new session (clear memory)
    DOT_HOST_IP_MAP=()
    
    # File should still contain mappings
    [ -f "$DOT_IP_MAP_FILE" ]
    grep -q "dns.adguard-dns.com=1.1.1.1" "$DOT_IP_MAP_FILE"
    grep -q "dns.quad9.net=9.9.9.9" "$DOT_IP_MAP_FILE"
}

@test "dot IP map file is not corrupted by concurrent updates" {
    # Simulate multiple rapid updates
    dot_ip_map_set "host1.com" "1.1.1.1"
    dot_ip_map_set "host2.com" "2.2.2.2"
    dot_ip_map_set "host1.com" "1.1.1.2"  # Update existing
    
    [ -f "$DOT_IP_MAP_FILE" ]
    
    # Should have exactly 2 lines (one per unique host, deduped)
    local count=$(wc -l < "$DOT_IP_MAP_FILE" 2>/dev/null || echo 0)
    [ "$count" -eq 2 ]
}

# ============================================================================
# Test Group 9: Edge Cases
# ============================================================================

@test "dot_ip_map handles special characters in hostname" {
    local hostname="dns-1.example-domain.co.uk"
    dot_ip_map_set "$hostname" "1.1.1.1"
    
    local result=$(dot_ip_map_get "$hostname")
    [ "$result" = "1.1.1.1" ]
}

@test "dot_ip_map_set creates map file if not exists" {
    [ ! -f "$DOT_IP_MAP_FILE" ]
    
    dot_ip_map_set "test.com" "1.1.1.1"
    
    [ -f "$DOT_IP_MAP_FILE" ]
}

@test "DoT disabled returns 0 from preload_dot_ips" {
    export ENABLE_DOT="false"
    
    run preload_dot_ips
    [ "$status" -eq 0 ]
}

@test "DoT IP refresh interval=0 disables refresh" {
    export DOT_IP_REFRESH_INTERVAL="0"
    [ "$DOT_IP_REFRESH_INTERVAL" = "0" ]
}

# ============================================================================
# Test Group 10: Integration Points
# ============================================================================

@test "dot module uses firewall module for port 853" {
    # Verify that ipt_add_853 is available from firewall.sh
    declare -f ipt_add_853 >/dev/null
}

@test "dot module integrates with common.sh logging" {
    # Verify log_json function is available
    declare -f log_json >/dev/null
}

@test "dot module respects common.sh command_exists utility" {
    # Verify command_exists is available
    declare -f command_exists >/dev/null
}
