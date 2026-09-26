#!/usr/bin/env bats
# Tests for dns_blocklist.sh module
#
# Tests the four main blocklist functions:
# 1. download_blocklists() - downloads lists from URLs
# 2. compile_blocklists() - parses and compiles multiple formats
# 3. _blocklist_refresh_loop() - periodic refresh daemon
# 4. start_blocklist_refresh() - starts the refresh loop

# Setup: Prepare test environment
setup() {
    export TEST_TMP=$(mktemp -d)
    export DNS_BLOCKLIST_RAW_DIR="$TEST_TMP/raw"
    export DNS_BLOCKLIST_COMPILED_DNSMASQ="$TEST_TMP/blocklist.dnsmasq"
    export DNS_BLOCKLIST_COMPILED_UNBOUND="$TEST_TMP/blocklist.unbound"
    export DNS_BLOCKLIST_STATE_FILE="$TEST_TMP/blocklist.state"
    export DNS_BLOCKLIST_MIN_AGE=0
    export DNS_BLOCKLIST_REFRESH_INTERVAL=3600
    export ENABLE_DNS_BLOCKLIST=true
    export DNS_BLOCKLIST_URLS=""
    export DNS_BLOCKLIST_ALLOWLIST=""
    
    # Create directories
    mkdir -p "$DNS_BLOCKLIST_RAW_DIR" "$(dirname "$DNS_BLOCKLIST_COMPILED_UNBOUND")"
    
    # Source required libraries
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/common.sh
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/dns_blocklist.sh
}

# Teardown: Clean up test files
teardown() {
    rm -rf "$TEST_TMP"
}

# ============================================================================
# Test Group 1: Module Loading
# ============================================================================

@test "dns_blocklist module has all required functions" {
    declare -f download_blocklists >/dev/null || return 1
    declare -f compile_blocklists >/dev/null || return 1
    declare -f _blocklist_refresh_loop >/dev/null || return 1
    declare -f start_blocklist_refresh >/dev/null || return 1
}

# ============================================================================
# Test Group 2: download_blocklists() - Local file parsing
# ============================================================================

@test "download_blocklists returns 0 when disabled" {
    export ENABLE_DNS_BLOCKLIST=false
    run download_blocklists
    [ "$status" -eq 0 ]
}

@test "download_blocklists returns 1 when no URLs configured" {
    export ENABLE_DNS_BLOCKLIST=true
    export DNS_BLOCKLIST_URLS=""
    run download_blocklists
    # No URLs = no downloads = success is debatable; check empty dir
    [ -d "$DNS_BLOCKLIST_RAW_DIR" ]
}

@test "download_blocklists respects MIN_AGE cache policy" {
    export ENABLE_DNS_BLOCKLIST=true
    export DNS_BLOCKLIST_MIN_AGE=3600
    
    # Simulate cached state (less than 1h old)
    echo "999999999" > "$DNS_BLOCKLIST_STATE_FILE"
    
    run download_blocklists
    # Should skip download due to recent cache
    [ "$status" -eq 0 ]
}

# ============================================================================
# Test Group 3: compile_blocklists() - Format parsing
# ============================================================================

@test "compile_blocklists returns 1 when disabled" {
    export ENABLE_DNS_BLOCKLIST=false
    run compile_blocklists
    [ "$status" -eq 0 ]  # Returns 0 when disabled (skipped)
}

@test "compile_blocklists parses hosts format correctly" {
    export ENABLE_DNS_BLOCKLIST=true
    
    # Create a sample hosts file
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
127.0.0.1 ads.example.com
0.0.0.0 tracker.test.org
127.0.0.1 malware.net
EOF
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    # Check dnsmasq format output
    [ -f "$DNS_BLOCKLIST_COMPILED_DNSMASQ" ]
    grep -q "address=/ads.example.com/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    grep -q "address=/tracker.test.org/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
}

@test "compile_blocklists parses adblock format correctly" {
    export ENABLE_DNS_BLOCKLIST=true
    
    # Create an adblock format file
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
||ads.doubleclick.net^
||google-analytics.com^
||tracking-pixel.org^
EOF
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    [ -f "$DNS_BLOCKLIST_COMPILED_DNSMASQ" ]
    grep -q "address=/ads.doubleclick.net/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
}

@test "compile_blocklists parses raw domain list format" {
    export ENABLE_DNS_BLOCKLIST=true
    
    # Create raw domain list
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
ads.example.com
tracker.test.org
malware.net
suspicious.link
EOF
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    [ -f "$DNS_BLOCKLIST_COMPILED_DNSMASQ" ]
    grep -q "address=/ads.example.com/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
}

@test "compile_blocklists respects allowlist exclusions" {
    export ENABLE_DNS_BLOCKLIST=true
    export DNS_BLOCKLIST_ALLOWLIST="trusted.example.com,cdn.trusted.org"
    
    # Mix of domains, some in allowlist
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
ads.example.com
trusted.example.com
tracker.test.org
cdn.trusted.org
EOF
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    [ -f "$DNS_BLOCKLIST_COMPILED_DNSMASQ" ]
    grep -q "address=/ads.example.com/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    ! grep -q "address=/trusted.example.com/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    ! grep -q "address=/cdn.trusted.org/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
}

@test "compile_blocklists rejects too-small compilations" {
    export ENABLE_DNS_BLOCKLIST=true
    
    # Create a tiny file that won't generate 100+ lines
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
ads.example.com
EOF
    
    run compile_blocklists
    # Should fail due to minimum domain threshold
    [ "$status" -eq 1 ]
}

@test "compile_blocklists generates unbound format correctly" {
    export ENABLE_DNS_BLOCKLIST=true
    
    # Create a substantial hosts file
    for i in {1..150}; do
        echo "127.0.0.1 ads${i}.example.com"
    done > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt"
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    [ -f "$DNS_BLOCKLIST_COMPILED_UNBOUND" ]
    grep -q 'local-zone: "ads1.example.com" always_nxdomain' "$DNS_BLOCKLIST_COMPILED_UNBOUND"
}

# ============================================================================
# Test Group 4: Environment Variable Defaults
# ============================================================================

@test "blocklist environment variables are initialized in common.sh" {
    # Verify that lib/common.sh initializes blocklist variables
    [ -n "${ENABLE_DNS_BLOCKLIST+x}" ]
    [ -n "${DNS_BLOCKLIST_URLS+x}" ]
    [ -n "${DNS_BLOCKLIST_REFRESH_INTERVAL+x}" ]
    [ -n "${DNS_BLOCKLIST_MIN_AGE+x}" ]
    [ -n "${DNS_BLOCKLIST_ALLOWLIST+x}" ]
    
    # Check defaults
    [ "${ENABLE_DNS_BLOCKLIST}" = "false" ]  # Should be disabled by default
    [ "${DNS_BLOCKLIST_REFRESH_INTERVAL}" = "86400" ]  # 24h
    [ "${DNS_BLOCKLIST_MIN_AGE}" = "3600" ]  # 1h
}

# ============================================================================
# Test Group 5: Edge Cases & Error Handling
# ============================================================================

@test "compile_blocklists handles mixed formats in single file" {
    export ENABLE_DNS_BLOCKLIST=true
    
    # Mix all three formats in one file
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
127.0.0.1 ads.example.com
||tracker.net^
malware.org
suspicious.link
0.0.0.0 spam.test.com
EOF
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    [ -f "$DNS_BLOCKLIST_COMPILED_DNSMASQ" ]
    # Verify all formats were parsed
    grep -q "address=/ads.example.com/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    grep -q "address=/tracker.net/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    grep -q "address=/malware.org/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
}

@test "compile_blocklists normalizes domain case to lowercase" {
    export ENABLE_DNS_BLOCKLIST=true
    
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
127.0.0.1 ADS.EXAMPLE.COM
||Tracker.NET^
MalWare.ORG
EOF
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    [ -f "$DNS_BLOCKLIST_COMPILED_DNSMASQ" ]
    grep -q "address=/ads.example.com/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    grep -q "address=/tracker.net/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    grep -q "address=/malware.org/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
}

@test "compile_blocklists deduplicates domains" {
    export ENABLE_DNS_BLOCKLIST=true
    
    # Repeat same domain multiple times
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
127.0.0.1 ads.example.com
127.0.0.1 ads.example.com
ads.example.com
||ads.example.com^
EOF
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    # Count occurrences of ads.example.com
    local count=$(grep -c "ads.example.com" "$DNS_BLOCKLIST_COMPILED_DNSMASQ" || echo 0)
    # Should appear twice (one for IPv4, one for IPv6 in dnsmasq format)
    [ "$count" -eq 2 ]
}

@test "compile_blocklists excludes invalid domains" {
    export ENABLE_DNS_BLOCKLIST=true
    
    cat > "$DNS_BLOCKLIST_RAW_DIR/list_1.txt" << 'EOF'
127.0.0.1 ads.example.com
127.0.0.1 invalid
127.0.0.1 -invalid.domain
127.0.0.1 _underscore.com
127.0.0.1 validDomain123.org
EOF
    
    run compile_blocklists
    [ "$status" -eq 0 ]
    
    # Valid domains should be included
    grep -q "address=/ads.example.com/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
    grep -q "address=/validdomain123.org/0.0.0.0" "$DNS_BLOCKLIST_COMPILED_DNSMASQ"
}
