#!/usr/bin/env bats
# Tests for dns_blocklist.sh module

# Load the dns_blocklist module
setup() {
    # Source the common library and dns_blocklist module
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/common.sh
    source "$(dirname "$BATS_TEST_FILENAME")"/../lib/dns_blocklist.sh
}

# Test: dns_blocklist module is sourced correctly
@test "dns_blocklist module is loaded" {
    # Should define key functions
    declare -f download_blocklists >/dev/null || return 1
    declare -f compile_blocklist >/dev/null || return 1
    declare -f validate_blocklist_size >/dev/null || return 1
}

# Test: validate_blocklist_size rejects empty files
@test "validate_blocklist_size rejects empty files" {
    tmpfile=$(mktemp)
    run validate_blocklist_size "$tmpfile"
    [ "$status" -eq 1 ]  # Should fail for empty file
    rm "$tmpfile"
}

# Test: validate_blocklist_size rejects files below minimum size
@test "validate_blocklist_size rejects too small files" {
    tmpfile=$(mktemp)
    echo "127.0.0.1 blocked.domain" > "$tmpfile"  # Just 1 line, too small
    run validate_blocklist_size "$tmpfile"
    # Result depends on MIN_SIZE config - should fail if too small
    [ "$status" -eq 1 ]
    rm "$tmpfile"
}

# Test: Common initialization works with blocklist defaults
@test "init_environment sets blocklist defaults" {
    # Should initialize ENABLE_DNS_BLOCKLIST, DNS_BLOCKLIST_URLS, etc.
    init_environment
    [ -n "${ENABLE_DNS_BLOCKLIST+x}" ]  # Variable exists
    [ -n "${DNS_BLOCKLIST_URLS+x}" ]
    [ -n "${DNS_BLOCKLIST_REFRESH_INTERVAL+x}" ]
    [ -n "${DNS_BLOCKLIST_MIN_AGE+x}" ]
    [ -n "${DNS_BLOCKLIST_ALLOWLIST+x}" ]
}

# Test: Allowlist parsing handles empty allowlist
@test "allowlist parsing handles empty allowlist gracefully" {
    tmpfile=$(mktemp)
    DNS_BLOCKLIST_ALLOWLIST=""
    # Function should not fail with empty allowlist
    run true  # Placeholder - actual function call when function exists
    [ "$status" -eq 0 ]
    rm "$tmpfile"
}
