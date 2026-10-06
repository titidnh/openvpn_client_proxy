# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.0] - 2026-10-07

### Added
- **WireGuard support** (`VPN_TYPE=wireguard`):
  - New `lib/wireguard.sh`: robust config parsing (`Key = value` and `Key=value`), `PresharedKey`, `PersistentKeepalive` (25 s default behind NAT), routes `0.0.0.0/1` + `128.0.0.0/1`
  - Handshake-based tunnel probe (fails if the last handshake is older than 180 s)
  - Healthcheck accepts the `wg0` interface; fallback to `wireguard-go` when the kernel module is absent
  - IPv6 endpoints (`[host]:port`) supported, including literal addresses
- **DNS Blocklist** (optional feature):
  - New environment variables: `ENABLE_DNS_BLOCKLIST`, `DNS_BLOCKLIST_URLS`, `DNS_BLOCKLIST_REFRESH_INTERVAL`, `DNS_BLOCKLIST_MIN_AGE`, `DNS_BLOCKLIST_ALLOWLIST`
  - Download and compile DNS blocklists from multiple sources (hosts, adblock, raw formats)
  - Integration with dnsmasq and unbound with automatic reload
  - Cache management with configurable TTL and refresh interval
  - Fallback mechanism when blocklist download fails
- **Public IP leak detection**:
  - Real public IP captured at bootstrap; the tunnel check fails with `LEAK DETECTED` if the egress IP equals the real IP
  - `COLLECT_REAL_IP=false` (default) disables the collection
- **CI pipeline** (`.github/workflows/docker-publish.yml`): syntax, shellcheck, parser and security tests run before publishing
- **Security regression test suite**: `tests/security_regression.bats`, `tests/firewall.bats`, `tests/dot.bats`, `parse_tests.sh`

### Security
- **Early lockdown**: DROP-all firewall applied in the first second of supervision; the DNS/bootstrap exceptions (tcp/443) are removed as soon as the full kill switch is in place
- **Fail-closed firewall**:
  - Per-remote `OUTPUT` rules (`-o <iface> -d <ip>`) derived from the OpenVPN config instead of a port-based rule (previously `tcp/443` VPN leaked all HTTPS outside the tunnel)
  - WireGuard rules target the real `Endpoint` IP/port instead of hard-coded `51820`
  - All remote IPs (IPv4 + IPv6, OpenVPN + WireGuard) resolved during bootstrap before lockdown; no port-based fallback remains; startup fails if no rule can be applied
  - After 5 consecutive firewall failures the container exits (code 1) so Docker restarts a full bootstrap
- **Strict DoT mode**: no `ACCEPT` to `DNS_SERVER:53` when DoT is enabled; DNS/DoT upstream traffic only allowed through the tunnel after lockdown; idempotent port 853 rules
- **IPv6 fail-closed**: container refuses to start when IPv6 is enabled but `ip6tables` is unusable; faithful `ip6tables` return codes
- **Supervisor hardening**:
  - PID `0`/empty guard (`kill 0` previously killed the whole process group)
  - `set -e` removed from sourced libraries; critical operations checked explicitly
  - `stop_stack()` cleanup before every retry, no orphaned services
  - Interruptible waits (`sleep_wait`) so `SIGTERM` cleanup runs immediately instead of after up to 40 s
  - Fail-closed startup: services do not start if the firewall or a dependency failed
- **Proxy hardening**: Privoxy runs unprivileged and cannot egress to private networks; the container refuses to start an unauthenticated externally reachable proxy
- **Secrets handling**: Tailscale authkey passed via file (removed after `up`) instead of `--authkey` on the command line; proxy credentials removed from the internal proxy URL; no `bash -c` interpolation of environment values
- **Strict environment validation**: invalid configuration fails startup with an explicit error instead of being silently ignored
- **Tailscale binary pinned** with SHA256 verification (S6)
- Removed the no-op `DROP_CAPS` implementation and the `python3` dependency

### Fixed
- **Supervisor reliability**:
  - Metrics, DoT refresh and blocklist refresh start exactly once even when the first DNS iteration fails (previously disabled for life)
  - Blocklist refresh no longer restarts the whole stack daily (stale dnsmasq PID)
  - Monotonic restart counter; metrics handler reads the configured `METRICS_DIR`
  - Grace period capped at 15 min, backoff capped at 60 s
- **Healthcheck**: honest probe via `PROXY_TEST_URL` (a Privoxy error page no longer counts as healthy); `HEALTHCHECK --timeout` raised from 5 s to 20 s
- **Logging**: `log_json` writes to stderr with escaped messages (no longer pollutes command substitution, produces valid JSON)
- **OpenVPN config parsing**: multi-remote, `<connection>` blocks with per-block and global inheritance, `proto`/`port`/`rport` normalization (`udp4`/`tcp-client` → `udp`/`tcp`), CRLF and UTF-8 BOM handling; bounded `nslookup` fallback with correct busybox/classic output handling
- **DoT validation**: `bind-tools` added to the image so the check queries unbound on port 5053 instead of dnsmasq on port 53
- **WireGuard**: idempotent endpoint host route so reconnects work
- **tinyproxy**: `BasicAuth` credentials validated against the supported character set (invalid credentials fail fast instead of a crash loop)
- **DNS blocklist**: raw lists no longer concatenate domains onto one line

### Changed
- **Authenticated proxy** (`PROXY_AUTH=true`): nginx replaced by tinyproxy (nginx cannot handle `CONNECT`/407 proxy auth); credentials limited to `[A-Za-z0-9._-]`
- `COLLECT_REAL_IP` defaults to `false` (the bootstrap tcp/443 exception only targets `1.1.1.1` and is reserved for blocklist downloads)
- Documentation updated (README, docker-compose profiles: DEFAULT and STRICT-FILTERING)

---

## [2.1.0] - 2026-08-20

### Fixed
- **Unbound stability**: preloading of all resolver IPs, DNSSEC startup fixes, `control-enable`, unbound log with correct ownership
- Stabilization and healthcheck delays retuned in `start.sh` and `healthcheck.sh`
- Privoxy configuration cleanup

### Changed
- Reduced default logging noise

---

## [2.0.0] - 2026-08-09

### Code Quality Improvements

#### Architecture and Organization
- **Created a common functions library** (`lib/common.sh`):
  - Extracted duplicated functions (`find_vpn_interface`, `vpn_tunnel_ready`, etc.)
  - Centralized logging, validation, network, and DNS functions
  - Significantly reduced code duplication between `start.sh` and `healthcheck.sh`

#### Improved Scripts

**start.sh (v2.0.0):**
- **Modular structure**: Clear separation into sections (initialization, firewall, DNS, proxy, Tailscale, monitoring)
- **PID management**: Used an associative array `SERVICE_PIDS` for cleaner tracking
- **Environment validation**: Added validation functions for environment variables
- **Better error handling**: Consistent use of `set -euo pipefail`
- **Improved documentation**: More detailed and structured comments
- **Reusable functions**: Extracted common functions into `lib/common.sh`
- **Structured logging**: Improved JSON format with proper escaping of special characters

**healthcheck.sh (v2.0.0):**
- **Use of common library**: Imported `lib/common.sh` to avoid duplication
- **Modular functions**: Separated checks into distinct functions
- **Better readability**: More structured and commented code
- **Error handling**: More informative error messages

**openvpn.sh (v2.0.0):**
- **Prerequisite validation**: Checked for the existence of files and commands
- **Improved logging**: Used the common library for logging
- **Documentation**: Added comments and metadata

#### Improved Dockerfile
- **Base update**: Switched to `alpine:3.23` (2026-compatible)
- **Enriched metadata**: Added OpenContainers labels
- **Optimization**: Better layer organization
- **Documentation**: More detailed comments

#### Improved docker-compose.yml
- **Organization**: Better structuring of sections
- **Documentation**: Clearer and more complete comments
- **Default variables**: Updated and documented default values

#### Privoxy Configuration
- **privoxy.config**: More comprehensive configuration with advanced security options
- **user.action**: Improved documentation and clearer examples

#### New Files
- **Makefile**: Added useful commands for building, testing, and management
- **.shellcheckrc**: Configuration for shellcheck with justified exclusions
- **.dockerignore**: Comprehensive list of files to exclude
- **CHANGELOG.md**: This file

#### Maintainability Improvements
- **Naming conventions**: More consistent variable and function names
- **Input validation**: Type checking (boolean, number, IP, port)
- **Error handling**: More informative and structured error messages
- **Documentation**: More detailed comments for complex functions
- **Modularity**: Code separation into logical modules

#### 2026 Compatibility
- **Alpine 3.23**: Docker base updated to a version supported in 2026
- **Default DNS**: AdGuard DNS (94.140.14.14, 94.140.15.15) remains valid
- **Tailscale**: Support for recent versions (1.80.3+)
- **Applications**: OpenVPN, Privoxy, dnsmasq, Unbound — all 2026-compatible

### Bug Fixes
- **Code duplication**: Removed duplicated `find_vpn_interface`
- **Style inconsistencies**: Normalized quotes and indentation
- **Error handling**: Better handling of failure cases

### Performance
- **Size reduction**: Better Dockerfile organization for caching
- **Faster startup**: Optimized order of operations

---

## [1.0.0] - 2026-03-06

### Initial Release
- Created the `openvpn_client_proxy` project
- Basic implementation of the Docker container
- Initial configuration of OpenVPN, Privoxy, and dnsmasq
- Implemented kill switch and DNS leak protection
- Optional integration of Tailscale

---

[Unreleased]: https://github.com/titidnh/openvpn_client_proxy/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/titidnh/openvpn_client_proxy/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/titidnh/openvpn_client_proxy/compare/v1.0.0...v2.0.0
