# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Read-only root filesystem** (roadmap "Read-only filesystem"): the container runs with an immutable root filesystem — `read_only: true` + targeted tmpfs mounts in docker-compose, or `docker run --read-only --tmpfs /run --tmpfs /var/tmp --tmpfs /var/log`
  - All runtime-generated configs moved out of `/etc` into the `/run` tmpfs: dnsmasq (`/run/dnsmasq.conf`), unbound (`/run/unbound/unbound.conf`), the tinyproxy auth config (`/run/tinyproxy/`); the Privoxy runtime config is a copy of the image config adapted in `/run/privoxy.config` (new `PRIVOXY_SOURCE_CONF`, default `/etc/privoxy/privoxy.config`) — `/etc` is never written at runtime
  - Fail-closed startup probe: if `/run` or `/tmp` is not writable (read-only rootfs without tmpfs mounts), the container exits immediately with the exact remediation instead of failing later with cryptic `EROFS` errors; unwritable `/var/tmp`/`/var/log` log a warning
  - `setup_proxy_routing` `rt_tables` registration is best-effort (routing commands already use the numeric table `100` — behavior unchanged on a read-only rootfs)
  - Build-time permission normalization of `/etc/privoxy` (directory `0755`, config files and `templates/` error pages `0644`, explicit `templdir`): the Alpine `privoxy` package ships `0770 root:root`, which breaks Privoxy after its privilege drop — the old runtime `chmod a+rx /etc/privoxy` masked it on writable root filesystems but cannot run against a read-only `/etc`
  - Optional features under read-only mode documented (NetBird: tmpfs on `/etc/netbird`; DNSSEC: `unbound-anchor` volume on `/var/lib/unbound`); covered by `tests/security_regression.bats` (runtime paths outside `/etc`, Privoxy source config never edited, idempotent regeneration, Dockerfile permission guard)
- **Follow the VPN provider's DNS** (`DNS_FROM_VPN`, default `false`): once the tunnel is healthy, dnsmasq switches to the DNS provided by the VPN provider instead of `DNS_SERVER_1`/`DNS_SERVER_2` — restores the geo-consistency of the tunnel (a third-party resolver can break it even when queries go through the tunnel)
  - OpenVPN: `dhcp-option DNS` pushed options captured by a new `--up`/`--route-up` hook (`scripts/vpn-dns-up.sh`, `--script-security 2` enabled only for that hook); WireGuard: `DNS = ...` line of `wg0.conf`
  - Pushed servers are validated, deduplicated and capped at 8 in `VPN_PUSHED_DNS_FILE` (default `/run/vpn-pushed-dns`), emptied at every VPN (re)start so a previous connection's DNS is never reused; the target file is pre-created `vpn:vpn` mode 664 so the post-privilege-drop `--route-up` hook stays able to write it (SIGUSR1 + `--persist-tun` reconnections replay `route-up`, not `up`)
  - The supervisor applies them via `apply_vpn_pushed_dns` (idempotent: dnsmasq restarted only on an actual upstream change); `DNS_SERVER_1`/`DNS_SERVER_2` remain the bootstrap upstreams (remote resolution before the tunnel) and the fallback when nothing is pushed
  - `DNS_FROM_VPN=true` combined with `ENABLE_DOT=true` is rejected by `validate_environment` (fail-closed): DoT to a third party would override the pushed DNS
  - Covered by `tests/dns_from_vpn.bats` (25 tests: defaults, validation, switching, idempotence, hostile input, hook, WireGuard parsing); documented in the README
- **LAN metrics scraping (explicit opt-in)** (`METRICS_BIND`, default `127.0.0.1`): bind the `/metrics` endpoint outside the container loopback (e.g. `0.0.0.0` for a remote Prometheus). The container firewall opens the matching INPUT rule only when the bind is not loopback, and a warning is logged at startup
  - Access modes documented in the README "Prometheus Metrics" section: `docker exec` (default), Docker host via `127.0.0.1:9100:9100` port mapping, LAN via `METRICS_BIND=0.0.0.0` + published port
- **NetBird integration** (`ENABLE_NETBIRD`, default `false`): optional [NetBird](https://netbird.io) mesh VPN client alongside Tailscale — open-source and self-hostable alternative
  - `netbird` binary (v0.81.3, SHA256-verified) installed via a dedicated Docker stage, same pattern as the Tailscale binaries
  - Configuration via environment / docker-compose: `NETBIRD_SETUP_KEY`, `NETBIRD_MANAGEMENT_URL` (self-hosted), `NETBIRD_FLAGS`, `NETBIRD_DATA_DIR`
  - Setup key passed to the client via its environment (`NB_SETUP_KEY`), never on the command line (not visible in `ps`)
  - Client started in foreground mode and supervised like the other services: deferred start until the tunnel is healthy, idempotent restarts, full restart if the process dies
  - Kill switch extended: forwarding between the NetBird interface (`wt+`) and the VPN tunnel (`tun+`/`tap+`/`wg+`) allowed in IPv4 and IPv6
  - `/var/lib/netbird` volume for persistent peer identity; docs and docker-compose examples updated (Tailscale and NetBird can run simultaneously, with a supervisor warning)
- **Local DNS bypass** (`DNS_BYPASS_VPN`, default `false`): pins the upstream DNS servers outside the VPN tunnel so a **local** resolver (box DNS, LAN Pi-hole) stays reachable through the physical network
  - Works in plain mode (`DNS_SERVER_1`/`DNS_SERVER_2`, ports 53 UDP+TCP) and in DoT/DoH mode (resolved server IPs, ports 853/443 per `DOT_FORWARD_ADDRS_FILE`)
  - Idempotent firewall ACCEPT rules by destination, re-applied on every kill-switch rebuild, unbound restart and DoT IP refresh
  - Host routes via the physical gateway (`ip route replace`) so `redirect-gateway` (OpenVPN) or the `0.0.0.0/1`+`128.0.0.0/1` routes (WireGuard) don't swallow DNS traffic into the tunnel; re-asserted after every tunnel (re)connection
  - Security trade-off documented in the README: queries leave through the local network and keep working when the tunnel is down — only enable for local resolvers

### Fixed
- **Metrics endpoint ignored `METRICS_PORT`**: the listener (socat/nc) and the firewall loopback rules hard-coded `9100`; `METRICS_PORT` is now honored by the listener, the IPv4/IPv6 loopback OUTPUT rules, and validated (`validate_port`/`validate_ip`) like the other variables
- **socat log noise on every metrics scrape**: the generated handler answered without consuming the client's HTTP request, so socat closed the socket with unread data and logged `read(...): Connection reset by peer` on each scrape; the handler now drains the request before answering, and socat runs with a 30 s inactivity timeout so stalled clients can't pile up forked handlers

### Changed
- **Default runtime config paths** (read-only filesystem support): `DNSMASQ_CONF` `/etc/dnsmasq.conf` → `/run/dnsmasq.conf`, `UNBOUND_CONF` `/etc/unbound/unbound.conf` → `/run/unbound/unbound.conf`, `PRIVOXY_CONF` `/etc/privoxy/privoxy.config` → `/run/privoxy.config`, tinyproxy auth config `/etc/tinyproxy/` → `/run/tinyproxy/`. Overriding these variables keeps working as before; one-liners that read the old paths (monitoring, `docker exec`) must use the new ones
- **Repository restructure** (no functional changes): runtime scripts moved to `scripts/` (`start.sh`, `openvpn.sh`, `healthcheck.sh`, `vpn-selector.sh`), Privoxy configuration to `config/privoxy/` (`privoxy.config`, `default.action`, `default.filter`, `user.action`, `user.filter`), test helper to `tests/parse_tests.sh`, and documentation to `docs/` (`CI_LINT_TESTS.md`, `SECURITY_REVIEW.md`)
  - Moved files are byte-identical; only path references were updated (Dockerfile, Makefile, CI workflow, bats tests, README)
  - Destination paths inside the container are unchanged (`/start.sh`, `/usr/local/bin/*.sh`, `/usr/local/lib/*.sh`, `/etc/privoxy/`) — no impact on the published image behaviour

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
