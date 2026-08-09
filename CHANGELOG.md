# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [1.0.0] - 2024-XX-XX

### Initial Release
- Created the `openvpn_client_proxy` project
- Basic implementation of the Docker container
- Initial configuration of OpenVPN, Privoxy, and dnsmasq
- Implemented kill switch and DNS leak protection
- Optional integration of Tailscale

---
[2.0.0]: https://github.com/titidnh/openvpn_client_proxy/compare/v1.0.0...v2.0.0
