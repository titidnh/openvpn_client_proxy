# OpenVPN Client Proxy

> **Lightweight Docker container** running an OpenVPN client, an HTTP proxy ([Privoxy](https://www.privoxy.org/)), and a local DNS resolver ([dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html)) — featuring a network **kill switch**, **DNS leak protection**, **optional proxy authentication**, and optional **Tailscale** integration.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration Files](#configuration-files)
  - [vpn.conf — OpenVPN Configuration](#vpnconf--openvpn-configuration)
  - [vpn.auth — Credentials File](#vpnauth--credentials-file)
  - [dnsmasq.conf — DNS Resolver](#dnsmasqconf--dns-resolver)
  - [privoxy.config — HTTP Proxy](#privoxyconfig--http-proxy)
- [Environment Variables](#environment-variables)
- [Network Kill Switch](#network-kill-switch)
- [DNS Leak Protection](#dns-leak-protection)
- [DNS-over-TLS (Optional)](#dns-over-tls-optional)
- [Split DNS (Optional)](#split-dns-optional)
- [Prometheus Metrics (Optional)](#prometheus-metrics-optional)
- [Structured JSON Logs](#structured-json-logs)
- [Capability Drop (Optional)](#capability-drop-optional)
- [Proxy Authentication (Optional)](#proxy-authentication-optional)
- [Supervision & Auto-Restart](#supervision--auto-restart)
- [Healthcheck](#healthcheck)
- [Tailscale Integration (Optional)](#tailscale-integration-optional)
- [Docker Compose Examples](#docker-compose-examples)
- [Build](#build)
- [Using the Proxy](#using-the-proxy)
- [Troubleshooting](#troubleshooting)
- [Project File Reference](#project-file-reference)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| 🔒 **VPN Kill Switch** | iptables DROP policy by default — all traffic is blocked if the tunnel drops |
| 🛡️ **DNS Leak Protection** | All DNS queries are forced through local `dnsmasq` — no external resolver bypass possible |
| 🔁 **Auto-Reconnect** | Built-in supervisor with exponential backoff (5s → 60s cap) restarts services on failure |
| 🌐 **HTTP Proxy** | Privoxy on port `3128` — usable by any app or container that supports HTTP proxies |
| 🔑 **Optional Proxy Auth** | Set `PROXY_USER` + `PROXY_PASS` to require HTTP Basic Auth on the proxy (nginx fronts Privoxy) |
| 🧹 **Ad/Content Filtering** | DNS-level filtering via upstream resolver — configurable with `DNS_SERVER_1` / `DNS_SERVER_2` (default: AdGuard, ads only) |
| 🐳 **Multi-arch** | Docker image published for `linux/amd64` and `linux/arm64` |
| 🔗 **Tailscale Exit Node** | Optional — route your entire Tailscale network through the VPN tunnel |
| 📦 **Minimal Image** | Based on `alpine:3.20` — minimal footprint (~120 MB), multi-stage build isolates Tailscale binaries |
| 🔐 **DNS-over-TLS** | Optional — all DNS queries encrypted via `unbound` → DoT upstream (port 853). Blocks plain DNS port 53 leaks when enabled. |
| 🔒 **DNSSEC Validation** | Optional (`ENABLE_DNSSEC=true`) — strict DNSSEC validation via unbound with auto-managed root trust anchor |
| 📌 **DoT Cert Pinning** | Mount a custom CA bundle (`DOT_TLS_CERT_BUNDLE`) to restrict which TLS certificates are accepted for DoT connections |
| 🌍 **DoH Support** | Use `https://` prefix in `DOT_DNS_SERVERS` to forward to a DNS-over-HTTPS upstream |
| 🔀 **Split DNS** | Route specific domains to an internal resolver (`DNS_SPLIT="corp.local=10.0.0.53"`). Works in both plain and DoT modes. |
| 🔄 **Dynamic DoT IP Refresh** | Periodically re-resolves DoT server hostnames and updates iptables rules atomically (zero connectivity interruption) |
| 📊 **Prometheus Metrics** | Optional (`ENABLE_METRICS=true`) — exposes a `/metrics` endpoint on `127.0.0.1:9100` with VPN status, restart count, DoT state, and uptime |
| 🛡️ **Capability Drop** | Optional (`DROP_CAPS=true`) — drops all Linux capabilities except `CAP_NET_ADMIN` and `CAP_NET_RAW` after startup |
| 📋 **Structured JSON Logs** | All log output is JSON (`{"ts":"...","level":"INFO","component":"...","msg":"..."}`), ready for Loki/Splunk/any log aggregator |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                       Docker Container                          │
│                                                                 │
│  ┌──────────┐  ┌─────────┐  ┌──────────┐  ┌─────────────────┐   │
│  │ dnsmasq  │  │ unbound │  │ Privoxy  │  │    OpenVPN      │   │
│  │  :53     │→ │  :5053  │  │  :3128   │  │  (tun0 / tap0)  │   │
│  └──────────┘  └────┬────┘  └────┬─────┘  └───────┬─────────┘   │
│  (DoT mode only)    │TLS:853     │                │             │
│                     │            │                │             │
│  ┌──────────────────┴────────────┴────────────────┘             │
│  │               iptables / ip6tables                           │
│  │     DROP default — DNS :53 leak blocked if DoT active        │
│  └───────────────────────────┬──────────────────────────────────│
│                               │ VPN Tunnel                      │
│  ┌─────────────────────────── │ ──────────────────────────────┐ │
│  │ Supervisor (start.sh)      │                               │ │
│  │  • JSON structured logs    │  • Prometheus metrics :9100   │ │
│  │  • Dynamic DoT IP refresh  │  • Capability drop (optional) │ │
│  └────────────────────────────┴───────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │ VPN Tunnel
                              ▼
                        VPN Server (remote)
                              │
                              ▼
                           Internet
```

- **dnsmasq** listens on `127.0.0.1:53` and forwards queries either directly to `DNS_SERVER_1` / `DNS_SERVER_2` (plain DNS mode) or to `unbound` on `127.0.0.1:5053` (DoT mode). Default upstream: AdGuard `94.140.14.14` / `94.140.15.15`. No process inside or outside the container can reach another resolver.
- **Privoxy** listens on `0.0.0.0:3128` and routes all HTTP/HTTPS traffic through the VPN tunnel.
- **iptables** enforces a DROP-everything-by-default policy. Only traffic going out via `tun+` / `tap+` interfaces is allowed.
- **start.sh** is the entrypoint supervisor — it starts all services, watches them every 10 seconds, and restarts on failure. It also runs optional services: `socat` metrics endpoint on `:9100`, dynamic DoT IP refresh, and post-startup capability drop.

---

## Prerequisites

- Docker Engine ≥ 20.10 (or Docker Desktop)
- A valid OpenVPN configuration file (`.ovpn` or `.conf`)
- The host kernel must have the `tun` module loaded: `modprobe tun`
- `NET_ADMIN` capability and access to `/dev/net/tun`
- `python3` and `socat` are bundled in the image — no host-side installation needed

---

## Quick Start

### 1. Prepare your VPN directory

Create a local directory (e.g. `./vpn/`) and place your files inside:

```
./vpn/
├── vpn.conf        ← required: your OpenVPN config (rename .ovpn → vpn.conf)
└── vpn.auth        ← optional: credentials file (username + password, one per line)
```

> See the [vpn.conf example](#vpnconf--openvpn-configuration) and [vpn.auth example](#vpnauth--credentials-file) below.

### 2. Run the container

```sh
docker run \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --rm \
  --memory 128MB \
  -v ./vpn:/vpn:ro \
  -p 3128:3128 \
  titidnh/openvpn_client_proxy:latest
```

### 3. Test the proxy

```sh
curl --proxy http://127.0.0.1:3128 https://api.ipify.org
```

The returned IP should be your VPN's exit IP — not your real one.

---

## Configuration Files

### `vpn.conf` — OpenVPN Configuration

Rename your provider's `.ovpn` file to `vpn.conf` and place it in the `/vpn` mount directory.

The entrypoint reads `remote`, `proto`, and port directly from this file to configure the iptables kill switch correctly.

**Minimal example (UDP, password auth):**

```ini
client
dev tun
proto udp

remote vpn.example.com 1194

resolv-retry infinite
nobind

persist-key
persist-tun

ca   ca.crt
cert client.crt
key  client.key

auth-user-pass vpn.auth

verb 3
```

**Example with inline certificates (single-file config, no extra files needed):**

```ini
client
dev tun
proto tcp

remote vpn.example.com 443

resolv-retry infinite
nobind

persist-key
persist-tun

remote-cert-tls server
cipher AES-256-GCM
auth SHA256

auth-user-pass vpn.auth

verb 3

<ca>
-----BEGIN CERTIFICATE-----
MIIBxxx...
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
MIIBxxx...
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
MIIBxxx...
-----END PRIVATE KEY-----
</key>

<tls-auth>
-----BEGIN OpenVPN Static key V1-----
xxxx...
-----END OpenVPN Static key V1-----
</tls-auth>
key-direction 1
```

> **Tip:** Most commercial VPN providers (Mullvad, ProtonVPN, NordVPN, etc.) let you export a `.ovpn` file from their website. Just rename it to `vpn.conf`.

---

### `vpn.auth` — Credentials File

If your `vpn.conf` contains `auth-user-pass vpn.auth`, create this file alongside `vpn.conf`:

```
myusername
mypassword
```

- Line 1 → username
- Line 2 → password
- No trailing spaces or blank lines

> ⚠️ Restrict file permissions: `chmod 600 vpn.auth`

---

### `dnsmasq.conf` — DNS Resolver

Located at `/etc/dnsmasq.conf` inside the container. **This file is generated at container startup** from the `DNS_SERVER_1` and `DNS_SERVER_2` environment variables — editing the repository file has no effect at runtime.

**Default upstream resolvers (AdGuard Default — blocks ads only):**

```ini
server=94.140.14.14
server=94.140.15.15
```

**Change DNS provider via environment variables:**

```bash
# Cloudflare — no filtering
-e DNS_SERVER_1=1.1.1.1 -e DNS_SERVER_2=1.0.0.1

# Quad9 — blocks malware/phishing
-e DNS_SERVER_1=9.9.9.9 -e DNS_SERVER_2=149.112.112.112

# AdGuard Family — blocks ads AND adult content
-e DNS_SERVER_1=94.140.14.15 -e DNS_SERVER_2=94.140.15.16

# Google DNS — no filtering
-e DNS_SERVER_1=8.8.8.8 -e DNS_SERVER_2=8.8.4.4
```

> The declared IPs are automatically whitelisted in iptables by `start.sh` — no manual firewall changes needed.

---

### `privoxy.config` — HTTP Proxy

Located at `/etc/privoxy/privoxy.config` inside the container.

**Current configuration:**

```ini
# Proxy listen address and port
listen-address 0.0.0.0:3128

# Disable all logging (privacy + Docker stdout cleanliness)
logdir /dev/null
logfile /dev/null

# Action and filter files (default < user — user overrides default)
actionsfile /etc/privoxy/default.action
actionsfile /etc/privoxy/user.action

filterfile /etc/privoxy/default.filter
filterfile /etc/privoxy/user.filter

# No admin UI exposed
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0

# Buffer limit (needed for regex filters on compressed content)
buffer-limit 10240
```

To change the listening port, edit `listen-address` and update the `-p` flag in `docker run` (or `ports:` in compose) accordingly.

> ⚠️ **Security notice:** by default, Privoxy has no authentication. The proxy accepts connections from any client that can reach port 3128. See the [Proxy Authentication](#proxy-authentication-optional) section to enable Basic Auth, or at minimum bind the port to `127.0.0.1` only.

---

## Environment Variables

All variables are optional. Defaults match a plain OpenVPN-only setup.

| Variable | Default | Description |
|---|---|---|
| `DNS_SERVER_1` | `94.140.14.14` | Primary upstream DNS resolver (AdGuard Default — ads only). Set to any IPv4 address. |
| `DNS_SERVER_2` | `94.140.15.15` | Secondary upstream DNS resolver. |
| `PROXY_USER` | *(empty)* | Username for HTTP Basic Auth on the proxy. Both `PROXY_USER` and `PROXY_PASS` must be set to activate auth. |
| `PROXY_PASS` | *(empty)* | Password for HTTP Basic Auth. Uses bcrypt hashing via `htpasswd`. |
| `ENABLE_TAILSCALE` | `false` | Set to `true` to start `tailscaled` at container startup. |
| `TAILSCALE_AUTHKEY` | *(empty)* | Pre-auth key for non-interactive `tailscale up`. |
| `TAILSCALE_FLAGS` | *(empty)* | Extra flags appended verbatim to `tailscale up`. |
| `TAILSCALE_ACCEPT_ROUTES` | `false` | Pass `--accept-routes` to `tailscale up`. |
| `TAILSCALE_HOSTNAME` | `openvpn-client-proxy` | Hostname registered in Tailscale (`--hostname`). |
| `TAILSCALE_ADVERTISE_EXIT_NODE` | `false` | Advertise this container as a Tailscale exit node — all Tailscale clients can route traffic through the VPN. |
| `ENABLE_DOT` | `false` | Set to `true` to enable DNS-over-TLS. All DNS queries are routed through a local `unbound` instance that forwards to DoT upstream servers on port 853. Plain DNS port 53 egress is blocked. |
| `DOT_DNS_SERVERS` | `tls://dns.adguard-dns.com` | Space or comma-separated list of DoT/DoH servers. Format: `tls://hostname` or `https://hostname`. Used only when `ENABLE_DOT=true`. |
| `ENABLE_DNSSEC` | `false` | Set to `true` to enable strict DNSSEC validation in unbound. Initialises the root trust anchor via `unbound-anchor`. Leave `false` for zones that are not DNSSEC-signed. |
| `DOT_TLS_CERT_BUNDLE` | *(system CA)* | Path to a PEM bundle for TLS certificate verification of DoT servers. Defaults to Alpine's system bundle. Mount a restricted bundle for certificate pinning (e.g. `-v ./my-ca.pem:/vpn/dot-ca.pem:ro` then `DOT_TLS_CERT_BUNDLE=/vpn/dot-ca.pem`). |
| `DOT_IP_REFRESH_INTERVAL` | `3600` | Seconds between re-resolution of DoT server hostnames. If an IP changes, iptables rules are updated atomically. Set to `0` to disable. |
| `DNS_SPLIT` | *(empty)* | Comma-separated list of `domain=resolver[:port]` entries for split DNS. Routes those domains to an internal resolver instead of the default upstream. Works in both DoT and plain modes. Example: `corp.local=10.0.0.53,internal.net=10.0.1.53:5353` |
| `ENABLE_METRICS` | `false` | Set to `true` to expose a Prometheus-compatible metrics endpoint on `127.0.0.1:9100`. The port is loopback-only (iptables enforced). |
| `DROP_CAPS` | `false` | Set to `true` to drop all Linux capabilities except `CAP_NET_ADMIN` and `CAP_NET_RAW` after all services have started. |

---

## Network Kill Switch

At container startup, `start.sh` installs iptables rules with a **DROP-by-default** policy for INPUT, FORWARD, and OUTPUT chains. This means:

- **No traffic exits the container** unless it goes through the VPN tunnel (`tun+` / `tap+` interfaces)
- If the VPN tunnel drops, internet connectivity is fully blocked — nothing leaks in plaintext
- DNS is only permitted to `127.0.0.1:53` (local dnsmasq) and the upstream IPs declared in `dnsmasq.conf`
- The Docker internal network (`eth0` subnet) is always allowed so the container remains reachable on port `3128`

The kill switch is re-applied on every service restart cycle, including supervised restarts after a failure.

**IPv6 is also covered:** `ip6tables` rules mirror the IPv4 rules. If IPv6 is unavailable in the runtime, the setup is skipped gracefully.

---

## DNS Leak Protection

`/etc/resolv.conf` is overwritten at startup to:

```
nameserver 127.0.0.1
```

This forces every process inside the container (including OpenVPN itself) to use local dnsmasq for DNS resolution. dnsmasq then forwards queries to the upstream servers **through the VPN tunnel** (because iptables only allows outbound traffic via `tun+`/`tap+`).

If the Docker runtime mounts `/etc/resolv.conf` as read-only, the entrypoint falls back to a `mount --bind` from `/tmp` to achieve the same result.

---

## DNS-over-TLS (Optional)

By default, DNS queries are forwarded in plaintext to `DNS_SERVER_1` / `DNS_SERVER_2`. This means your ISP or anyone on the network path between the container and the DNS server can observe which domains you resolve (even though traffic itself goes through the VPN).

**DNS-over-TLS (DoT)** encrypts DNS queries using TLS on port **853**, eliminating this metadata leak.

### Architecture with DoT enabled

```
┌──────────────────────────────────────────────────────────────────┐
│                        Docker Container                          │
│                                                                  │
│  App → dnsmasq :53 → unbound :5053 ──TLS:853──→ DoT Server      │
│                                        (via VPN tunnel tun0)     │
│                                                                  │
│  iptables: UDP/TCP 53 external → DROP  (DNS leak kill switch)    │
│            TCP 853 → DoT server IPs   → ACCEPT                   │
└──────────────────────────────────────────────────────────────────┘
```

- **dnsmasq** continues to listen on `127.0.0.1:53` — no application changes needed
- **unbound** listens on `127.0.0.1:5053` and forwards all queries via TLS to the DoT upstream(s)
- The firewall **blocks all external UDP/TCP 53** (plain DNS leak prevention) and **allows TCP 853** only to the resolved IPs of the configured DoT servers
- DoT server IPs are resolved **once at startup** using the original system `resolv.conf` — before dnsmasq takes over — to avoid any circular dependency

### Enabling DNS-over-TLS

```bash
docker run \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  -e ENABLE_DOT=true \
  -e DOT_DNS_SERVERS="tls://dns.adguard-dns.com" \
  -v ./vpn:/vpn:ro \
  -p 3128:3128 \
  titidnh/openvpn_client_proxy:latest
```

Or in Docker Compose:

```yaml
environment:
  ENABLE_DOT: "true"
  DOT_DNS_SERVERS: "tls://dns.adguard-dns.com"
```

### Multiple DoT servers (failover)

Pass multiple servers separated by spaces or commas:

```yaml
DOT_DNS_SERVERS: "tls://dns.adguard-dns.com tls://cloudflare-dns.com"
```

unbound will use them in round-robin / failover order.

### Popular DoT providers

| Provider | `DOT_DNS_SERVERS` value | Filtering |
|---|---|---|
| AdGuard Default | `tls://dns.adguard-dns.com` | Ads only |
| AdGuard Family | `tls://family.adguard-dns.com` | Ads + adult content |
| Cloudflare | `tls://cloudflare-dns.com` | None |
| Cloudflare Malware | `tls://security.cloudflare-dns.com` | Malware/phishing |
| Quad9 | `tls://dns.quad9.net` | Malware/phishing |
| Google | `tls://dns.google` | None |
| NextDNS | `tls://dns.nextdns.io` | Configurable |

> **Note:** When `ENABLE_DOT=true`, the `DNS_SERVER_1` / `DNS_SERVER_2` variables are ignored — DoT servers defined in `DOT_DNS_SERVERS` take over entirely.

### DNS-over-HTTPS (DoH)

Use the `https://` prefix to forward to a DoH upstream instead of DoT. unbound will connect on port 443 with TLS and SNI:

```yaml
DOT_DNS_SERVERS: "https://cloudflare-dns.com"
# or mix DoT and DoH:
DOT_DNS_SERVERS: "tls://dns.adguard-dns.com https://cloudflare-dns.com"
```

### DNSSEC validation

Enable strict DNSSEC signature verification for all resolved domains:

```yaml
ENABLE_DNSSEC: "true"
```

On first start, `unbound-anchor` downloads the IANA root trust anchor into `/var/lib/unbound/root.key`. Zones that are not DNSSEC-signed will fail to resolve. Leave at `false` (default) if your VPN provider or upstreams use unsigned zones.

### Certificate pinning

By default, unbound verifies DoT server certificates against Alpine's system CA bundle. For stricter pinning, mount your own bundle:

```yaml
volumes:
  - ./my-dot-ca.pem:/vpn/dot-ca.pem:ro
environment:
  DOT_TLS_CERT_BUNDLE: "/vpn/dot-ca.pem"
```

Create a minimal bundle containing only the CA(s) that signed your DoT server's certificate:

```sh
# Example: extract AdGuard DNS CA from the system bundle
openssl s_client -connect dns.adguard-dns.com:853 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -out my-dot-ca.pem
```

### Dynamic IP refresh

DoT server hostnames (e.g. `dns.adguard-dns.com`) are resolved at startup. The refresh loop re-resolves them every `DOT_IP_REFRESH_INTERVAL` seconds (default: 1 hour). If an IP changes, the new iptables rule is added **before** the old one is removed — zero connectivity interruption:

```yaml
DOT_IP_REFRESH_INTERVAL: "3600"   # 1 hour (default)
DOT_IP_REFRESH_INTERVAL: "300"    # 5 minutes (aggressive)
DOT_IP_REFRESH_INTERVAL: "0"      # disabled
```

### Verifying DoT is active

Check that unbound started and bound to port 5053:

```sh
docker logs <container> | grep unbound
# → {"component":"start_unbound","msg":"started — DoT active","port":"5053"}
```

Confirm no plain DNS queries escape:

```sh
# Should FAIL — all external port 53 is blocked
docker exec <container> nslookup example.com 8.8.8.8

# Should work — via local chain: dnsmasq → unbound → DoT
docker exec <container> nslookup example.com 127.0.0.1
```

---

## Split DNS (Optional)

Split DNS routes specific domains to a designated internal resolver while all other queries follow the default path (DoT upstream or `DNS_SERVER_1/2`).

```yaml
# Single internal domain
DNS_SPLIT: "corp.local=10.0.0.53"

# Multiple domains, custom port
DNS_SPLIT: "corp.local=10.0.0.53,internal.net=10.0.1.53:5353"
```

**How it works:**

| Mode | Implementation |
|---|---|
| `ENABLE_DOT=true` | unbound `forward-zone` entries with `forward-tls-upstream: no` (plain DNS to internal resolver) |
| `ENABLE_DOT=false` | dnsmasq `server=/domain/ip#port` directives |

The internal resolver receives queries for the specified domain in **plain DNS** (no TLS) — this is intentional for RFC-1918 resolvers that do not support TLS.

---

## Prometheus Metrics (Optional)

Enable with `ENABLE_METRICS=true`. The endpoint is served on `127.0.0.1:9100` via `socat`, loopback-only (iptables enforces this — the port is never reachable from outside the container).

```sh
# Access from the host via docker exec:
docker exec <container> curl -s http://127.0.0.1:9100/metrics
```

**Available metrics:**

| Metric | Type | Description |
|---|---|---|
| `vpn_up` | gauge | `1` if the VPN tunnel is active, `0` otherwise |
| `vpn_restart_total` | counter | Total number of supervisor restart cycles |
| `dot_active` | gauge | `1` if DNS-over-TLS (unbound) is running |
| `process_uptime_seconds` | gauge | Container uptime in seconds |
| `last_restart_timestamp_seconds` | gauge | Unix epoch of the last supervisor restart |

**Prometheus scrape config example:**

```yaml
scrape_configs:
  - job_name: openvpn_proxy
    static_configs:
      - targets: ['<docker_host_ip>:9100']   # expose via SSH tunnel or sidecar
```

> ⚠️ Never bind port 9100 to `0.0.0.0` — always access it via `docker exec` or an SSH tunnel.

---

## Structured JSON Logs

All output from `start.sh` is JSON, one object per line:

```json
{"ts":"2025-01-15T10:23:01Z","level":"INFO","component":"start_unbound","msg":"started — DoT active","pid":"42","port":"5053"}
{"ts":"2025-01-15T10:23:04Z","level":"INFO","component":"check_vpn_ip","msg":"public IP via VPN confirmed","ip":"185.220.101.1"}
{"ts":"2025-01-15T10:33:15Z","level":"WARN","component":"supervisor","msg":"openvpn routing failure"}
{"ts":"2025-01-15T10:33:20Z","level":"INFO","component":"supervisor","msg":"openvpn routing restored","pid":"89"}
```

Fields: `ts` (ISO-8601 UTC), `level` (`INFO`/`WARN`/`ERROR`), `component`, `msg`, plus optional key-value pairs.

**Loki / Promtail config:**

```yaml
- job_name: openvpn_proxy
  static_configs:
    - targets: [localhost]
      labels:
        job: openvpn_proxy
        __path__: /var/lib/docker/containers/*/*-json.log
  pipeline_stages:
    - json:
        expressions:
          level: level
          component: component
    - labels:
        level:
        component:
```

---

## Capability Drop (Optional)

Enable with `DROP_CAPS=true`. After all services have started (first cycle only), the supervisor process drops all Linux capabilities from its bounding set **except**:

- `CAP_NET_ADMIN` (`12`) — required for iptables, ip route, tunnel management
- `CAP_NET_RAW` (`13`) — required for ping, healthcheck

Implementation uses `python3` + `ctypes` to call `prctl(PR_CAPBSET_DROP, cap)` directly on the **current process** (bash). This is the only reliable method — `capsh --drop` only affects child processes.

```yaml
DROP_CAPS: "true"
```

> **Note:** This only affects the supervisor bash process itself — child processes (OpenVPN, unbound, Privoxy, etc.) that were already started retain their own capabilities. If `python3` is missing, the drop is skipped gracefully (logged as WARN).

---

## Proxy Authentication (Optional)

By default, Privoxy listens on `0.0.0.0:3128` with **no authentication** — any client that can reach the port can use it. This is fine for isolated Docker networks or localhost-only setups.

When you set both `PROXY_USER` and `PROXY_PASS`, the container automatically activates **HTTP Basic Authentication**:

```
Client → nginx :3128 (Basic Auth check) → Privoxy 127.0.0.1:3129 → VPN tunnel
```

- **nginx** acts as an authenticating reverse proxy on port `3128` (the only publicly exposed port)
- **Privoxy** is moved to `127.0.0.1:3129` — unreachable from outside the container
- Passwords are hashed with **bcrypt** via `htpasswd` at container startup
- The `Authorization` header is stripped before forwarding to Privoxy

### Enabling authentication

```bash
docker run \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  -e PROXY_USER="alice" \
  -e PROXY_PASS="s3cr3t!" \
  -v ./vpn:/vpn:ro \
  -p 3128:3128 \
  titidnh/openvpn_client_proxy:latest
```

Or in Docker Compose:

```yaml
environment:
  PROXY_USER: "alice"
  PROXY_PASS: "s3cr3t!"
```

### Using the authenticated proxy

```bash
# curl
curl --proxy http://alice:s3cr3t!@127.0.0.1:3128 https://api.ipify.org

# wget
http_proxy=http://alice:s3cr3t!@127.0.0.1:3128 wget -qO- https://api.ipify.org

# Environment variables
export HTTP_PROXY="http://alice:s3cr3t!@127.0.0.1:3128"
export HTTPS_PROXY="http://alice:s3cr3t!@127.0.0.1:3128"
```

> ⚠️ HTTP Basic Auth transmits credentials in base64 (not encrypted). Always combine with a network-level control (localhost binding, Docker internal network) in production. Use a strong, unique password.

### Without authentication — hardening options

| Mitigation | How |
|---|---|
| **Localhost only** | `-p 127.0.0.1:3128:3128` — only local processes can connect |
| **Internal Docker network** | Place containers on a named bridge, do not publish port 3128 on the host |
| **Host firewall** | Allow port 3128 only from trusted IPs via `iptables` / `ufw` |

---

## Supervision & Auto-Restart

The container runs a built-in supervisor loop (`start.sh`) that polls all services every **10 seconds**:

| Condition | Action |
|---|---|
| OpenVPN process died | Kills and restarts OpenVPN only. Waits up to 5s for routing. If restored → continue normally. If not → full restart. |
| OpenVPN routing still broken after restart | Full service restart (dnsmasq + iptables + Privoxy + nginx + OpenVPN + Tailscale) |
| Privoxy not listening on its port | Full service restart |
| nginx auth proxy died or not listening (if enabled) | Full service restart |
| dnsmasq process died | Full service restart |
| DNS resolution via `127.0.0.1` fails | Full service restart |
| Tailscale process died (if enabled) | Full service restart |
| unbound process died or not listening on `:5053` (if DoT enabled) | Full service restart |
| Metrics endpoint (`socat`) died (if metrics enabled) | Logged only — non-critical |
| DoT IP refresh loop died | Logged only — refreshed on next full restart cycle |

Restart delay uses **exponential backoff**: 5s, 10s, 15s, … capped at **60s**. The counter resets after a successful monitoring cycle.

---

## Healthcheck

The image declares a native `HEALTHCHECK` in the `Dockerfile` — no configuration needed:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1
```

`healthcheck.sh` runs the following checks in order:

1. **Sentinel file** — `/tmp/vpn_healthy` must exist. The supervisor writes it once the tunnel is confirmed up, and removes it on failure.
2. **VPN server reachability** — reads `remote` and `proto` from `vpn.conf` and probes the VPN endpoint via `nc` (TCP or UDP).
3. **Fallback via Privoxy** — if the VPN probe is inconclusive, attempts an HTTP request through `http://127.0.0.1:3128`. Success confirms the tunnel and proxy are both working.

Everything is self-contained — `nc`, `curl`, and `openvpn` are all installed in the image.

---

## Tailscale Integration (Optional)

Tailscale is installed inside the image by default. The supervisor checks for `tailscaled` at startup and silently skips it if `ENABLE_TAILSCALE` is not `true`.

### Basic Tailscale usage

```sh
docker run \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --rm \
  -e ENABLE_TAILSCALE=true \
  -e TAILSCALE_AUTHKEY="tskey-auth-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -v ./vpn:/vpn:ro \
  -p 3128:3128 \
  titidnh/openvpn_client_proxy:latest
```

### Tailscale as a VPN exit node

When `TAILSCALE_ADVERTISE_EXIT_NODE=true`, all Tailscale clients that select this node as their exit will have their traffic routed through the OpenVPN tunnel.

> **Note:** This requires kernel IP forwarding. Pass the sysctls at the container/compose level.

```sh
docker run \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --rm \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -e ENABLE_TAILSCALE=true \
  -e TAILSCALE_AUTHKEY="tskey-auth-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  -e TAILSCALE_ADVERTISE_EXIT_NODE=true \
  -e TAILSCALE_HOSTNAME="my-vpn-exit-node" \
  -v ./vpn:/vpn:ro \
  -p 3128:3128 \
  titidnh/openvpn_client_proxy:latest
```

After the container starts, **approve the exit node** in the Tailscale admin console (or pass `--advertise-exit-node` via `TAILSCALE_FLAGS` if auto-approval is enabled on your tailnet).

### Persist Tailscale identity

Mount the `/var/lib/tailscale` volume so the node doesn't re-authenticate on every container recreation:

```yaml
volumes:
  - tailscale-state:/var/lib/tailscale
  - ./vpn:/vpn:ro
```

---

## Docker Compose Examples

### Minimal — OpenVPN + Proxy only

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    container_name: vpn_proxy
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 128M
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    volumes:
      - ./vpn:/vpn:ro
    ports:
      # Bind to localhost only — prevents external machines from using the proxy
      - "127.0.0.1:3128:3128"
    environment:
      DNS_SERVER_1: "94.140.14.14"
      DNS_SERVER_2: "94.140.15.15"
```

### With proxy authentication

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    container_name: vpn_proxy
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 192M   # nginx frontal requires a bit more memory
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    volumes:
      - ./vpn:/vpn:ro
    ports:
      - "3128:3128"   # safe to expose publicly — auth required
    environment:
      PROXY_USER: "alice"
      PROXY_PASS: "s3cr3t!"
      DNS_SERVER_1: "94.140.14.14"
      DNS_SERVER_2: "94.140.15.15"
```

### With DNS-over-TLS + Metrics + Capability Drop

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    container_name: vpn_proxy
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 128M
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    volumes:
      - ./vpn:/vpn:ro
      # Optional: certificate pinning for DoT
      # - ./my-dot-ca.pem:/vpn/dot-ca.pem:ro
    ports:
      - "127.0.0.1:3128:3128"
    environment:
      ENABLE_DOT: "true"
      DOT_DNS_SERVERS: "tls://dns.adguard-dns.com tls://cloudflare-dns.com"
      DOT_IP_REFRESH_INTERVAL: "3600"
      ENABLE_DNSSEC: "false"
      # DOT_TLS_CERT_BUNDLE: "/vpn/dot-ca.pem"
      # DNS_SPLIT: "corp.local=10.0.0.53"
      ENABLE_METRICS: "true"
      DROP_CAPS: "true"
```

### Full — OpenVPN + Proxy auth + Tailscale exit node

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    container_name: vpn_proxy
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 256M   # Tailscale + nginx require extra memory
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv6.conf.all.forwarding: "1"
    volumes:
      - ./vpn:/vpn:ro
      - tailscale-state:/var/lib/tailscale
    ports:
      - "3128:3128"
    environment:
      ENABLE_TAILSCALE: "true"
      TAILSCALE_AUTHKEY: "tskey-auth-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      TAILSCALE_HOSTNAME: "my-vpn-exit-node"
      TAILSCALE_ADVERTISE_EXIT_NODE: "true"
      PROXY_USER: "alice"
      PROXY_PASS: "s3cr3t!"
      DNS_SERVER_1: "94.140.14.14"
      DNS_SERVER_2: "94.140.15.15"

volumes:
  tailscale-state:
```

### Multi-container — Another container routing through the VPN

Route another service's traffic through the VPN without giving it `NET_ADMIN`:

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    container_name: vpn_proxy
    restart: unless-stopped
    mem_limit: 128M
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    volumes:
      - ./vpn:/vpn:ro
    ports:
      - "3128:3128"

  myapp:
    image: curlimages/curl:latest
    depends_on:
      vpnproxy:
        condition: service_healthy
    environment:
      # Without auth:
      HTTP_PROXY: "http://vpn_proxy:3128"
      HTTPS_PROXY: "http://vpn_proxy:3128"
      # With auth:
      # HTTP_PROXY: "http://alice:s3cr3t!@vpn_proxy:3128"
      # HTTPS_PROXY: "http://alice:s3cr3t!@vpn_proxy:3128"
    command: ["curl", "-s", "https://api.ipify.org"]
```

---

## Build

Build the image locally:

```sh
docker build -t openvpn-client-proxy:latest .
```

Build for multiple architectures (requires Buildx):

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t openvpn-client-proxy:latest \
  --push .
```

You can pin the Tailscale version at build time:

```sh
docker build --build-arg TAILSCALE_VERSION=1.80.3 -t openvpn-client-proxy:latest .
```

The CI/CD pipeline (`.github/workflows/docker-publish.yml`) automatically builds and pushes to Docker Hub on every push to `main` or on version tags (`v*`).

---

## Using the Proxy

Once the container is running and healthy, configure any HTTP-proxy-aware client to use `http://127.0.0.1:3128`.

If authentication is enabled (`PROXY_USER` + `PROXY_PASS`), include the credentials in the proxy URL: `http://user:pass@127.0.0.1:3128`.

### curl

```sh
# Without auth
curl --proxy http://127.0.0.1:3128 https://api.ipify.org

# With auth
curl --proxy http://alice:s3cr3t!@127.0.0.1:3128 https://api.ipify.org
```

### wget

```sh
# Without auth
http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128 \
  wget -qO- https://api.ipify.org

# With auth
http_proxy=http://alice:s3cr3t!@127.0.0.1:3128 \
https_proxy=http://alice:s3cr3t!@127.0.0.1:3128 \
  wget -qO- https://api.ipify.org
```

### Environment variables (Linux/macOS)

```sh
export HTTP_PROXY="http://127.0.0.1:3128"
export HTTPS_PROXY="http://127.0.0.1:3128"
export NO_PROXY="localhost,127.0.0.1"
```

### Browser (Firefox)

Go to **Settings → Network Settings → Manual proxy configuration**:
- HTTP Proxy: `127.0.0.1` — Port: `3128`
- Check **Also use this proxy for HTTPS**

If auth is enabled, Firefox will prompt for credentials on first use.

### Python (requests)

```python
import requests

proxies = {
    "http":  "http://127.0.0.1:3128",       # or http://alice:s3cr3t!@127.0.0.1:3128
    "https": "http://127.0.0.1:3128",
}

r = requests.get("https://api.ipify.org", proxies=proxies)
print(r.text)  # → your VPN exit IP
```

---

## Troubleshooting

### The container starts but `curl` returns no IP / connection refused

1. Check that the VPN tunnel is up: `docker logs vpn_proxy | grep "public IP via VPN"`
2. Verify the sentinel file exists: `docker exec vpn_proxy ls /tmp/vpn_healthy`
3. Confirm the proxy is listening: `docker exec vpn_proxy nc -z 127.0.0.1 3128 && echo OK`

### `407 Proxy Authentication Required`

Auth is enabled but credentials are missing from the proxy URL. Add `user:pass@` to the URL:

```sh
curl --proxy http://alice:s3cr3t!@127.0.0.1:3128 https://api.ipify.org
```

Verify nginx started correctly:

```sh
docker logs vpn_proxy | grep nginx
docker exec vpn_proxy nginx -t -c /etc/nginx/nginx_proxy_auth.conf
```

### `tun: Operation not permitted`

The host kernel is missing the `tun` module or `/dev/net/tun` is not available:

```sh
modprobe tun
ls -la /dev/net/tun   # should show crw-rw-rw-
```

If using Synology NAS or similar, enable the TUN driver in the kernel module management.

### `AUTH_FAILED` or `TLS handshake failed`

- Double-check `vpn.auth` — no extra spaces, correct username/password on separate lines
- Verify that `ca.crt`, `client.crt`, `client.key` are present in `/vpn` if referenced by `vpn.conf`
- Test the config outside Docker: `sudo openvpn --config vpn.conf`

### DNS not resolving inside the container

```sh
docker exec vpn_proxy nslookup example.com 127.0.0.1
```

If it fails, test the dnsmasq configuration:

```sh
docker exec vpn_proxy dnsmasq --test --conf-file=/etc/dnsmasq.conf
```

### `/etc/resolv.conf` is read-only

The entrypoint handles this automatically via `mount --bind`. If it still fails, check your Docker runtime's `--read-only` or `--mount` flags.

### DoT not working / DNS resolution fails with `ENABLE_DOT=true`

Check that unbound started and is listening:

```sh
docker logs <container> | grep unbound
docker exec <container> nc -z 127.0.0.1 5053 && echo "unbound OK"
```

Test the DoT chain directly:

```sh
# Should resolve via dnsmasq → unbound → DoT server
docker exec <container> nslookup example.com 127.0.0.1

# Should FAIL — external port 53 is blocked when DoT is active
docker exec <container> nslookup example.com 8.8.8.8
```

Check the generated unbound config:

```sh
docker exec <container> cat /etc/unbound/unbound.conf
docker exec <container> unbound-checkconf /etc/unbound/unbound.conf
```

### DNSSEC failures (`SERVFAIL` on valid domains)

If `ENABLE_DNSSEC=true` causes resolution failures, the domain is likely not DNSSEC-signed or the root key is stale. Disable strict mode:

```yaml
ENABLE_DNSSEC: "false"
```

Or re-initialise the root trust anchor:

```sh
docker exec <container> unbound-anchor -a /var/lib/unbound/root.key -v
```

### Metrics endpoint not responding

```sh
# Check socat is running
docker exec <container> ps aux | grep socat

# Test directly inside the container
docker exec <container> curl -s http://127.0.0.1:9100/metrics

# Check startup log
docker logs <container> | grep metrics
```

### Capability drop errors

```sh
docker logs <container> | grep drop_caps
```

If `python3` is missing, the drop is skipped gracefully (logged as WARN). The container remains fully functional.

### Tailscale not starting

```sh
docker logs vpn_proxy | grep tailscale
```

Make sure `ENABLE_TAILSCALE=true` and a valid, non-expired `TAILSCALE_AUTHKEY` is provided.

---

## Project File Reference

| File | Location in container | Description |
|---|---|---|
| `start.sh` | `/start.sh` | Main entrypoint — supervisor, iptables setup, service orchestration, JSON logging, metrics, DoT IP refresh, capability drop |
| `openvpn.sh` | `/usr/local/bin/openvpn.sh` | Thin wrapper: `openvpn --cd /vpn --config /vpn/vpn.conf` |
| `healthcheck.sh` | `/usr/local/bin/healthcheck.sh` | Container healthcheck script |
| `privoxy.config` | `/etc/privoxy/privoxy.config` | Privoxy HTTP proxy main config |
| `default.action` | `/etc/privoxy/default.action` | Privoxy default action rules |
| `user.action` | `/etc/privoxy/user.action` | Privoxy user-defined action overrides |
| `default.filter` | `/etc/privoxy/default.filter` | Privoxy default content filters |
| `user.filter` | `/etc/privoxy/user.filter` | Privoxy user-defined content filters |
| `Dockerfile` | — | Multi-stage build: `alpine:3.20` base + Tailscale binary stage |
| `docker-compose.yml` | — | Full example compose file with all options |
| `.github/workflows/docker-publish.yml` | — | CI/CD — builds and pushes to Docker Hub on `main` and `v*` tags |

**Volume mounts:**

| Mount | Usage |
|---|---|
| `/vpn` | **Required** — place `vpn.conf`, `vpn.auth`, and any cert files here (mounted read-only) |
| `/var/lib/tailscale` | Optional — persist Tailscale identity across container recreations |

---

## Roadmap

### 🔐 Security & Privacy

| Idea | Status |
|---|---|
| DNSSEC validation | ✅ Implemented — `ENABLE_DNSSEC=true` |
| DoT certificate pinning | ✅ Implemented — `DOT_TLS_CERT_BUNDLE` |
| DNS-over-HTTPS (DoH) | ✅ Implemented — `https://` prefix in `DOT_DNS_SERVERS` |
| Drop capabilities | ✅ Implemented — `DROP_CAPS=true` |
| Proxy TLS (HTTPS proxy) | 💡 Expose the proxy over TLS to protect credentials in transit (nginx TLS terminator + mounted certificate) |
| Read-only filesystem | 💡 `--read-only` flag with targeted tmpfs mounts to reduce attack surface |

### 🧰 Operational & Reliability

| Idea | Status |
|---|---|
| Dynamic DoT IP refresh | ✅ Implemented — `DOT_IP_REFRESH_INTERVAL` |
| Prometheus metrics | ✅ Implemented — `ENABLE_METRICS=true` |
| Structured JSON logs | ✅ Implemented |
| Split DNS | ✅ Implemented — `DNS_SPLIT` |
| Graceful reload via `SIGHUP` | 💡 Reload dnsmasq/unbound config without a full restart |
| Lightweight OpenVPN reconnect | 💡 Attempt `SIGUSR1` reconnect before triggering a full supervisor restart |

### 🐳 Docker & Deployment

| Idea | Status |
|---|---|
| Docker secrets support | 💡 Read `PROXY_PASS` / `TAILSCALE_AUTHKEY` from `/run/secrets/` to avoid secrets in `docker inspect` |
| ARM32v7 support | 💡 Add `linux/arm/v7` for older Raspberry Pi models |
| Healthcheck via DoT | 💡 Verify the full resolver chain (dnsmasq → unbound) when DoT is enabled |
| Config validation at startup | 💡 Pre-flight check on all env vars with fast-fail and clear error messages |

### 🌐 Proxy Features

| Idea | Status |
|---|---|
| SOCKS5 proxy | 💡 Expose a SOCKS5 proxy (`dante` or `microsocks`) in addition to HTTP — supports UDP and broader app compatibility |
| Per-container proxy routing | 💡 Use Privoxy `forward` directives to split-tunnel specific domains at the proxy level |
| Bandwidth / connection limits | 💡 nginx rate limiting to prevent a single client from saturating the VPN uplink |

---

## License

See the [LICENSE](LICENSE) file in this repository.
