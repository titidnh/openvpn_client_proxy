# OpenVPN Client Proxy

> **Lightweight Docker container** running an OpenVPN client, an HTTP proxy ([Privoxy](https://www.privoxy.org/)), and a local DNS resolver ([dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html)) with AdGuard Family DNS — featuring a network **kill switch**, **DNS leak protection**, and optional **Tailscale** integration.

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
- [Supervision & Auto-Restart](#supervision--auto-restart)
- [Healthcheck](#healthcheck)
- [Tailscale Integration (Optional)](#tailscale-integration-optional)
- [Docker Compose Examples](#docker-compose-examples)
- [Build](#build)
- [Using the Proxy](#using-the-proxy)
- [Troubleshooting](#troubleshooting)
- [Project File Reference](#project-file-reference)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| 🔒 **VPN Kill Switch** | iptables DROP policy by default — all traffic is blocked if the tunnel drops |
| 🛡️ **DNS Leak Protection** | All DNS queries are forced through local `dnsmasq` — no external resolver bypass possible |
| 🔁 **Auto-Reconnect** | Built-in supervisor with exponential backoff (5s → 60s cap) restarts services on failure |
| 🌐 **HTTP Proxy** | Privoxy on port `3128` — usable by any app or container that supports HTTP proxies |
| 🧹 **Ad/Content Filtering** | AdGuard Family DNS blocks ads and adult content at the DNS level |
| 🐳 **Multi-arch** | Docker image published for `linux/amd64` and `linux/arm64` |
| 🔗 **Tailscale Exit Node** | Optional — route your entire Tailscale network through the VPN tunnel |
| 📦 **Minimal Image** | Based on `debian:trixie-slim` — small footprint, no unnecessary tools |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                  Docker Container                    │
│                                                      │
│  ┌─────────┐   ┌──────────┐   ┌──────────────────┐   │
│  │ dnsmasq │   │ Privoxy  │   │    OpenVPN       │   │
│  │  :53    │   │  :3128   │   │  (tun0 / tap0)   │   │
│  └────┬────┘   └────┬─────┘   └────────┬─────────┘   │
│       │             │                  │             │
│       └─────────────┴──────────────────┘             │
│                    iptables                          │
│          (DROP default — VPN-only egress)            │
│                       │                              │
└───────────────────────┼──────────────────────────────┘
                        │ VPN Tunnel
                        ▼
                  VPN Server (remote)
                        │
                        ▼
                   Internet
```

- **dnsmasq** listens on `127.0.0.1:53` and forwards queries to AdGuard Family DNS (`94.140.14.15`, `94.140.15.16`). No app inside or outside the container can reach another resolver.
- **Privoxy** listens on `0.0.0.0:3128` and routes all HTTP/HTTPS traffic through the VPN tunnel.
- **iptables** enforces a DROP-everything-by-default policy. Only traffic going out via `tun+` / `tap+` is allowed.
- **start.sh** is the entrypoint supervisor — it starts all services, watches them every 10 seconds, and restarts on failure.

---

## Prerequisites

- Docker Engine ≥ 20.10 (or Docker Desktop)
- A valid OpenVPN configuration file (`.ovpn` or `.conf`)
- The host kernel must have the `tun` module loaded: `modprobe tun`
- `NET_ADMIN` capability and access to `/dev/net/tun`

---

## Quick Start

### 1. Prepare your VPN directory

Create a local directory (e.g. `./vpn-config/`) and place your files inside:

```
./vpn-config/
├── vpn.conf        ← required: your OpenVPN config (rename .ovpn → vpn.conf)
└── vpn.auth        ← optional: credentials file (username + password)
```

> See the [vpn.conf example](#vpnconf--openvpn-configuration) and [vpn.auth example](#vpnauth--credentials-file) below.

### 2. Run the container

```sh
docker run \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  --rm \
  --memory 128MB \
  -v ./vpn-config:/vpn:ro \
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

> ⚠️ Make sure the file permissions are restricted: `chmod 600 vpn.auth`

---

### `dnsmasq.conf` — DNS Resolver

Located at `/etc/dnsmasq.conf` inside the container (mapped from `dnsmasq.conf` in the repository root).

**Default configuration (AdGuard Family DNS):**

```ini
# Listen only on localhost
listen-address=127.0.0.1
bind-interfaces

# Do not read /etc/resolv.conf — only use the servers listed below
no-resolv

# AdGuard Family DNS — blocks ads + adult content
server=94.140.14.15
server=94.140.15.16

# DNS cache
cache-size=1000

# Silence dnsmasq logs (redirect to /dev/null for Docker)
log-facility=/dev/null
```

**Swap to a different DNS provider — examples:**

```ini
# Cloudflare (1.1.1.1) — no filtering
server=1.1.1.1
server=1.0.0.1

# Quad9 — security filtering (blocks malware/phishing, no adult filter)
server=9.9.9.9
server=149.112.112.112

# AdGuard Default DNS — blocks ads only (no adult content filter)
server=94.140.14.14
server=94.140.15.15

# Google DNS — no filtering
server=8.8.8.8
server=8.8.4.4
```

> Any `server=` IP declared here is automatically whitelisted in iptables by `start.sh` — no manual firewall changes needed.

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

---

## Environment Variables

All variables are optional. Defaults match a plain OpenVPN-only setup with no Tailscale.

| Variable | Default | Description |
|---|---|---|
| `ENABLE_TAILSCALE` | `false` | Set to `true` to start `tailscaled` at container startup |
| `TAILSCALE_AUTHKEY` | *(empty)* | Pre-auth key for non-interactive `tailscale up` |
| `TAILSCALE_FLAGS` | *(empty)* | Extra flags appended verbatim to `tailscale up` |
| `TAILSCALE_ACCEPT_ROUTES` | `false` | Pass `--accept-routes` to `tailscale up` |
| `TAILSCALE_HOSTNAME` | `openvpn-client-proxy` | Hostname registered in Tailscale (`--hostname`) |
| `TAILSCALE_ADVERTISE_EXIT_NODE` | `false` | Advertise this container as a Tailscale exit node — all Tailscale clients can route traffic through the VPN |

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

## Supervision & Auto-Restart

The container runs a built-in supervisor loop (`start.sh`) that polls all services every **10 seconds**:

| Condition | Action |
|---|---|
| OpenVPN process died | Lightweight OpenVPN restart. If routing is restored within 5s → continue normally |
| OpenVPN routing still broken after restart | Full service restart (dnsmasq + iptables + Privoxy + OpenVPN + Tailscale) |
| Privoxy not listening on port `3128` | Full service restart |
| dnsmasq process died | Full service restart |
| DNS resolution via `127.0.0.1` fails | Full service restart |
| Tailscale process died (if enabled) | Full service restart |

Restart delay uses **exponential backoff**: 5s, 10s, 15s, … capped at **60s**. The counter resets after a successful monitoring cycle.

---

## Healthcheck

The image declares a native `HEALTHCHECK` in the `Dockerfile` — no configuration needed:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1
```

`healthcheck.sh` runs the following checks in order:

1. **Sentinel file** — `/tmp/vpn_healthy` must exist. The supervisor writes it once the tunnel is confirmed up, and removes it on failure. Missing → immediate failure.
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
  -v ./vpn-config:/vpn:ro \
  -p 3128:3128 \
  titidnh/openvpn_client_proxy:latest
```

### Tailscale as a VPN exit node

When `TAILSCALE_ADVERTISE_EXIT_NODE=true`, all Tailscale clients that select this node as their exit will have their traffic routed through the OpenVPN tunnel.

> **Note:** This requires kernel IP forwarding. Pass the sysctls at the container/compose level — the container may not have permission to set them itself.

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
  -v ./vpn-config:/vpn:ro \
  -p 3128:3128 \
  titidnh/openvpn_client_proxy:latest
```

After the container starts, **approve the exit node** in the Tailscale admin console (or pass `--advertise-exit-node` via `TAILSCALE_FLAGS` if auto-approval is enabled on your tailnet).

### Persist Tailscale identity

Mount the `/var/lib/tailscale` volume so the node doesn't re-authenticate on every container recreation:

```yaml
volumes:
  - tailscale-state:/var/lib/tailscale
  - ./vpn-config:/vpn:ro
```

---

## Docker Compose Examples

### Minimal — OpenVPN + Proxy only

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    container_name: vpn_proxy
    restart: always
    mem_limit: 128M
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    volumes:
      - ./vpn-config:/vpn:ro
    ports:
      - "3128:3128"
```

### Full — OpenVPN + Proxy + Tailscale exit node

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    container_name: vpn_proxy
    restart: always
    mem_limit: 256M
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv6.conf.all.forwarding: "1"
    volumes:
      - ./vpn-config:/vpn:ro
      - tailscale-state:/var/lib/tailscale
    ports:
      - "3128:3128"
    environment:
      ENABLE_TAILSCALE: "true"
      TAILSCALE_AUTHKEY: "tskey-auth-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      TAILSCALE_HOSTNAME: "my-vpn-exit-node"
      TAILSCALE_ADVERTISE_EXIT_NODE: "true"
      # TAILSCALE_ACCEPT_ROUTES: "false"
      # TAILSCALE_FLAGS: "--shields-up"

volumes:
  tailscale-state:
```

### Multi-container — Another container using the VPN proxy

Route another service's traffic through the VPN without giving it `NET_ADMIN`:

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    container_name: vpn_proxy
    restart: always
    mem_limit: 128M
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    volumes:
      - ./vpn-config:/vpn:ro
    ports:
      - "3128:3128"

  myapp:
    image: curlimages/curl:latest
    depends_on:
      vpnproxy:
        condition: service_healthy
    environment:
      HTTP_PROXY: "http://vpn_proxy:3128"
      HTTPS_PROXY: "http://vpn_proxy:3128"
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

The CI/CD pipeline (`.github/workflows/docker-publish.yml`) automatically builds and pushes to Docker Hub on every push to `main` or on version tags (`v*`).

---

## Using the Proxy

Once the container is running and healthy, configure any HTTP-proxy-aware client to use `http://127.0.0.1:3128` (or `http://<host-ip>:3128` from another machine/container).

### curl

```sh
curl --proxy http://127.0.0.1:3128 https://api.ipify.org
```

### wget

```sh
http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128 \
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
- Check "Also use this proxy for HTTPS"

### Python (requests)

```python
import requests

proxies = {
    "http":  "http://127.0.0.1:3128",
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
3. Confirm Privoxy is listening: `docker exec vpn_proxy nc -z 127.0.0.1 3128 && echo OK`

### `tun: Operation not permitted`

The host kernel is missing the `tun` module or `/dev/net/tun` is not available. Run:

```sh
modprobe tun
ls -la /dev/net/tun   # should show crw-rw-rw-
```

If using Synology NAS or similar, enable the TUN driver in the kernel module management.

### `AUTH_FAILED` or `TLS handshake failed`

- Double-check `vpn.auth` — no extra spaces, correct username/password on separate lines.
- Verify that `ca.crt`, `client.crt`, `client.key` are present in `/vpn` if referenced by `vpn.conf`.
- Test the config outside Docker first: `sudo openvpn --config vpn.conf`

### DNS not resolving inside the container

```sh
docker exec vpn_proxy nslookup example.com 127.0.0.1
```

If it fails, check dnsmasq logs:

```sh
docker exec vpn_proxy dnsmasq --test --conf-file=/etc/dnsmasq.conf
```

### `/etc/resolv.conf` is read-only

The entrypoint handles this automatically via `mount --bind`. If it still fails, check your Docker runtime's `--read-only` or `--mount` flags.

### Tailscale not starting

```sh
docker logs vpn_proxy | grep tailscale
```

Make sure `ENABLE_TAILSCALE=true` and a valid `TAILSCALE_AUTHKEY` is provided. The key must not be expired.

---

## Project File Reference

| File | Location in container | Description |
|---|---|---|
| `start.sh` | `/start.sh` | Main entrypoint — supervisor, iptables setup, service orchestration |
| `openvpn.sh` | `/usr/local/bin/openvpn.sh` | Thin wrapper: `openvpn --cd /vpn --config /vpn/vpn.conf` |
| `healthcheck.sh` | `/usr/local/bin/healthcheck.sh` | Container healthcheck script |
| `dnsmasq.conf` | `/etc/dnsmasq.conf` | dnsmasq DNS resolver configuration |
| `privoxy.config` | `/etc/privoxy/privoxy.config` | Privoxy HTTP proxy main config |
| `default.action` | `/etc/privoxy/default.action` | Privoxy default action rules |
| `user.action` | `/etc/privoxy/user.action` | Privoxy user-defined action overrides |
| `default.filter` | `/etc/privoxy/default.filter` | Privoxy default content filters |
| `user.filter` | `/etc/privoxy/user.filter` | Privoxy user-defined content filters |
| `Dockerfile` | — | Image build definition (debian:trixie-slim base) |
| `.github/workflows/docker-publish.yml` | — | CI/CD — builds and pushes to Docker Hub on `main` and `v*` tags |

**Volume mounts:**

| Mount | Usage |
|---|---|
| `/vpn` | **Required** — place `vpn.conf`, `vpn.auth`, and any certs here (mounted read-only) |
| `/var/lib/tailscale` | Optional — persist Tailscale identity across container recreations |

---

## License

See the [LICENSE](LICENSE) file in this repository.