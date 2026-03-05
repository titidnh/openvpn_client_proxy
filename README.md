# OpenVPN Client Proxy (Privoxy + AdGuard Family DNS)

Lightweight Docker image that runs an OpenVPN client together with a local HTTP proxy (Privoxy) and a local DNS resolver (`dnsmasq`) configured to use AdGuard Family DNS. The container provides a per-container VPN client that also blocks ads and adult content via DNS filtering.

**Features**
- OpenVPN client (configured with files placed in `/vpn`)
- HTTP proxy using Privoxy for local filtering
- Local DNS resolver (`dnsmasq`) using AdGuard Family upstream servers
- **Network kill switch** — iptables DROP by default; all traffic is blocked if the VPN tunnel goes down
- **DNS leak protection** — all DNS queries are forced through `dnsmasq`; no process can reach an external resolver directly
- Automatic VPN reconnection with exponential backoff supervision
- Optional Tailscale integration with exit-node support
- Debian-slim based, minimal image

---

## Build

```sh
docker build -t openvpn-client-proxy:latest .
```

---

## Run (basic example)

Provide your OpenVPN client configuration as `vpn.conf` inside the mounted `/vpn` directory:

```sh
docker run --cap-add=NET_ADMIN --device /dev/net/tun --rm \
  --memory 128MB \
  -v /path/to/vpn:/vpn:ro \
  -p 3128:3128 openvpn-client-proxy:latest
```

**Requirements:**
- The container needs `NET_ADMIN` capability and access to `/dev/net/tun` to create the VPN tunnel.
- The mounted directory must contain `vpn.conf` (or rename your `.ovpn` file to `vpn.conf`).
- If your provider requires username/password authentication, include a `vpn.auth` file in the same folder (first line: username, second line: password) and reference it from your config with `auth-user-pass vpn.auth`.
- Privoxy listens on port `3128` by default inside the container.

---

## Configuration files

| File | Description |
|------|-------------|
| `dnsmasq.conf` | Upstream DNS servers (AdGuard Family). Edit to change resolver. |
| `start.sh` | Container entrypoint — starts `dnsmasq`, configures iptables kill switch, then starts Privoxy, OpenVPN and optionally Tailscale. Supervises all processes and restarts on failure. |
| `openvpn.sh` | OpenVPN entry script (reads config from `/vpn`). |
| `privoxy.*` | Privoxy configuration files under `/etc/privoxy` inside the image. |

---

## Network kill switch

At startup, `start.sh` configures iptables (IPv4 and IPv6) with a **DROP-by-default** policy:

- All outbound traffic is blocked except through the VPN tunnel (`tun+`/`tap+`)
- DNS is only allowed to `127.0.0.1:53` (local `dnsmasq`) and the upstream servers declared in `dnsmasq.conf`
- If the VPN tunnel goes down, internet traffic is blocked — nothing leaks in plaintext
- OpenVPN reconnects automatically; if it cannot recover, all services are restarted with exponential backoff (5s, 10s … capped at 60s)

---

## Supervision behavior

The entrypoint runs a built-in supervisor that monitors all services every 10 seconds:

- **OpenVPN down** → attempts a lightweight restart (without touching the firewall). If routing is restored within 5 seconds, monitoring resumes normally.
- **Routing still broken** → full restart of all services (dnsmasq, iptables, Privoxy, OpenVPN, Tailscale).
- **Privoxy or dnsmasq down** → full restart.
- **Tailscale down** (if enabled) → full restart.

---

## Healthcheck

The image declares a healthcheck interval and timeout but does not define a `test` command by default. To add a meaningful check, override it in your `docker-compose.yml`:

```yaml
healthcheck:
  test: ["CMD", "nc", "-z", "-w", "3", "127.0.0.1", "3128"]
  interval: 30s
  timeout: 5s
  retries: 3
```

---

## Tailscale integration (optional)

Tailscale must be installed inside the image for this feature to work. The entrypoint checks for the presence of `tailscaled` at startup and skips silently if it is not found.

The following environment variables control Tailscale behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_TAILSCALE` | `false` | Set to `true` to start `tailscaled` at container startup |
| `TAILSCALE_AUTHKEY` | *(empty)* | Pre-auth key for non-interactive `tailscale up` |
| `TAILSCALE_FLAGS` | *(empty)* | Extra flags appended to `tailscale up` |
| `TAILSCALE_ACCEPT_ROUTES` | `false` | Adds `--accept-routes` to `tailscale up` |
| `TAILSCALE_HOSTNAME` | *(empty)* | Hostname to register in Tailscale (`--hostname`) |
| `TAILSCALE_ADVERTISE_EXIT_NODE` | `false` | Advertise this container as a Tailscale exit node |

When `TAILSCALE_ADVERTISE_EXIT_NODE=true`, all traffic from your Tailscale devices is forwarded through the VPN tunnel — iptables FORWARD and NAT rules are already configured for this.

> **Note:** enabling `TAILSCALE_ADVERTISE_EXIT_NODE` requires kernel IP forwarding. Pass the sysctls at the compose/runtime level (see example below); setting them from inside the container may be restricted by your runtime.

### Example — Tailscale with auth key and exit node:

```sh
docker run --cap-add=NET_ADMIN --device /dev/net/tun --rm \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  -e ENABLE_TAILSCALE=true \
  -e TAILSCALE_AUTHKEY="tskey-xxx" \
  -e TAILSCALE_ADVERTISE_EXIT_NODE=true \
  -v /path/to/vpn:/vpn:ro \
  -p 3128:3128 openvpn-client-proxy:latest
```

---

## Docker Compose example

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
    healthcheck:
      test: ["CMD", "nc", "-z", "-w", "3", "127.0.0.1", "3128"]
      interval: 30s
      timeout: 5s
      retries: 3
    volumes:
      - ./data:/vpn:ro
    ports:
      - "3128:3128"
    environment:
      ENABLE_TAILSCALE: "false"
      # TAILSCALE_AUTHKEY: "tskey-xxx"
      # TAILSCALE_ACCEPT_ROUTES: "false"
      # TAILSCALE_HOSTNAME: "my-vpn-node"
      # TAILSCALE_ADVERTISE_EXIT_NODE: "false"
    # Required if TAILSCALE_ADVERTISE_EXIT_NODE=true
    # sysctls:
    #   net.ipv4.ip_forward: "1"
    #   net.ipv6.conf.all.forwarding: "1"
```

---

## Where to tweak DNS blocking

Edit `dnsmasq.conf` in the repository. It currently uses AdGuard Family servers (blocks ads + adult content). Replace the `server=` entries with any resolver of your choice.

---

## Notes & caveats

- `/etc/resolv.conf` is overwritten at container start to point at local `dnsmasq`. If your Docker runtime mounts it read-only, the entrypoint falls back to a `mount --bind` from `/tmp`.
- The image is intentionally minimal. Add debugging tools (`curl`, `iputils`, etc.) in a derived Dockerfile if needed.
- iptables rules are configured by `start.sh` on every startup (including after a supervised restart). Do not rely on host-level rules surviving a container restart.

---

## License

See repository LICENSE file.
