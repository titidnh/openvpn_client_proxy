# OpenVPN Client Proxy (Privoxy + AdGuard Family DNS)

Lightweight Docker image that runs an OpenVPN client together with a local HTTP proxy (Privoxy) and a local DNS resolver (dnsmasq) configured to use AdGuard Family DNS. The container is intended to provide a per-container VPN client that also blocks ads and adult content via DNS filtering.

**Features**
- OpenVPN client (configured with files placed in /vpn)
- HTTP proxy using Privoxy for local filtering
- Local DNS resolver (dnsmasq) using AdGuard Family upstream servers
- Minimal, optimized Alpine-based image

**Build**

Build the image from the repository root:

```sh
docker build -t openvpn-client-proxy:latest .
```

**Run (basic example)**

Provide your OpenVPN client configuration as /vpn/vpn.conf inside the container. The simplest way is to mount a host directory containing your OpenVPN files to `/vpn`:

```sh
docker run --cap-add=NET_ADMIN --device /dev/net/tun --rm \
  --memory 128MB --health-interval=30s --health-timeout=5s --health-retries=3 \
  -v /path/to/vpn:/vpn:ro \
  -p 3128:3128 openvpn-client-proxy:latest
```

Make sure the mounted directory contains `vpn.conf` (or rename your .ovpn to `vpn.conf`). If your provider requires username/password authentication, include a `vpn.auth` file in the same folder (first line username, second line password) and reference it from your configuration with `auth-user-pass vpn.auth`.

Notes:
- The container needs NET_ADMIN and access to /dev/net/tun to create the VPN tunnel.
- Privoxy listens on port 3128 by default (exposed in the Dockerfile).

**Configuration files (in repository)**
- dnsmasq.conf: upstream DNS servers (AdGuard Family). Change these addresses if you want another upstream.
- start.sh: container entrypoint that starts dnsmasq, OpenVPN, and Privoxy.
- openvpn.sh: simplified OpenVPN entry script (reads config from /vpn).
- privoxy.*: Privoxy configuration files under /etc/privoxy inside the image.

**Environment / runtime options**
- The entrypoint expects your OpenVPN configuration at `/vpn/vpn.conf` (or an .ovpn file mounted to that path).
- If you need username/password authentication create `/vpn/vpn.auth` with two lines: username then password, and reference it from your .conf (e.g. `auth-user-pass vpn.auth`).
- DNS is handled inside the container by `dnsmasq` (AdGuard Family upstreams). The image already configures `/etc/resolv.conf` to point to the local resolver at container start.

Tailscale integration (optional)
------------------------------

This image can optionally install and run Tailscale when `ENABLE_TAILSCALE` is set to `true` at container runtime. The following environment variables control Tailscale behavior:

- `ENABLE_TAILSCALE` (default: `false`): when `true`, the container attempts to install Tailscale and bring it up.
- `TAILSCALE_AUTHKEY` (default: empty): a pre-authentication key to perform a non-interactive `tailscale up --authkey <key>`.
- `TAILSCALE_FLAGS` (default: empty): additional flags to append to `tailscale up`.
- `TAILSCALE_ACCEPT_ROUTES` (default: `false`): when `true`, `--accept-routes` is added to `tailscale up` to accept routes advertised by other nodes.

Behavior notes:
- The startup script will install Tailscale if necessary using the official installer script and will attempt to start `tailscaled` before running `tailscale up`.
- `tailscale set --advertise-exit-node` is executed after a successful `tailscale up` to advertise this container as an exit node (idempotent).
- The container will enable kernel IP forwarding via sysctl to support exit-node routing.
- Provide `TAILSCALE_AUTHKEY` for non-interactive deployments. If omitted, `tailscale up` may require interactive authentication.

Example run enabling Tailscale with an auth key and accepting routes:

```sh
docker run --cap-add=NET_ADMIN --device /dev/net/tun --rm \
  -e ENABLE_TAILSCALE=true \
  -e TAILSCALE_AUTHKEY="tskey-xxx" \
  -e TAILSCALE_ACCEPT_ROUTES=true \
  -v /path/to/vpn:/vpn:ro \
  -p 3128:3128 openvpn-client-proxy:latest
```

Runtime Tailscale installation
------------------------------

Tailscale is installed and configured at container startup when `ENABLE_TAILSCALE` is set to `true`. The startup script (`start.sh`) performs the following, idempotently:

- Installs Tailscale at runtime if the `tailscale` binary is not present (uses the official installer script). `curl` or `wget` will be used if available; `curl` is installed temporarily if needed and removed after the installer.
- Enables kernel IP forwarding via sysctl (writes files under `/etc/sysctl.d` or updates `/etc/sysctl.conf` only when necessary).
- Starts `tailscaled` if needed, runs `tailscale up` (supports non-interactive auth via `TAILSCALE_AUTHKEY`, accepts additional flags via `TAILSCALE_FLAGS`, and supports `--accept-routes` via `TAILSCALE_ACCEPT_ROUTES`).
- Waits for the Tailscale interface to become ready, then runs `tailscale set --advertise-exit-node` to advertise an exit node (idempotent).

Environment variables (runtime):

- `ENABLE_TAILSCALE` (default: `false`): set to `true` to enable runtime Tailscale install/configuration.
- `TAILSCALE_AUTHKEY`: optional pre-shared auth key for non-interactive `tailscale up`.
- `TAILSCALE_FLAGS`: extra flags appended to `tailscale up`.
- `TAILSCALE_ACCEPT_ROUTES` (default: `false`): when `true`, `--accept-routes` is added to `tailscale up`.
- `TAILSCALE_HOSTNAME`: optional hostname to register for this machine in Tailscale (passed to `tailscale up --hostname`).

Example run enabling Tailscale with an auth key and accepting routes:

```sh
docker run --cap-add=NET_ADMIN --device /dev/net/tun --rm \
  -e ENABLE_TAILSCALE=true \
  -e TAILSCALE_AUTHKEY="tskey-xxx" \
  -e TAILSCALE_ACCEPT_ROUTES=true \
  -v /path/to/vpn:/vpn:ro \
  -p 3128:3128 openvpn-client-proxy:latest
```

Notes:
- The installer runs at container start when `ENABLE_TAILSCALE=true`; this keeps the base image small by default but adds startup latency when installing at runtime.
- The startup script attempts to keep the install idempotent and will clean temporary packages/artifacts it created during installation.

**Notes & caveats**
- The image is intentionally minimal. If you need advanced debugging tools (curl, iputils, etc.) add them in a derived Dockerfile.
- Overwriting /etc/resolv.conf is performed at container start to point at the local dnsmasq. If your Docker runtime or host locks resolv.conf, adapt the startup to use OpenVPN up/down hooks to update DNS.
- Firewalling was removed to keep the image small; if you need per-container firewall policies add them on the host or reintroduce iptables rules.

**Where to tweak DNS blocking**
- To change or extend the blocking upstreams, edit dnsmasq.conf in the repo. It currently uses AdGuard Family servers (blocks adult content + ads).

**License**
See repository LICENSE file.

**Docker Compose (example)**

The following `docker-compose.yml` shows a minimal example for running the image:

```yaml
services:
  vpnproxy:
    image: titidnh/openvpn_client_proxy:latest
    network_mode: bridge
    container_name: vpn_proxy
    restart: always
    mem_limit: 128M
    cap_add:
      - NET_ADMIN
    devices:
      - "/dev/net/tun"
    healthcheck:
      interval: 30s
      timeout: 5s
      retries: 3
    volumes:
      - ./data:/vpn:ro
    ports:
      - "3128:3128"
    environment:
      # By default Tailscale is disabled in the container (keeps image small).
      ENABLE_TAILSCALE: "false"
      # Optional: provide a pre-auth key for non-interactive tailscale up
      # TAILSCALE_AUTHKEY: "tskey-xxx"
      # Optional: accept routes advertised by other nodes
      # TAILSCALE_ACCEPT_ROUTES: "false"
      # Optional: set the Tailscale machine hostname (no spaces)
      # TAILSCALE_HOSTNAME: "my-vpn-node"
      # Additional flags to append to `tailscale up` (optional)
      # TAILSCALE_FLAGS: "--os=linux"

    # Example to enable Tailscale at runtime, uncomment and set values above.
```
