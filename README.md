# OpenVPN Client Proxy (Privoxy + AdGuard Family DNS)

Lightweight Docker image that runs an OpenVPN client together with a local HTTP proxy (Privoxy) and a local DNS resolver (`dnsmasq`) configured to use AdGuard Family DNS. The container provides a per-container VPN client that also blocks ads and adult content via DNS filtering.

**Features**
- OpenVPN client (configured with files placed in `/vpn`)
- HTTP proxy using Privoxy for local filtering
- Local DNS resolver (`dnsmasq`) using AdGuard Family upstream servers
- Debian-slim based, minimal image

## Build

Build the image from the repository root:

```sh
docker build -t openvpn-client-proxy:latest .
```

## Run (basic example)

Provide your OpenVPN client configuration as `/vpn/vpn.conf` inside the container. The simplest way is to mount a host directory containing your OpenVPN files to `/vpn`:

```sh
docker run --cap-add=NET_ADMIN --device /dev/net/tun --rm \
  --memory 128MB --health-interval=30s --health-timeout=5s --health-retries=3 \
  -v /path/to/vpn:/vpn:ro \
  -p 3128:3128 openvpn-client-proxy:latest
```

Make sure the mounted directory contains `vpn.conf` (or rename your `.ovpn` to `vpn.conf`). If your provider requires username/password authentication, include a `vpn.auth` file in the same folder (first line username, second line password) and reference it from your configuration with `auth-user-pass vpn.auth`.

Notes:
- The container needs `NET_ADMIN` and access to `/dev/net/tun` to create the VPN tunnel.
- Privoxy listens on port `3128` by default (binds inside the container; map the port as shown above).

## Configuration files (in repository)
- `dnsmasq.conf`: upstream DNS servers (AdGuard Family). Change these addresses if you want another upstream.
- `start.sh`: container entrypoint that starts `dnsmasq`, OpenVPN, and Privoxy.
- `openvpn.sh`: simplified OpenVPN entry script (reads config from `/vpn`).
- `privoxy.*`: Privoxy configuration files under `/etc/privoxy` inside the image.

## Environment / runtime options
- The entrypoint expects your OpenVPN configuration at `/vpn/vpn.conf` (or an .ovpn file mounted to that path).
- If you need username/password authentication create `/vpn/vpn.auth` with two lines: username then password, and reference it from your .conf (e.g. `auth-user-pass vpn.auth`).
- DNS is handled inside the container by `dnsmasq` (AdGuard Family upstreams). The image configures `/etc/resolv.conf` to point to the local resolver at container start.

## Tailscale integration (optional)

This image can optionally install and run Tailscale when `ENABLE_TAILSCALE` is set to `true` at container runtime. The following environment variables control Tailscale behavior:

- `ENABLE_TAILSCALE` (default: `false`): when `true`, the container attempts to install Tailscale and bring it up.
- `TAILSCALE_AUTHKEY` (default: empty): a pre-authentication key to perform a non-interactive `tailscale up --authkey <key>`.
- `TAILSCALE_FLAGS` (default: empty): additional flags to append to `tailscale up`.
- `TAILSCALE_ACCEPT_ROUTES` (default: `false`): when `true`, `--accept-routes` is added to `tailscale up` to accept routes advertised by other nodes.
- `TAILSCALE_HOSTNAME`: optional hostname to register for this machine in Tailscale (passed to `tailscale up --hostname`).
- `TAILSCALE_ADVERTISE_EXIT_NODE` (default: `false`): when `true`, the container will attempt to advertise itself as an exit node.

Behavior notes:
- At startup the script will install Tailscale (if missing), start `tailscaled`, and run `tailscale up` (non-interactive if `TAILSCALE_AUTHKEY` is provided).
- If `TAILSCALE_ADVERTISE_EXIT_NODE=true`, the container attempts to enable kernel IP forwarding and calls `tailscale set --advertise-exit-node=true`.
- Enabling kernel sysctls from inside the container may be restricted by the container runtime; prefer passing `--sysctl` or enabling forwarding on the host (see examples below).

### Example run enabling Tailscale with an auth key and accepting routes:

```sh
docker run --cap-add=NET_ADMIN --device /dev/net/tun --rm \
  -e ENABLE_TAILSCALE=true \
  -e TAILSCALE_AUTHKEY="tskey-xxx" \
  -e TAILSCALE_ACCEPT_ROUTES=true \
  -v /path/to/vpn:/vpn:ro \
  -p 3128:3128 openvpn-client-proxy:latest
```

## Notes & caveats
- The image is intentionally minimal. If you need advanced debugging tools (`curl`, `iputils`, etc.) add them in a derived Dockerfile.
- Overwriting `/etc/resolv.conf` is performed at container start to point at the local `dnsmasq`. If your Docker runtime or host locks `resolv.conf`, adapt the startup to use OpenVPN up/down hooks to update DNS.
- The startup script configures iptables rules by default to enable Tailscale/OpenVPN operation; you can customize or remove these rules in `start.sh` if you prefer host-managed firewalling.

## Where to tweak DNS blocking
- To change or extend the blocking upstreams, edit `dnsmasq.conf` in the repo. It currently uses AdGuard Family servers (blocks adult content + ads).

## Docker Compose example

A minimal `docker-compose.yml` example. If you enable `TAILSCALE_ADVERTISE_EXIT_NODE=true` you will likely need to set `sysctls` on the container or enable forwarding on the host.

```yaml
version: '3.8'
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
    # Example sysctls for exit-node (prefer to set on host/compose):
    # sysctls:
    #   net.ipv4.ip_forward: "1"
    #   net.ipv6.conf.all.forwarding: "1"
```

## License
See repository LICENSE file.
