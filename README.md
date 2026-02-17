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

**Notes & caveats**
- The image is intentionally minimal. If you need advanced debugging tools (curl, iputils, etc.) add them in a derived Dockerfile.
- Overwriting /etc/resolv.conf is performed at container start to point at the local dnsmasq. If your Docker runtime or host locks resolv.conf, adapt the startup to use OpenVPN up/down hooks to update DNS.
- Firewalling was removed to keep the image small; if you need per-container firewall policies add them on the host or reintroduce iptables rules.

**Where to tweak DNS blocking**
- To change or extend the blocking upstreams, edit dnsmasq.conf in the repo. It currently uses AdGuard Family servers (blocks adult content + ads).

**License**
See repository LICENSE file.

**Docker Compose (example)**

The following `docker-compose.yml` shows a minimal example for running the image (example from titi@WaterlooSrv):

```yaml
titi@WaterlooSrv:~/docker_source/vpn_fr $ cat docker-compose.yml
services:
  vpnes:
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
```

Comme documentation de docker compose.
