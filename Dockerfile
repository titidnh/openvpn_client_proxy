FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
ENV DEBIAN_FRONTEND=${DEBIAN_FRONTEND}

# Runtime environment variables for Tailscale (disabled by default).
# ENABLE_TAILSCALE=true   → start tailscaled and run `tailscale up`
# TAILSCALE_AUTHKEY       → pre-auth key for non-interactive authentication
# TAILSCALE_FLAGS         → extra flags appended to `tailscale up`
# TAILSCALE_ACCEPT_ROUTES → pass --accept-routes to `tailscale up`
# TAILSCALE_ADVERTISE_EXIT_NODE → advertise this node as a Tailscale exit node
ENV ENABLE_TAILSCALE=false \
    TAILSCALE_AUTHKEY="" \
    TAILSCALE_FLAGS="" \
    TAILSCALE_ACCEPT_ROUTES=false \
    TAILSCALE_HOSTNAME="openvpn-client-proxy" \
    TAILSCALE_STATE_DIR="/var/lib/tailscale" \
    TAILSCALE_ADVERTISE_EXIT_NODE=false

RUN groupadd -r vpn && useradd -r -g vpn -M -s /usr/sbin/nologin vpn

# Install all packages in a single layer.
# curl and gnupg are needed only to bootstrap Tailscale's apt repo; they are
# purged at the end of the same RUN so they do not inflate the final image.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg \
  && curl -fsSL https://tailscale.com/install.sh | sh \
  && apt-get install -y --no-install-recommends \
    openvpn privoxy dnsmasq iptables tini netcat-openbsd dnsutils \
  && apt-get purge -y curl gnupg \
  && apt-get autoremove -y \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

COPY --chown=root:root openvpn.sh /usr/local/bin/openvpn.sh
COPY --chown=root:root healthcheck.sh /usr/local/bin/healthcheck.sh
COPY --chown=root:root start.sh /start.sh
RUN chmod 0755 /usr/local/bin/openvpn.sh /usr/local/bin/healthcheck.sh /start.sh

COPY --chown=vpn:vpn privoxy.config default.action default.filter user.action user.filter /etc/privoxy/
COPY --chown=vpn:vpn dnsmasq.conf /etc/dnsmasq.conf

# /vpn        → mount your OpenVPN config (vpn.conf, certs, credentials)
# /var/lib/tailscale → persist Tailscale identity across container recreations
VOLUME ["/vpn", "/var/lib/tailscale"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/start.sh"]