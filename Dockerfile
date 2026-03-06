FROM debian:stable-slim

ARG DEBIAN_FRONTEND=noninteractive

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
  TAILSCALE_ADVERTISE_EXIT_NODE=false \
  DNS_SERVER_1="94.140.14.14" \
  DNS_SERVER_2="94.140.15.15"

RUN groupadd -r vpn && useradd -r -g vpn -M -s /usr/sbin/nologin vpn

# Install all packages in a single layer.
# gnupg is needed only to bootstrap Tailscale's apt repo; they are
# purged at the end of the same RUN so they do not inflate the final image.
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg \
  && curl -fsSL https://tailscale.com/install.sh | sh \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    openvpn privoxy dnsmasq iptables iproute2 tini netcat-openbsd dnsutils \
  && apt-get purge -y gnupg \
  && apt-get autoremove -y \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

COPY --chmod=0755 openvpn.sh /usr/local/bin/openvpn.sh
COPY --chmod=0755 healthcheck.sh /usr/local/bin/healthcheck.sh
COPY --chmod=0755 start.sh /start.sh

COPY --chown=vpn:vpn privoxy.config default.action default.filter user.action user.filter /etc/privoxy/

# /vpn        → mount your OpenVPN config (vpn.conf, certs, credentials)
# /var/lib/tailscale → persist Tailscale identity across container recreations
VOLUME ["/vpn", "/var/lib/tailscale"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/start.sh"]