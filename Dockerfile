FROM debian:trixie-slim

# By default Tailscale is disabled at runtime. These env vars control runtime behaviour.
# - `ENABLE_TAILSCALE`: set to "true" to enable installing/configuring Tailscale at container start
# - `TAILSCALE_AUTHKEY`: pre-auth key for non-interactive `tailscale up`
# - `TAILSCALE_FLAGS`: extra flags to append to `tailscale up`
# - `TAILSCALE_ACCEPT_ROUTES`: set to "true" to pass `--accept-routes` to `tailscale up`
ENV ENABLE_TAILSCALE=false
ENV TAILSCALE_AUTHKEY=""
ENV TAILSCALE_FLAGS=""
ENV TAILSCALE_ACCEPT_ROUTES=false
ENV TAILSCALE_HOSTNAME="openvpn-client-proxy"

# Create vpn user (system user, no home)
RUN groupadd -r vpn \
  && useradd -r -g vpn -M -s /usr/sbin/nologin vpn || true

# Copy configuration and scripts (only required files are included via .dockerignore)
COPY --chown=vpn:vpn privoxy.config default.action default.filter user.action user.filter /etc/privoxy/
COPY --chown=vpn:vpn dnsmasq.conf /etc/dnsmasq.conf
COPY --chown=root:root openvpn.sh /usr/local/bin/openvpn.sh
COPY --chown=root:root healthcheck.sh /usr/local/bin/healthcheck.sh
COPY --chown=root:root start.sh /start.sh

# Install runtime packages, including openrc so `rc-update` is available for installers that expect it.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    openvpn \
    privoxy \
    dnsmasq \
    iptables \
    tini \
    ca-certificates \
    netcat-openbsd \
    dnsutils \
    openrc \
  && chmod 0755 /usr/local/bin/openvpn.sh /usr/local/bin/healthcheck.sh /start.sh \
  && chown root:root /usr/local/bin/openvpn.sh /usr/local/bin/healthcheck.sh /start.sh \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

VOLUME ["/vpn"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/start.sh"]