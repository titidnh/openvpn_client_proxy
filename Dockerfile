FROM alpine:3.18

# By default enable Tailscale in the image (propagated from build arg). Can be overridden at runtime
# Build-time: `--build-arg ENABLE_TAILSCALE=true|false` — controls whether tailscale is installed
# Runtime: `-e ENABLE_TAILSCALE=true|false` — controls whether start.sh will attempt to configure/run tailscale
# Tailscale runtime configuration (optional)
# - `TAILSCALE_AUTHKEY`: set a pre-shared auth key for non-interactive `tailscale up`
# - `TAILSCALE_FLAGS`: extra flags to append to `tailscale up`
# - `TAILSCALE_ACCEPT_ROUTES`: set to "true" to pass `--accept-routes` to `tailscale up`
ENV ENABLE_TAILSCALE=false
ENV TAILSCALE_AUTHKEY=""
ENV TAILSCALE_FLAGS=""
ENV TAILSCALE_ACCEPT_ROUTES=false

# Create vpn user
RUN addgroup -S vpn \
  && adduser -S -G vpn vpn

# Copy configuration and scripts (only required files are included via .dockerignore)
COPY --chown=vpn:vpn privoxy.config default.action default.filter user.action user.filter /etc/privoxy/
COPY --chown=vpn:vpn dnsmasq.conf /etc/dnsmasq.conf
COPY --chown=root:root openvpn.sh /usr/local/bin/openvpn.sh
COPY --chown=root:root healthcheck.sh /usr/local/bin/healthcheck.sh
COPY --chown=root:root start.sh /start.sh

# Install runtime packages in a single layer, set permissions and remove documentation to save space
RUN apk add --no-cache \
    openvpn \
    privoxy \
    dnsmasq \
    iptables \
    tini \
    ca-certificates \
    netcat-openbsd \
    bind-tools \
  && chmod 0755 /usr/local/bin/openvpn.sh /usr/local/bin/healthcheck.sh /start.sh \
  && chown root:root /usr/local/bin/openvpn.sh /usr/local/bin/healthcheck.sh /start.sh \
  && rm -rf /usr/share/man /usr/share/doc /usr/share/locale /var/cache/apk/*

VOLUME ["/vpn"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/start.sh"]