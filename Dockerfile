# =============================================================================
# Stage 1 — Tailscale binaries
# Download only the two binaries we need (tailscale + tailscaled).
# Using a dedicated stage avoids pulling the install script toolchain into the
# final image and lets BuildKit cache the download layer independently.
# =============================================================================
FROM alpine:3.20 AS tailscale-dl

ARG TARGETARCH
# TAILSCALE_VERSION can be pinned at build time: --build-arg TAILSCALE_VERSION=1.80.3
# If left empty, the latest stable release is fetched automatically.
ARG TAILSCALE_VERSION=""

RUN apk add --no-cache curl tar \
 && ARCH="${TARGETARCH:-amd64}" \
 && if [ -n "${TAILSCALE_VERSION}" ]; then \
      URL="https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${ARCH}.tgz"; \
    else \
      URL="https://pkgs.tailscale.com/stable/tailscale_latest_${ARCH}.tgz"; \
    fi \
 && echo "Downloading: ${URL}" \
 && curl -fsSL "${URL}" -o tailscale.tgz \
 && PREFIX=$(tar -tz -f tailscale.tgz | head -1 | cut -d/ -f1) \
 && echo "Tailscale version: ${PREFIX}" \
 && tar -xz -f tailscale.tgz "${PREFIX}/tailscale" "${PREFIX}/tailscaled" \
 && mv "${PREFIX}/tailscale" "${PREFIX}/tailscaled" . \
 && rm -rf tailscale.tgz "${PREFIX}" \
 && chmod 755 tailscale tailscaled

# =============================================================================
# Stage 2 — Final image
# =============================================================================
FROM alpine:3.20

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------
ENV ENABLE_TAILSCALE=false \
    TAILSCALE_AUTHKEY="" \
    TAILSCALE_FLAGS="" \
    TAILSCALE_ACCEPT_ROUTES=false \
    TAILSCALE_HOSTNAME="openvpn-client-proxy" \
    TAILSCALE_ADVERTISE_EXIT_NODE=false \
    DNS_SERVER_1="94.140.14.14" \
    DNS_SERVER_2="94.140.15.15" \
    PROXY_USER="" \
    PROXY_PASS="" \
    ENABLE_DOT=false \
    DOT_DNS_SERVERS="tls://dns.adguard-dns.com" \
    ENABLE_DNSSEC=false \
    DOT_TLS_CERT_BUNDLE="" \
    DOT_IP_REFRESH_INTERVAL=3600 \
    DNS_SPLIT="" \
    ENABLE_METRICS=false \
    DROP_CAPS=false

# ---------------------------------------------------------------------------
# System user
# Alpine uses addgroup / adduser instead of groupadd / useradd
# ---------------------------------------------------------------------------
RUN addgroup -S vpn && adduser -S -G vpn -H -s /sbin/nologin vpn

# ---------------------------------------------------------------------------
# Runtime packages
# Notes:
#   - busybox (included in Alpine base) provides nslookup → no dnsutils needed
#   - tini is in Alpine's main repo
#   - ip6tables is bundled with iptables on Alpine
#   - nginx + apache2-utils for optional proxy auth
# ---------------------------------------------------------------------------
RUN apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      dnsmasq \
      iptables \
      ip6tables \
      iproute2 \
      netcat-openbsd \
      nginx \
      apache2-utils \
      openvpn \
      privoxy \
      tini \
      unbound \
      libcap \
      python3 \
      socat

# Ensure unbound runtime directories exist and are owned by the unbound user
RUN mkdir -p /var/lib/unbound /etc/unbound \
 && chown -R unbound:unbound /var/lib/unbound /etc/unbound 2>/dev/null || true

# ---------------------------------------------------------------------------
# Tailscale binaries from stage 1
# ---------------------------------------------------------------------------
COPY --from=tailscale-dl /tailscale  /usr/local/bin/tailscale
COPY --from=tailscale-dl /tailscaled /usr/local/bin/tailscaled

# ---------------------------------------------------------------------------
# Application scripts and Privoxy config
# ---------------------------------------------------------------------------
COPY --chmod=0755 openvpn.sh      /usr/local/bin/openvpn.sh
COPY --chmod=0755 healthcheck.sh  /usr/local/bin/healthcheck.sh
COPY --chmod=0755 start.sh        /start.sh
RUN sed -i 's/\r//' /start.sh
COPY --chown=vpn:vpn \
     privoxy.config default.action default.filter user.action user.filter \
     /etc/privoxy/

# ---------------------------------------------------------------------------
# Volumes and healthcheck
# ---------------------------------------------------------------------------
VOLUME ["/vpn", "/var/lib/tailscale"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/start.sh"]