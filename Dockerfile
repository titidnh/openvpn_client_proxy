FROM alpine:3.18

RUN addgroup -S vpn && adduser -S -G vpn vpn
COPY --chown=vpn:vpn privoxy.config default.action default.filter user.action user.filter /etc/privoxy/
COPY --chown=root:root openvpn.sh /usr/local/bin/openvpn.sh
COPY --chown=root:root start.sh /start.sh
COPY --chown=vpn:vpn dnsmasq.conf /etc/dnsmasq.conf
RUN apk add --no-cache \
    bash \
    openvpn \
    privoxy \
    dnsmasq \
    iptables \
    tini \
    ca-certificates \
    curl \
    netcat-openbsd \
    bind-tools \
    unbound \
  && chmod 0755 /usr/local/bin/openvpn.sh /start.sh \
  && chown root:root /usr/local/bin/openvpn.sh /start.sh

  COPY --chown=root:root healthcheck.sh /usr/local/bin/healthcheck.sh
  RUN chmod 0755 /usr/local/bin/healthcheck.sh || true
  COPY --chown=root:root unbound.conf /etc/unbound/unbound.conf
  RUN mkdir -p /var/lib/unbound || true
  # create unbound user/group and set ownership for unbound data dir
  RUN addgroup -S unbound && adduser -S -G unbound -h /var/lib/unbound -H unbound || true \
  && chown -R unbound:unbound /var/lib/unbound || true

VOLUME ["/vpn"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /usr/local/bin/healthcheck.sh || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/start.sh"]