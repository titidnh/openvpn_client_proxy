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
  && chmod 0755 /usr/local/bin/openvpn.sh /start.sh \
  && chown root:root /usr/local/bin/openvpn.sh /start.sh

VOLUME ["/vpn"]
ENTRYPOINT ["/sbin/tini", "--", "/start.sh"]