FROM alpine:3
EXPOSE 3128
RUN addgroup -S vpn \
  && apk add --no-cache \
    bash \
    ip6tables \
    iptables \
    openvpn \
    privoxy \
    dnsmasq \
    tini \
    ca-certificates
COPY privoxy.config default.action default.filter user.action user.filter /etc/privoxy/
COPY openvpn.sh /usr/local/bin/openvpn.sh
COPY start.sh /start.sh
COPY dnsmasq.conf /etc/dnsmasq.conf
RUN chmod +x /usr/local/bin/openvpn.sh /start.sh

# Healthcheck removed to avoid adding curl and reduce image size

VOLUME ["/vpn"]
ENTRYPOINT ["/sbin/tini", "--", "/start.sh"]