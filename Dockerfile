FROM alpine:3
EXPOSE 3128

# Copy config and scripts first so we can set permissions in the same layer
COPY privoxy.config default.action default.filter user.action user.filter /etc/privoxy/
COPY openvpn.sh /usr/local/bin/openvpn.sh
COPY start.sh /start.sh
COPY dnsmasq.conf /etc/dnsmasq.conf

# Install packages, create group and set executable permissions in one layer
RUN addgroup -S vpn \
  && apk add --no-cache \
    bash \
    openvpn \
    privoxy \
    dnsmasq \
    tini \
    ca-certificates \
  && chmod +x /usr/local/bin/openvpn.sh /start.sh

# Healthcheck removed to avoid adding curl and reduce image size

VOLUME ["/vpn"]
ENTRYPOINT ["/sbin/tini", "--", "/start.sh"]