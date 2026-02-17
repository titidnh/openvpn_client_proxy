#!/bin/sh

# Start dnsmasq (AdGuard DNS) and point resolv to localhost
if [ -f /etc/dnsmasq.conf ]; then
	rm -f /etc/resolv.conf || true
	echo "nameserver 127.0.0.1" > /etc/resolv.conf
	dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf &
fi

# Lancer OpenVPN (script utilisateur)
/usr/local/bin/openvpn.sh &

# Lancer Privoxy
/usr/sbin/privoxy --no-daemon /etc/privoxy/privoxy.config &

# Attendre que tous les processus enfants se terminent
wait
