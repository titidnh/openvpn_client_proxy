#!/bin/sh

set -eu

conf="/vpn/vpn.conf"

setup_iptables() {
	# Flush previous rules and set restrictive defaults
	iptables -F || true
	iptables -P OUTPUT DROP
	iptables -P FORWARD DROP
	iptables -P INPUT ACCEPT

	# Allow loopback
	iptables -A OUTPUT -o lo -j ACCEPT

	# Allow established/related
	iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	# Allow traffic via tun (when tunnel is up)
	iptables -A OUTPUT -o tun+ -j ACCEPT

	# Allow DNS to local resolver (dnsmasq)
	iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT || true
	iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT || true

	# Allow OpenVPN handshake to VPN server port (parse from config if possible)
	if [ -f "$conf" ]; then
		port=$(awk '/^remote /{print $3; exit}' "$conf" || true)
		proto=$(awk '/^proto /{print $2; exit}' "$conf" || true)
		if [ -z "$port" ]; then
			port=1194
		fi
		if [ -z "$proto" ]; then
			proto=udp
		fi
		iptables -A OUTPUT -p "$proto" --dport "$port" -j ACCEPT || true
	else
		iptables -A OUTPUT -p udp --dport 1194 -j ACCEPT || true
	fi
}

# Block IPv6 traffic by default and allow only necessary interfaces (tun) and loopback
setup_ip6tables() {
	# If ip6tables is not available this will fail; ignore errors to keep container running
	ip6tables -F || true
	ip6tables -P OUTPUT DROP || true
	ip6tables -P FORWARD DROP || true
	ip6tables -P INPUT ACCEPT || true

	# Allow loopback
	ip6tables -A OUTPUT -o lo -j ACCEPT || true

	# Allow established/related
	ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true

	# Allow traffic via tun (when tunnel is up)
	ip6tables -A OUTPUT -o tun+ -j ACCEPT || true

	# Allow DNS to local resolver (if any) on ::1
	ip6tables -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT || true
	ip6tables -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT || true

	# Do not allow any other IPv6 outbound traffic
}

start_dnsmasq() {
	if [ -f /etc/dnsmasq.conf ]; then
		rm -f /etc/resolv.conf || true
		echo "nameserver 127.0.0.1" > /etc/resolv.conf
		dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf &
	fi
}

start_privoxy() {
	/usr/sbin/privoxy --no-daemon /etc/privoxy/privoxy.config &
}

supervise_openvpn() {
	# Loop forever: (re)apply iptables then start openvpn; if it exits, restart
	attempt=0
	while true; do
		attempt=$((attempt+1))
		setup_iptables
		setup_ip6tables
		/usr/local/bin/openvpn.sh &
		vpn_pid=$!
		# wait for the openvpn process to exit
		wait "$vpn_pid" || true
		# exponential/backoff restart delay to avoid rapid restarts
		sleep_s=$((5 * attempt))
		if [ "$sleep_s" -gt 60 ]; then
			sleep_s=60
		fi
		echo "[openvpn] process exited — restarting in ${sleep_s}s (attempt ${attempt})"
		sleep "$sleep_s"
	done
}

trap 'kill 0 || true; exit 0' INT TERM

# Start services
start_dnsmasq
start_privoxy

# Run supervisor in foreground so signals are handled directly
supervise_openvpn