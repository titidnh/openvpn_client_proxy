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

	# Allow DNS upstreams configured in dnsmasq.conf but restrict to the
	# dnsmasq process only (owner match). This forces other processes to use
	# the local resolver at 127.0.0.1.
	if [ -f /etc/dnsmasq.conf ]; then
		grep -E '^\s*server=' /etc/dnsmasq.conf | sed 's/^\s*server=//' | while read -r dns; do
			case "$dns" in
				*[.:]* )
					iptables -A OUTPUT -p udp -d "$dns" --dport 53 -m owner --uid-owner dnsmasq -j ACCEPT || true
					iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -m owner --uid-owner dnsmasq -j ACCEPT || true
					;;
			esac
		done
	fi

	# Allow OpenVPN handshake to VPN server port (parse from config if possible).
	# Support both formats: "remote host port" and "remote host:port".
	if [ -f "$conf" ]; then
		remote_line=$(awk '/^remote /{print; exit}' "$conf" || true)
		host=""
		port=""
		proto=$(awk '/^proto /{print $2; exit}' "$conf" || true)
		if [ -n "$remote_line" ]; then
			set -- $remote_line
			hostpart="$2"
			if echo "$hostpart" | grep -q ':'; then
				host=$(echo "$hostpart" | cut -d: -f1)
				port=$(echo "$hostpart" | cut -d: -f2)
			else
				host="$hostpart"
				if [ "$#" -ge 3 ]; then port="$3"; fi
			fi
		fi
		if [ -z "$port" ]; then
			port=1194
		fi
		if [ -z "$proto" ]; then
			proto=udp
		fi
		# Allow handshake to the parsed port (any destination). For tighter
		# security we could resolve $host and restrict to that IP.
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