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
	# allow local unbound (DoT forwarder) on 127.0.0.1:5353
	iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 5353 -j ACCEPT || true
	iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 5353 -j ACCEPT || true

	# dnsmasq forwards to local unbound; only allow local resolver (127.0.0.1:53)
	# (per-upstream rules are unnecessary and may be invalid when using "server=127.0.0.1#5353")

	# Allow DoT outbound only for the unbound process (prevents other processes from doing DoT)
	iptables -A OUTPUT -p tcp -m owner --uid-owner unbound --dport 853 -j ACCEPT || true

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
		dnsmasq_pid=$!
	fi
}

start_unbound() {
    if [ -f /etc/unbound/unbound.conf ]; then
        unbound -d -c /etc/unbound/unbound.conf &
        unbound_pid=$!
    fi
}

start_privoxy() {
	/usr/sbin/privoxy --no-daemon /etc/privoxy/privoxy.config &
	privoxy_pid=$!
}

start_openvpn() {
    /usr/local/bin/openvpn.sh &
    vpn_pid=$!
}

supervise_all() {
	attempt=0
	while true; do
		attempt=$((attempt+1))

		setup_iptables
		setup_ip6tables

		# start unbound, dnsmasq and privoxy (pids set by functions)
		start_unbound
		# give unbound a moment to be ready
		sleep 1
		start_dnsmasq
		start_privoxy

		# start openvpn wrapper
		start_openvpn

		echo "[supervisor] started: vpn=$vpn_pid dnsmasq=${dnsmasq_pid:-unknown} privoxy=${privoxy_pid:-unknown}"

		# monitor loop: check processes, privoxy port and DNS resolution
		check_interval=10
		fail=0
		while true; do
			sleep "$check_interval"

			# check openvpn
			if ! kill -0 "$vpn_pid" >/dev/null 2>&1; then
				echo "[supervisor] openvpn process died"
				fail=1
			fi

			# check privoxy listen port
			proxy_port=3128
			if [ -f /etc/privoxy/privoxy.config ]; then
				addr=$(awk '/^[[:space:]]*listen-address/ {print $2; exit}' /etc/privoxy/privoxy.config || true)
				if [ -n "$addr" ]; then
					proxy_port=$(echo "$addr" | awk -F: '{print $NF}')
				fi
			fi
			if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
				echo "[supervisor] privoxy not listening on 127.0.0.1:$proxy_port"
				fail=1
			fi

			# check dnsmasq process
			if ! kill -0 "${dnsmasq_pid:-0}" >/dev/null 2>&1; then
				echo "[supervisor] dnsmasq process died"
				fail=1
			fi

			# check DNS resolution via local resolver
			if ! nslookup example.com 127.0.0.1 >/dev/null 2>&1; then
				echo "[supervisor] DNS resolution via 127.0.0.1 failed"
				fail=1
			fi

			if [ "$fail" -eq 1 ]; then
				break
			fi
		done

		# kill started processes
		echo "[supervisor] failure detected - killing services to restart"
		kill "${vpn_pid}" 2>/dev/null || true
		kill "${privoxy_pid}" 2>/dev/null || true
		kill "${dnsmasq_pid}" 2>/dev/null || true
		kill "${unbound_pid}" 2>/dev/null || true
		wait 2>/dev/null || true

		# exponential backoff before restart
		sleep_s=$((5 * attempt))
		if [ "$sleep_s" -gt 60 ]; then
			sleep_s=60
		fi
		echo "[supervisor] restarting all services in ${sleep_s}s (attempt ${attempt})"
		sleep "$sleep_s"
	done
}

trap 'kill 0 || true; exit 0' INT TERM

# Run supervisor in foreground so signals are handled directly
supervise_all