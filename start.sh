#!/bin/sh

set -eu

conf="/vpn/vpn.conf"
TAILSCALE_STATE_DIR="${TAILSCALE_STATE_DIR:-/var/lib/tailscale}"
TAILSCALE_RUN_DIR="${TAILSCALE_RUN_DIR:-/var/run/tailscale}"
TAILSCALE_ADVERTISE_EXIT_NODE="${TAILSCALE_ADVERTISE_EXIT_NODE:-false}"

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

	# Allow traffic via tun (when tunnel is up) and tailscale interfaces
	iptables -A OUTPUT -o tun+ -j ACCEPT
	iptables -A OUTPUT -o tailscale+ -j ACCEPT
	# Allow all traffic coming from / to tailscale interfaces
	iptables -A INPUT -i tailscale+ -j ACCEPT || true
	iptables -A OUTPUT -o tailscale+ -j ACCEPT || true
	# Allow forwarding from tailscale into tun (and related return traffic)
	iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT || true
	iptables -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true

	# Local DNS resolver (dnsmasq) on 127.0.0.1
	iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT || true
	iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT || true

	# Allow DNS upstreams listed in /etc/dnsmasq.conf (no owner-match):
	# dnsmasq may run as root inside containers so owner-match can be unreliable.
	if [ -f /etc/dnsmasq.conf ]; then
		grep -E '^[[:space:]]*server=' /etc/dnsmasq.conf | sed 's/^[[:space:]]*server=//' | while read -r dns; do
			case "$dns" in
				*[.:]* )
					# allow upstream UDP/TCP 53 to the configured server IP/host
					iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT || true
					iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT || true
					;;
			esac
		done
	else
		# Fallback: allow common public DNS servers so bootstrapping can resolve
		iptables -A OUTPUT -p udp -d 8.8.8.8 --dport 53 -j ACCEPT || true
		iptables -A OUTPUT -p udp -d 1.1.1.1 --dport 53 -j ACCEPT || true
	fi

	# Allow outbound HTTPS (required by tailscaled to reach controlplane/DERP)
	# Note: this opens port 443 for all processes in the container. To be
	# stricter, run tailscaled under a dedicated UID and replace this rule
	# with an owner-match rule for that UID.
	iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT || true

	# Allow OpenVPN handshake to VPN server port (parse from config if possible).
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
		iptables -A OUTPUT -p "$proto" --dport "$port" -j ACCEPT || true
	else
		iptables -A OUTPUT -p udp --dport 1194 -j ACCEPT || true
	fi

	# Create a LOGDROP chain to log then drop unmatched packets (rate-limited).
	if ! iptables -L LOGDROP >/dev/null 2>&1; then
		iptables -N LOGDROP >/dev/null 2>&1 || true
	fi
	iptables -C LOGDROP -m limit --limit 5/min -j LOG --log-prefix "[iptables LOGDROP] " --log-level 6 >/dev/null 2>&1 || \
		iptables -A LOGDROP -m limit --limit 5/min -j LOG --log-prefix "[iptables LOGDROP] " --log-level 6 >/dev/null 2>&1 || true
	iptables -C LOGDROP -j DROP >/dev/null 2>&1 || iptables -A LOGDROP -j DROP >/dev/null 2>&1 || true

	# Ensure OUTPUT and FORWARD jump to LOGDROP at the end (idempotent)
	iptables -C OUTPUT -j LOGDROP >/dev/null 2>&1 || iptables -A OUTPUT -j LOGDROP >/dev/null 2>&1 || true
	iptables -C FORWARD -j LOGDROP >/dev/null 2>&1 || iptables -A FORWARD -j LOGDROP >/dev/null 2>&1 || true

	# (iptables periodic dump removed)
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
	ip6tables -A OUTPUT -o tailscale+ -j ACCEPT || true

	# Allow DNS to local resolver (if any) on ::1
	ip6tables -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT || true
	ip6tables -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT || true

	# Do not allow any other IPv6 outbound traffic
}

start_dnsmasq() {
	if [ -f /etc/dnsmasq.conf ]; then
		rm -f /etc/resolv.conf || true
		echo "nameserver 127.0.0.1" > /etc/resolv.conf

		# Test configuration before starting to capture errors early
		if ! dnsmasq --test --conf-file=/etc/dnsmasq.conf >/tmp/dnsmasq.test 2>&1; then
			echo "[start] dnsmasq config test failed:" 
			sed -n '1,200p' /tmp/dnsmasq.test || true
			return 0
		fi

		# Start dnsmasq in foreground writing logs to stdout so docker logs show them
		dnsmasq --no-daemon --conf-file=/etc/dnsmasq.conf --log-facility=- >/dev/null 2>&1 &
		dnsmasq_pid=$!

		# Wait briefly for dnsmasq to bind to 127.0.0.1:53
		bound=0
		for i in 1 2 3 4 5; do
			if nc -z -w 1 127.0.0.1 53 >/dev/null 2>&1; then
				bound=1
				break
			fi
			sleep 1
		done
		if [ "$bound" -eq 1 ]; then
			echo "[start] dnsmasq started (pid=$dnsmasq_pid) and is listening on 127.0.0.1:53"
		else
			echo "[start] dnsmasq did not bind to 127.0.0.1:53; check /tmp/dnsmasq.test and dnsmasq logs"
		fi
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

start_tailscale() {
	# Only start tailscaled if explicitly enabled and binary exists
	if [ "${ENABLE_TAILSCALE:-false}" != "true" ]; then
		return 0
	fi
	if ! command -v tailscaled >/dev/null 2>&1; then
		echo "[tailscale] tailscaled not installed; skipping"
		return 0
	fi

	# Ensure state and run directories exist (persist state at TAILSCALE_STATE_DIR)
	mkdir -p "$TAILSCALE_STATE_DIR" "$TAILSCALE_RUN_DIR" || true

	echo "[tailscale] starting tailscaled (state=$TAILSCALE_STATE_DIR run=$TAILSCALE_RUN_DIR)"
	tailscaled --state="$TAILSCALE_STATE_DIR/tailscaled.state" --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" >/var/log/tailscaled.log 2>&1 &
	export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
	tailscaled_pid=$!

	# Wait for tailscaled socket to appear or for `tailscale status` to respond
	timeout=20
	waited=0
	until tailscale status >/dev/null 2>&1 || [ "$waited" -ge "$timeout" ]; do
		sleep 1
		waited=$((waited+1))
	done

	if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
		up_flags="${TAILSCALE_FLAGS:-}"
		if [ "${TAILSCALE_ACCEPT_ROUTES:-false}" = "true" ]; then
			up_flags="$up_flags --accept-routes"
		fi
		if [ -n "${TAILSCALE_HOSTNAME:-}" ]; then
			up_flags="$up_flags --hostname=${TAILSCALE_HOSTNAME}"
		fi
		if [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ]; then
			up_flags="$up_flags --advertise-exit-node"
		fi
		echo "[tailscale] running 'tailscale up'"
		# If advertise-exit-node is requested, enable kernel IP forwarding first
		if [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ]; then
			sysctl_conf=/etc/sysctl.d/99-tailscale.conf
			mkdir -p /etc/sysctl.d || true
			# Add settings idempotently
			grep -q '^net.ipv4.ip_forward' "$sysctl_conf" 2>/dev/null || echo 'net.ipv4.ip_forward = 1' >> "$sysctl_conf"
			grep -q '^net.ipv6.conf.all.forwarding' "$sysctl_conf" 2>/dev/null || echo 'net.ipv6.conf.all.forwarding = 1' >> "$sysctl_conf"
			# Load the new sysctl settings
			sysctl -p "$sysctl_conf" || true
		fi

		# Run tailscale up in background to avoid blocking supervisor; capture exit-node advertising if requested
		(tailscale up --authkey="$TAILSCALE_AUTHKEY" $up_flags > /var/log/tailscale-up.log 2>&1) &
		up_cmd_pid=$!
		# If advertise-exit-node is requested, ensure it's set (tailscale set is idempotent)
		if [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ]; then
			# run in background so it doesn't block startup
			(tailscale set --advertise-exit-node=true >> /var/log/tailscale-up.log 2>&1) || true &
		fi
		# Note: we don't wait for `tailscale up` here; status/logs are available in /var/log/tailscale-up.log
	else
		echo "[tailscale] no authkey provided; skipping 'tailscale up'"
	fi
}

supervise_all() {
	attempt=0
	while true; do
		attempt=$((attempt+1))
		start_dnsmasq
		setup_iptables
		setup_ip6tables
		start_privoxy
		start_openvpn
		start_tailscale

		echo "[supervisor] started: vpn=$vpn_pid dnsmasq=${dnsmasq_pid:-unknown} privoxy=${privoxy_pid:-unknown}"

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
			kill "${tailscaled_pid:-0}" 2>/dev/null || true
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