#!/bin/sh

set -eu

conf="/vpn/vpn.conf"
TAILSCALE_RUN_DIR="${TAILSCALE_RUN_DIR:-/var/run/tailscale}"
TAILSCALE_ADVERTISE_EXIT_NODE="${TAILSCALE_ADVERTISE_EXIT_NODE:-false}"

setup_iptables() {
	# Simplified mode: accept all traffic (INPUT/OUTPUT/FORWARD)
	# This makes the container permissive so services (privoxy, openvpn, tailscale)
	# can receive incoming connections, perform outgoing connections and forward
	# traffic without restrictive iptables rules.
	iptables -F || true
	iptables -t nat -F || true
	iptables -t mangle -F || true
	iptables -X || true
	iptables -t nat -X || true
	iptables -t mangle -X || true
	iptables -P INPUT ACCEPT || true
	iptables -P FORWARD ACCEPT || true
	iptables -P OUTPUT ACCEPT || true
	# keep established/related accepted for good measure
	iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
	iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true

	# NAT: masquerade traffic going out via VPN/tailscale interfaces
	iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE || true
	iptables -t nat -A POSTROUTING -o tailscale+ -j MASQUERADE || true
}

# Simplified IPv6 mode: accept all IPv6 traffic (INPUT/OUTPUT/FORWARD)
setup_ip6tables() {
	# Make IPv6 permissive inside the container: flush rules and accept policy
	ip6tables -F || true
	ip6tables -t mangle -F 2>/dev/null || true
	ip6tables -X || true
	ip6tables -P INPUT ACCEPT || true
	ip6tables -P FORWARD ACCEPT || true
	ip6tables -P OUTPUT ACCEPT || true
	# keep established/related accepted for good measure
	ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
	ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true

	# Ensure kernel IPv6 forwarding is enabled so container can forward traffic
	# (may fail in restrictive runtimes; ignore errors)
	sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true

	# IPv6 NAT/Masquerade is not always available on all kernels.
	# If the nat table for ip6tables exists, add POSTROUTING MASQUERADE rules
	# for tun+ and tailscale+; otherwise rely on routing/forwarding.
	if ip6tables -t nat -L >/dev/null 2>&1; then
		ip6tables -t nat -A POSTROUTING -o tun+ -j MASQUERADE || true
		ip6tables -t nat -A POSTROUTING -o tailscale+ -j MASQUERADE || true
	fi
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

		# Start dnsmasq in foreground; --log-facility=- sends logs to stdout (visible in docker logs)
		dnsmasq --no-daemon --conf-file=/etc/dnsmasq.conf --log-facility=- &
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

	# Ensure state and run directories exist (state is hardcoded to /var/lib/tailscale)
	mkdir -p /var/lib/tailscale "$TAILSCALE_RUN_DIR" || true

	echo "[tailscale] starting tailscaled (state=/var/lib/tailscale run=$TAILSCALE_RUN_DIR)"
	tailscaled --state="/var/lib/tailscale/tailscaled.state" --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" >/var/log/tailscaled.log 2>&1 &
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
			# Overwrite the sysctl config to ensure forwarding is enabled
			cat > "$sysctl_conf" <<'EOF'
# Managed by openvpn_client_proxy start.sh for Tailscale exit-node
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
			# Load the new sysctl settings (may fail without appropriate privileges)
			sysctl -p "$sysctl_conf" || true
		fi

		# Run tailscale up in background; logs available in /var/log/tailscale-up.log
		(tailscale up --accept-dns=false --authkey="$TAILSCALE_AUTHKEY" $up_flags > /var/log/tailscale-up.log 2>&1) &
		# If advertise-exit-node is requested, ensure it's set (tailscale set is idempotent)
		if [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ]; then
			(tailscale set --advertise-exit-node=true >> /var/log/tailscale-up.log 2>&1) || true &
		fi
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
		kill "${dnsmasq_pid:-0}" 2>/dev/null || true
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
