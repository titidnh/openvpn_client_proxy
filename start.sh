#!/bin/bash

set -eu
set -o pipefail

conf="/vpn/vpn.conf"
TAILSCALE_RUN_DIR="${TAILSCALE_RUN_DIR:-/var/run/tailscale}"
TAILSCALE_ADVERTISE_EXIT_NODE="${TAILSCALE_ADVERTISE_EXIT_NODE:-false}"

# Detect OpenVPN port and protocol from $conf (sets VPN_PORT and VPN_PROTO)
get_vpn_port_proto() {
	if [ -f "$conf" ]; then
		VPN_PORT=$(awk '/^remote /{for(i=1;i<=NF;i++) if ($i ~ /:/){split($i,a,":"); print a[2]; exit}}' "$conf")
		VPN_PORT=${VPN_PORT:-$(awk '/^remote /{print $3; exit}' "$conf")}
		VPN_PORT=${VPN_PORT:-1194}
		VPN_PROTO=$(awk '/^proto /{print $2; exit}' "$conf")
		VPN_PROTO=${VPN_PROTO:-udp}
	else
		VPN_PORT=1194
		VPN_PROTO=udp
	fi
}

setup_iptables() {
    iptables -F
    iptables -t nat -F
	iptables -P INPUT ACCEPT       # Incoming accepted by default (adjust if needed)
	iptables -P OUTPUT DROP        # Outgoing dropped by default
	iptables -P FORWARD DROP       # Forwarding dropped by default

    # --- Interfaces ---
    LOOPBACK_IFS=("lo")
    TUN_IFS=("tun+" "eth0" "tailscale+")

	# --- Allow loopback ---
    for ifs in "${LOOPBACK_IFS[@]}"; do
        iptables -A OUTPUT -o "$ifs" -j ACCEPT
    done

	# --- Established/related connections ---
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	# --- Traffic on tunnel and network interfaces ---
    for ifs in "${TUN_IFS[@]}"; do
        iptables -A OUTPUT -o "$ifs" -j ACCEPT
    done

    # --- Forwarding Tailscale <-> TUN ---
    iptables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	# --- Local DNS ---
    iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT

    # --- DNS upstream ---
    DNS_SERVERS=("8.8.8.8" "1.1.1.1")
    if [ -f /etc/dnsmasq.conf ]; then
        while read -r dns; do
            [[ $dns =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]] || continue
            DNS_SERVERS+=("$dns")
        done < <(grep -E '^[[:space:]]*server=' /etc/dnsmasq.conf | sed 's/^[[:space:]]*server=//')
    fi
    for dns in "${DNS_SERVERS[@]}"; do
        iptables -A OUTPUT -p udp -d "$dns" --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "$dns" --dport 53 -j ACCEPT
    done

    # --- HTTP / HTTPS ---
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

	# --- OpenVPN ---
	get_vpn_port_proto
	iptables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT

	# --- NAT for the tunnel ---
    iptables -t nat -A POSTROUTING -o tun+ -j MASQUERADE

	# --- LOGDROP: log to Docker console ---
    iptables -N LOGDROP 2>/dev/null || true
    iptables -C LOGDROP -m limit --limit 5/min -j LOG \
        --log-prefix "[iptables LOGDROP] " \
        --log-level 6 2>/dev/null || \
    iptables -A LOGDROP -m limit --limit 5/min -j LOG \
        --log-prefix "[iptables LOGDROP] " \
        --log-level 6
    iptables -C LOGDROP -j DROP 2>/dev/null || iptables -A LOGDROP -j DROP

    iptables -C OUTPUT -j LOGDROP 2>/dev/null || iptables -A OUTPUT -j LOGDROP
    iptables -C FORWARD -j LOGDROP 2>/dev/null || iptables -A FORWARD -j LOGDROP
}

# Block IPv6 traffic by default and allow only necessary interfaces (tun) and loopback
setup_ip6tables() {
	# --- Check if IPv6 is available ---
    if ! command -v ip6tables >/dev/null 2>&1; then
		echo "[setup_ip6tables] ip6tables not installed, skipping IPv6 setup"
        return
    fi
    if [ ! -f /proc/net/if_inet6 ]; then
		echo "[setup_ip6tables] IPv6 not supported on this system, skipping IPv6 setup"
        return
    fi

	# --- Default policies ---
    ip6tables -F
    ip6tables -t nat -F 2>/dev/null || true
    ip6tables -P INPUT ACCEPT
    ip6tables -P OUTPUT DROP
    ip6tables -P FORWARD DROP

    # --- Interfaces ---
    LOOPBACK_IFS=("lo")
    TUN_IFS=("tun+" "eth0" "tailscale+")

	# --- Allow loopback ---
    for ifs in "${LOOPBACK_IFS[@]}"; do
        ip6tables -A OUTPUT -o "$ifs" -j ACCEPT
    done

	# --- Established/related connections ---
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	# --- Traffic on tunnel and network interfaces ---
    for ifs in "${TUN_IFS[@]}"; do
        ip6tables -A OUTPUT -o "$ifs" -j ACCEPT
    done

    # --- Forwarding Tailscale <-> TUN ---
    ip6tables -A FORWARD -i tailscale+ -o tun+ -j ACCEPT
    ip6tables -A FORWARD -i tun+ -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	# --- Local DNS IPv6 ---
    ip6tables -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT
    ip6tables -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT

    # --- HTTP / HTTPS IPv6 ---
    ip6tables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    ip6tables -A OUTPUT -p tcp --dport 443 -j ACCEPT

    # --- OpenVPN IPv6 ---
	get_vpn_port_proto
	ip6tables -A OUTPUT -p "$VPN_PROTO" --dport "$VPN_PORT" -j ACCEPT

	# --- LOGDROP for IPv6 ---
    ip6tables -N LOGDROP 2>/dev/null || true
    ip6tables -C LOGDROP -m limit --limit 5/min -j LOG \
        --log-prefix "[ip6tables LOGDROP] " \
        --log-level 6 2>/dev/null || \
    ip6tables -A LOGDROP -m limit --limit 5/min -j LOG \
        --log-prefix "[ip6tables LOGDROP] " \
        --log-level 6
    ip6tables -C LOGDROP -j DROP 2>/dev/null || ip6tables -A LOGDROP -j DROP

    ip6tables -C OUTPUT -j LOGDROP 2>/dev/null || ip6tables -A OUTPUT -j LOGDROP
    ip6tables -C FORWARD -j LOGDROP 2>/dev/null || ip6tables -A FORWARD -j LOGDROP

	echo "[setup_ip6tables] IPv6 ip6tables configured successfully"
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

# Check if OpenVPN is actually routing traffic via a tun interface.
# Returns 0 when routing looks ok, non-zero otherwise.
check_openvpn_routing() {
	# If `ip` isn't available, skip the check to avoid false failures
	if ! command -v ip >/dev/null 2>&1; then
		return 0
	fi

	# Use a well-known public IP to determine which device routes external traffic
	out=$(ip route get 8.8.8.8 2>/dev/null || true)
	dev=$(echo "$out" | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
	if [ -z "$dev" ]; then
		return 1
	fi

	# Accept if the selected device looks like a tun device
	case "$dev" in
		tun* ) ;;
		* ) return 1 ;;
	esac

	# Optionally ensure the interface has an IPv4 address
	if ! ip -4 addr show dev "$dev" >/dev/null 2>&1; then
		return 1
	fi

	return 0
}

# Restart only OpenVPN and wait briefly for routing to come back
restart_openvpn() {
	echo "[supervisor] restarting openvpn (pid=${vpn_pid:-unknown})"
	kill "${vpn_pid:-0}" 2>/dev/null || true
	wait "${vpn_pid:-0}" 2>/dev/null || true
	start_openvpn

	# Wait a short time for the tun interface / routes to appear
	for i in 1 2 3 4 5; do
		sleep 1
		if check_openvpn_routing; then
			echo "[supervisor] openvpn routing restored (pid=$vpn_pid)"
			return 0
		fi
	done
	echo "[supervisor] openvpn routing still not functional after restart"
	return 1
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

			# verify OpenVPN actually routes traffic via a tun device; try to restart only OpenVPN on routing failure
			if [ "$fail" -eq 0 ]; then
				if ! check_openvpn_routing; then
					echo "[supervisor] openvpn routing failure detected"
					if restart_openvpn; then
						# routing restored, continue monitoring without triggering full restart
						continue
					else
						# could not restore routing by restarting openvpn — trigger full restart
						fail=1
					fi
				fi
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
