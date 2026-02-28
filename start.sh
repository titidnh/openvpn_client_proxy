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
	iptables -A OUTPUT -o tailscale+ -j ACCEPT

	# Allow DNS to local resolver (dnsmasq)
	iptables -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j ACCEPT || true
	iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT || true

	# Allow DNS upstreams configured in dnsmasq.conf but restrict to the
	# dnsmasq process only (owner match). This forces other processes to use
	# the local resolver at 127.0.0.1.
	if [ -f /etc/dnsmasq.conf ]; then
		grep -E '^[[:space:]]*server=' /etc/dnsmasq.conf | sed 's/^[[:space:]]*server=//' | while read -r dns; do
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

	# Create a LOGDROP chain to log then drop unmatched packets (rate-limited).
	# This helps debugging dropped traffic; logs appear in kernel log and we also
	# periodically dump iptables counters to stdout for visibility in `docker logs`.
	if ! iptables -L LOGDROP >/dev/null 2>&1; then
		iptables -N LOGDROP >/dev/null 2>&1 || true
	fi
	iptables -C LOGDROP -m limit --limit 5/min -j LOG --log-prefix "[iptables LOGDROP] " --log-level 6 >/dev/null 2>&1 || \
		iptables -A LOGDROP -m limit --limit 5/min -j LOG --log-prefix "[iptables LOGDROP] " --log-level 6 >/dev/null 2>&1 || true
	iptables -C LOGDROP -j DROP >/dev/null 2>&1 || iptables -A LOGDROP -j DROP >/dev/null 2>&1 || true

	# Ensure OUTPUT and FORWARD jump to LOGDROP at the end (idempotent)
	iptables -C OUTPUT -j LOGDROP >/dev/null 2>&1 || iptables -A OUTPUT -j LOGDROP >/dev/null 2>&1 || true
	iptables -C FORWARD -j LOGDROP >/dev/null 2>&1 || iptables -A FORWARD -j LOGDROP >/dev/null 2>&1 || true

	# Setup a background logger that periodically dumps iptables counters to stdout
	if [ ! -f /var/run/iptables-logger.pid ] || ! kill -0 "$(cat /var/run/iptables-logger.pid)" 2>/dev/null; then
		(
			while true; do
				echo "[iptables dump] $(date -Is)";
				iptables -L -v -n --line-numbers || true;
				ip6tables -L -v -n --line-numbers || true;
				sleep 30;
			done
		) &
		echo $! > /var/run/iptables-logger.pid || true
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
	ip6tables -A OUTPUT -o tailscale+ -j ACCEPT || true

	# Allow DNS to local resolver (if any) on ::1
	ip6tables -A OUTPUT -p udp -d ::1 --dport 53 -j ACCEPT || true
	ip6tables -A OUTPUT -p tcp -d ::1 --dport 53 -j ACCEPT || true

	# Do not allow any other IPv6 outbound traffic
}

setup_tailscale() {
	if [ "${ENABLE_TAILSCALE:-false}" != "true" ] && [ "${ENABLE_TAILSCALE}" != "1" ]; then
		return
	fi

	echo "[start] ENABLE_TAILSCALE=true — configuring Tailscale"

	# Temporarily disable exit-on-error inside this function because
	# installer scripts and optional system utilities (rc-update, apk, etc.)
	# may return non-zero even when the end state is acceptable. We re-enable
	# strict mode at the end of the function.
	set +e

	# --- Ensure tailscale binary is present (install at runtime if necessary) ---
	if ! command -v tailscale >/dev/null 2>&1; then
		echo "[start] tailscale binary not found — attempting runtime install"

		# choose downloader or install curl temporarily
		if command -v curl >/dev/null 2>&1; then
			DL="curl -fsSL"
			INSTALLED_CURL=0
		elif command -v wget >/dev/null 2>&1; then
			DL="wget -qO-"
			INSTALLED_CURL=0
		else
			# Container uses Debian; install curl temporarily via apt
			apt-get update >/dev/null 2>&1 || true
			apt-get install -y --no-install-recommends curl >/dev/null 2>&1 || true
			DL="curl -fsSL"
			INSTALLED_CURL=1
		fi

		# run official installer; tolerate failures that still result in a usable binary
		if $DL https://tailscale.com/install.sh | sh; then
			echo "[start] tailscale installer completed"
		else
			if command -v tailscale >/dev/null 2>&1; then
				echo "[start] tailscale installer reported errors but tailscale is present — continuing"
			else
				echo "[start] warning: tailscale installer failed"
			fi
		fi

		# cleanup temporary tailscale files and uninstall transient curl if we installed it
		rm -rf /tmp/tailscale* /var/tmp/tailscale* || true
		if [ "${INSTALLED_CURL:-0}" -eq 1 ]; then
			apt-get remove -y curl >/dev/null 2>&1 || true
			apt-get autoremove -y >/dev/null 2>&1 || true
			apt-get clean >/dev/null 2>&1 || true
			rm -rf /var/lib/apt/lists/* || true
		fi

		# Persist Tailscale state under /vpn so container recreations keep auth/state
		# Use /vpn/tailscale for /var/lib/tailscale and /vpn/tailscale-etc for /etc/tailscale
		if [ -d /vpn ]; then
			# check writability of /vpn (some mounts may be read-only)
			if [ -w /vpn ] || touch /vpn/.write_test >/dev/null 2>&1; then
				PERSIST_VAR=/vpn/tailscale
				PERSIST_ETC=/vpn/tailscale-etc
				if mkdir -p "$PERSIST_VAR" "$PERSIST_ETC" 2>/dev/null; then
					PERSIST_OK=1
				else
					PERSIST_OK=0
				fi
				# If mkdir failed, mark not writable
				if [ "${PERSIST_OK:-0}" -ne 1 ]; then
					echo "[start] warning: /vpn exists but is not writable; skipping tailscale persistence"
				else
					# If there is existing state in image, move it to the persistent dir (one-time)
					if [ -d /var/lib/tailscale ] && [ -z "$(ls -A "$PERSIST_VAR" 2>/dev/null || true)" ]; then
						mv /var/lib/tailscale/* "$PERSIST_VAR/" 2>/dev/null || true
						rm -rf /var/lib/tailscale || true
					fi
					if [ -d /etc/tailscale ] && [ -z "$(ls -A "$PERSIST_ETC" 2>/dev/null || true)" ]; then
						mv /etc/tailscale/* "$PERSIST_ETC/" 2>/dev/null || true
						rm -rf /etc/tailscale || true
					fi

					# Ensure symlinks from expected locations to persisted dirs
					if [ ! -L /var/lib/tailscale ]; then
						rm -rf /var/lib/tailscale || true
						ln -s "$PERSIST_VAR" /var/lib/tailscale || true
					fi
					if [ ! -L /etc/tailscale ]; then
						rm -rf /etc/tailscale || true
						ln -s "$PERSIST_ETC" /etc/tailscale || true
					fi

					# Fix permissions
					chown -R root:root "$PERSIST_VAR" "$PERSIST_ETC" >/dev/null 2>&1 || true
					echo "[start] persisted tailscale state under /vpn (will survive container recreation)"
				fi
			else
				echo "[start] /vpn is not writable; skipping tailscale persistence"
			fi
		fi
	fi

	# --- Ensure kernel IP forwarding is enabled (idempotent) ---
	if [ -d /etc/sysctl.d ]; then
		# write idempotently: only replace the file if contents differ
		tmpf=$(mktemp /tmp/99-tailscale.XXXXXX) || tmpf="/tmp/99-tailscale.$$"
		cat > "$tmpf" <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
		if [ -f /etc/sysctl.d/99-tailscale.conf ] && cmp -s "$tmpf" /etc/sysctl.d/99-tailscale.conf; then
			rm -f "$tmpf"
		else
			mv "$tmpf" /etc/sysctl.d/99-tailscale.conf
		fi
		sysctl -p /etc/sysctl.d/99-tailscale.conf >/dev/null 2>&1 || true
	else
		# Update /etc/sysctl.conf idempotently: modify existing or append, then replace only if changed
		tmpf=$(mktemp /tmp/sysctl.XXXXXX) || tmpf="/tmp/sysctl.$$"
		if [ -f /etc/sysctl.conf ]; then
			cp /etc/sysctl.conf "$tmpf"
		else
			: > "$tmpf"
		fi

		if grep -q '^net.ipv4.ip_forward' "$tmpf" 2>/dev/null; then
			sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' "$tmpf" || true
		else
			echo 'net.ipv4.ip_forward = 1' >> "$tmpf"
		fi

		if grep -q '^net.ipv6.conf.all.forwarding' "$tmpf" 2>/dev/null; then
			sed -i 's/^net.ipv6.conf.all.forwarding.*/net.ipv6.conf.all.forwarding = 1/' "$tmpf" || true
		else
			echo 'net.ipv6.conf.all.forwarding = 1' >> "$tmpf"
		fi

		if [ -f /etc/sysctl.conf ] && cmp -s "$tmpf" /etc/sysctl.conf; then
			rm -f "$tmpf"
		else
			mv "$tmpf" /etc/sysctl.conf
		fi
		sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true
	fi

	if command -v tailscale >/dev/null 2>&1 && ! tailscale status >/dev/null 2>&1; then
		if command -v tailscaled >/dev/null 2>&1; then
			echo "[start] starting tailscaled"
			tailscaled >/dev/null 2>&1 &
			sleep 1
		fi

		# Build flags for `tailscale up`
		TS_FLAGS="${TAILSCALE_FLAGS:-}"
		if [ "${TAILSCALE_ACCEPT_ROUTES:-false}" = "true" ] || [ "${TAILSCALE_ACCEPT_ROUTES}" = "1" ]; then
			TS_FLAGS="$TS_FLAGS --accept-routes"
		fi
		# Optional: set machine hostname for Tailscale
		if [ -n "${TAILSCALE_HOSTNAME:-}" ]; then
			TS_FLAGS="$TS_FLAGS --hostname ${TAILSCALE_HOSTNAME}"
		fi

		# Bring interface up (support non-interactive authkey)
		if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
			tailscale up --authkey "${TAILSCALE_AUTHKEY}" $TS_FLAGS || true
		else
			tailscale up $TS_FLAGS || true
		fi
	fi

	# wait for tailscale to be ready (up to ~15s)
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
		if tailscale status >/dev/null 2>&1; then
			break
		fi
		sleep 1
	done

	# Advertise exit node if connected
	if tailscale status >/dev/null 2>&1; then
		tailscale set --advertise-exit-node || true

		# Configure NAT and FORWARDing so Tailscale exit-node forwards traffic to the internet.
		# Detect external interface (tries `ip route` then /proc/net/route) and add idempotent rules.
		ext_if=""
		if command -v ip >/dev/null 2>&1; then
			ext_if=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
		fi
		if [ -z "$ext_if" ] && [ -f /proc/net/route ]; then
			ext_if=$(awk '$2=="00000000" {print $1; exit}' /proc/net/route)
		fi
		if [ -n "$ext_if" ]; then
			iptables -t nat -C POSTROUTING -o "$ext_if" -j MASQUERADE >/dev/null 2>&1 || \
				iptables -t nat -A POSTROUTING -o "$ext_if" -j MASQUERADE >/dev/null 2>&1 || true
			iptables -C FORWARD -i tailscale+ -o "$ext_if" -j ACCEPT >/dev/null 2>&1 || \
				iptables -A FORWARD -i tailscale+ -o "$ext_if" -j ACCEPT >/dev/null 2>&1 || true
			iptables -C FORWARD -i "$ext_if" -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || \
				iptables -A FORWARD -i "$ext_if" -o tailscale+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || true
			echo "[start] configured NAT/forwarding via $ext_if for Tailscale exit-node"
		else
			echo "[start] warning: could not detect external interface for NAT; exit-node may not provide internet" 
		fi
	else
		echo "[start] tailscale not connected after attempts"
	fi

	# Re-enable strict mode for the rest of the script
	set -e
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

supervise_all() {
	attempt=0
	while true; do
		attempt=$((attempt+1))
		setup_tailscale
		setup_iptables
		setup_ip6tables
		start_dnsmasq
		start_privoxy
		start_openvpn

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