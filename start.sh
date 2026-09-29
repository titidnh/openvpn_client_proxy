#!/bin/bash

# ===========================================================================
# start.sh - thin orchestrator
# ===========================================================================

source "/usr/local/lib/common.sh"
source "/usr/local/lib/firewall.sh"
source "/usr/local/lib/dns_runtime.sh"
source "/usr/local/lib/dns_blocklist.sh"
source "/usr/local/lib/dot.sh"
source "/usr/local/lib/supervisor.sh"

# ===========================================================================
# Prometheus metrics
# ===========================================================================

update_metrics() {
    local vpn_up="${METRIC_VPN_UP:-0}"
    local restart_count="${METRIC_RESTART_COUNT:-0}"
    local dot_active="${METRIC_DOT_ACTIVE:-0}"
    local start_ts="${METRIC_START_TS:-$(date +%s)}"
    local last_restart_ts="${METRIC_LAST_RESTART_TS:-0}"

    printf '%s\n' "$vpn_up" \
        > "${METRICS_DIR}/metric_vpn_up" 2>/dev/null || true

    printf '%s\n' "$restart_count" \
        > "${METRICS_DIR}/metric_restart_count" 2>/dev/null || true

    printf '%s\n' "$dot_active" \
        > "${METRICS_DIR}/metric_dot_active" 2>/dev/null || true

    printf '%s\n' "$start_ts" \
        > "${METRICS_DIR}/metric_start_ts" 2>/dev/null || true

    printf '%s\n' "$last_restart_ts" \
        > "${METRICS_DIR}/metric_last_restart_ts" 2>/dev/null || true
}

start_metrics() {
    [ "${ENABLE_METRICS:-false}" = "true" ] || return 0

    if ! command_exists nc; then
        log_json WARN "start_metrics" \
            "nc not available - metrics disabled"
        return 0
    fi

    mkdir -p "$METRICS_DIR"

    cat > /tmp/metrics_handler.sh <<'HANDLER'
#!/bin/sh

vpn_up=$(cat /tmp/metrics/metric_vpn_up 2>/dev/null || echo 0)
restart_total=$(cat /tmp/metrics/metric_restart_count 2>/dev/null || echo 0)
dot_active=$(cat /tmp/metrics/metric_dot_active 2>/dev/null || echo 0)
start_ts=$(cat /tmp/metrics/metric_start_ts 2>/dev/null || echo 0)
last_restart=$(cat /tmp/metrics/metric_last_restart_ts 2>/dev/null || echo 0)

now=$(date +%s)
uptime_s=$((now - start_ts))

body="# HELP vpn_up VPN tunnel status (1=up 0=down)
# TYPE vpn_up gauge
vpn_up ${vpn_up}
# HELP vpn_restart_total Total supervisor restart cycles
# TYPE vpn_restart_total counter
vpn_restart_total ${restart_total}
# HELP dot_active DNS-over-TLS active
# TYPE dot_active gauge
dot_active ${dot_active}
# HELP process_uptime_seconds Container uptime in seconds
# TYPE process_uptime_seconds gauge
process_uptime_seconds ${uptime_s}
# HELP last_restart_timestamp_seconds Epoch of last supervisor restart
# TYPE last_restart_timestamp_seconds gauge
last_restart_timestamp_seconds ${last_restart}
"

len=${#body}

printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
    "$len" "$body"
HANDLER

    chmod +x /tmp/metrics_handler.sh

    update_metrics

    if command_exists socat; then
        socat \
            TCP-LISTEN:9100,bind=127.0.0.1,reuseaddr,fork \
            EXEC:/tmp/metrics_handler.sh &

        SERVICE_PIDS["metrics"]=$!
    else
        (
            while true; do
                nc -l 127.0.0.1 9100 \
                    < <(/tmp/metrics_handler.sh) \
                    2>/dev/null || sleep 1
            done
        ) &

        SERVICE_PIDS["metrics"]=$!

        log_json WARN "start_metrics" \
            "socat not found, using nc fallback (one request at a time)"
    fi

    log_json INFO "start_metrics" \
        "metrics endpoint started" \
        "pid=${SERVICE_PIDS["metrics"]}" \
        "addr=127.0.0.1:9100"
}

# ===========================================================================
# Capabilities
# ===========================================================================

drop_capabilities() {
    [ "${DROP_CAPS:-false}" = "true" ] || return 0

    if ! command_exists python3; then
        log_json WARN "drop_caps" \
            "python3 not found - capability drop skipped"
        return 0
    fi

    log_json INFO "drop_caps" \
        "dropping capabilities via prctl" \
        "retaining=cap_net_admin(12),cap_net_raw(13)"

    python3 - <<'PYCAPS'
import ctypes
import sys

libc = ctypes.CDLL(None, use_errno=True)

PR_CAPBSET_DROP = 24
CAP_NET_RAW = 13
CAP_NET_ADMIN = 12

KEEP = {CAP_NET_ADMIN, CAP_NET_RAW}
errors = []

for cap in range(40):
    if cap in KEEP:
        continue

    ret = libc.prctl(
        PR_CAPBSET_DROP,
        ctypes.c_ulong(cap),
        0,
        0,
        0
    )

    if ret != 0:
        err = ctypes.get_errno()

        if err != 22:
            errors.append(f"cap {cap}: errno {err}")

if errors:
    print(
        f"[drop_caps] some caps could not be dropped: {errors}",
        file=sys.stderr
    )
    sys.exit(1)

print(
    "[drop_caps] bounding set reduced - "
    "kept CAP_NET_ADMIN(12) CAP_NET_RAW(13)"
)
PYCAPS

    local rc=$?

    if [ "$rc" -eq 0 ]; then
        log_json INFO "drop_caps" \
            "capabilities dropped successfully" \
            "retained=cap_net_admin,cap_net_raw"
    else
        log_json WARN "drop_caps" \
            "capability drop had errors - check stderr above"
    fi
}

# ===========================================================================
# Proxy
# ===========================================================================

configure_privoxy_auth() {
    log_json INFO "configure_privoxy_auth" \
        "Configuring Privoxy authentication"

    local user="${PROXY_USER:-}"
    local pass="${PROXY_PASS:-}"
    local privoxy_port
    local privoxy_addr

    if [ -n "$user" ] && [ -n "$pass" ]; then
        privoxy_port=$((PROXY_PORT + 1))
        privoxy_addr="127.0.0.1"

        sed -i \
            "s|^listen-address .*|listen-address ${privoxy_addr}:${privoxy_port}|" \
            "$PRIVOXY_CONF"

        log_json INFO "configure_privoxy_auth" \
            "auth enabled - privoxy on ${privoxy_addr}:${privoxy_port}"
    else
        privoxy_port="$PROXY_PORT"
        privoxy_addr="0.0.0.0"

        sed -i \
            "s|^listen-address .*|listen-address ${privoxy_addr}:${privoxy_port}|" \
            "$PRIVOXY_CONF"

        log_json INFO "configure_privoxy_auth" \
            "no auth - privoxy on ${privoxy_addr}:${privoxy_port}"
    fi
}

start_privoxy() {
    log_json INFO "start_privoxy" \
        "Starting Privoxy"

    configure_privoxy_auth

    /usr/sbin/privoxy \
        --no-daemon \
        "$PRIVOXY_CONF" &

    SERVICE_PIDS["privoxy"]=$!
}

start_nginx_auth() {
    log_json INFO "start_nginx_auth" \
        "Starting nginx auth proxy"

    local user="${PROXY_USER:-}"
    local pass="${PROXY_PASS:-}"

    [ -n "$user" ] && [ -n "$pass" ] || return 0

    if ! command_exists nginx; then
        log_json WARN "start_nginx_auth" \
            "nginx not found - falling back to no-auth"

        sed -i \
            "s|^listen-address .*|listen-address 0.0.0.0:${PROXY_PORT}|" \
            "$PRIVOXY_CONF"

        return 0
    fi

    local htpasswd_file="/etc/nginx/.proxy_htpasswd"

    mkdir -p /etc/nginx

    htpasswd -cbB "$htpasswd_file" "$user" "$pass"
    chmod 600 "$htpasswd_file"

    local i
    local privoxy_internal_port=$((PROXY_PORT + 1))

    for i in 1 2 3 4 5; do
        if nc -z -w 1 127.0.0.1 "$privoxy_internal_port" >/dev/null 2>&1; then
            break
        fi

        sleep 1
    done

    mkdir -p /run/nginx /var/log/nginx

    cat > /etc/nginx/nginx_proxy_auth.conf <<NGINXCONF
worker_processes 1;
error_log /dev/null crit;
pid /run/nginx/nginx_proxy_auth.pid;

events {
    worker_connections 64;
}

http {
    access_log off;

    proxy_connect_timeout 60s;
    proxy_read_timeout 300s;
    proxy_send_timeout 60s;

    server {
        listen 0.0.0.0:${PROXY_PORT};

        auth_basic "Proxy Authentication Required";
        auth_basic_user_file /etc/nginx/.proxy_htpasswd;

        location / {
            proxy_pass http://127.0.0.1:${privoxy_internal_port};
            proxy_http_version 1.1;

            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header Connection "";
            proxy_set_header Authorization "";
        }
    }
}
NGINXCONF

    nginx \
        -c /etc/nginx/nginx_proxy_auth.conf \
        -g 'daemon off;' &

    SERVICE_PIDS["nginx"]=$!

    log_json INFO "start_nginx_auth" \
        "started" \
        "pid=${SERVICE_PIDS["nginx"]}" \
        "frontend=0.0.0.0:${PROXY_PORT}" \
        "backend=127.0.0.1:$((PROXY_PORT + 1))"
}

# ===========================================================================
# VPN
# ===========================================================================

start_vpn_service() {
    case "$VPN_TYPE_SELECTED" in
        openvpn)
            start_openvpn_local
            ;;
        wireguard)
            start_wireguard_local
            ;;
        *)
            log_json ERROR "start_vpn_service" \
                "Unknown VPN type" \
                "type=${VPN_TYPE_SELECTED}"
            return 1
            ;;
    esac
}

start_openvpn_local() {
    log_json INFO "start_openvpn" \
        "Starting OpenVPN"

    /usr/local/bin/openvpn.sh &

    SERVICE_PIDS["vpn"]=$!
}

start_wireguard_local() {
    if start_wireguard; then
        sleep infinity &
        SERVICE_PIDS["vpn"]=$!
    else
        SERVICE_PIDS["vpn"]=0
        return 1
    fi
}

check_vpn_routing() {
    command_exists ip || return 0
    vpn_tunnel_ready
}

restart_vpn_service() {
    log_json WARN "supervisor" \
        "restarting VPN (${VPN_TYPE_SELECTED})" \
        "pid=${SERVICE_PIDS["vpn"]:-unknown}"

    kill_if_running "${SERVICE_PIDS["vpn"]}"

    if [ -n "${SERVICE_PIDS["vpn"]}" ]; then
        wait "${SERVICE_PIDS["vpn"]}" 2>/dev/null || true
    fi

    SERVICE_PIDS["vpn"]=0

    cleanup_routes_on_restart
    start_vpn_service

    local i

    for i in 1 2 3 4 5; do
        sleep 1

        if check_vpn_routing; then
            log_json INFO "supervisor" \
                "VPN routing restored" \
                "pid=${SERVICE_PIDS["vpn"]}"

            return 0
        fi
    done

    log_json ERROR "supervisor" \
        "VPN routing still not functional after restart (${VPN_TYPE_SELECTED})"

    return 1
}

# ===========================================================================
# Healthcheck
# ===========================================================================

run_service_healthcheck() {
    local log_file="/tmp/healthcheck.log"
    local healthcheck_in_progress="/tmp/healthcheck_in_progress"
    local max_retries=3
    local retry=0
    local success=0

    # Mark that healthcheck is in progress to prevent supervisor from removing sentinel
    touch "$healthcheck_in_progress"

    while [ "$retry" -lt "$max_retries" ]; do
        if /usr/local/bin/healthcheck.sh \
            >"$log_file" 2>&1; then

            success=1
            break
        fi

        retry=$((retry + 1))

        log_json WARN "supervisor" \
            "healthcheck failed (attempt ${retry}/${max_retries}) - retrying in 5s"

        sleep 5
    done

    # Clear the flag that healthcheck is in progress
    rm -f "$healthcheck_in_progress"

    if [ "$success" -eq 0 ]; then
        cat "$log_file" >&2 || true

        log_json WARN "supervisor" \
            "healthcheck failed after ${max_retries} retries - restarting services"

        rm -f "$VPN_HEALTHY_FILE"

        METRIC_VPN_UP=0

        return 1
    fi

    return 0
}

check_vpn_ip() {
    log_json INFO "check_vpn_ip" \
        "Checking VPN public IP"

    if ! command_exists curl; then
        log_json WARN "check_vpn_ip" \
            "curl not available, skipping public IP check"
        return 0
    fi

    local proxy_port
    proxy_port=$(get_privoxy_port)

    if ! nc -z -w 3 127.0.0.1 "$proxy_port" >/dev/null 2>&1; then
        log_json WARN "check_vpn_ip" \
            "Privoxy not ready on port ${proxy_port}, skipping public IP check"
        return 0
    fi

    local public_ip
    local proxy_url="http://127.0.0.1:${proxy_port}"

    if [ -n "${PROXY_USER:-}" ] &&
        [ -n "${PROXY_PASS:-}" ]; then

        proxy_url="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${proxy_port}"
    fi

    public_ip=$(
        curl \
            -fsS \
            --max-time 20 \
            --retry 3 \
            --retry-delay 2 \
            --proxy "$proxy_url" \
            "https://api.ipify.org" \
            2>/dev/null || true
    )

    if [ -n "$public_ip" ]; then
        log_json INFO "check_vpn_ip" \
            "public IP via VPN confirmed" \
            "ip=${public_ip}"

        METRIC_VPN_UP=1
    else
        if ping -c 1 -W 5 "$HEALTHCHECK_IP" >/dev/null 2>&1; then
            log_json INFO "check_vpn_ip" \
                "VPN connectivity confirmed (ping to ${HEALTHCHECK_IP})"

            METRIC_VPN_UP=1
        else
            log_json WARN "check_vpn_ip" \
                "could not determine public IP (tunnel may still be initializing)"
        fi
    fi
}

# ===========================================================================
# Tailscale
# ===========================================================================

tailscale_has_state() {
    [ -s /var/lib/tailscale/tailscaled.state ]
}

tailscale_can_advertise_exit_node() {
    local ipv4_forward
    local ipv6_forward

    ipv4_forward=$(
        cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0
    )

    ipv6_forward=$(
        cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 0
    )

    [ "$ipv4_forward" = "1" ] &&
        [ "$ipv6_forward" = "1" ]
}

build_tailscale_up_flags() {
    local up_flags="${TAILSCALE_FLAGS:-}"

    if [ "${TAILSCALE_ACCEPT_ROUTES:-false}" = "true" ]; then
        up_flags="$up_flags --accept-routes"
    fi

    if [ -n "${TAILSCALE_HOSTNAME:-}" ]; then
        up_flags="$up_flags --hostname=${TAILSCALE_HOSTNAME}"
    fi

    if [ "${TAILSCALE_ADVERTISE_EXIT_NODE:-false}" = "true" ]; then
        if tailscale_can_advertise_exit_node; then
            up_flags="$up_flags --advertise-exit-node"
        else
            log_json WARN "start_tailscale" \
                "exit-node advertisement requested but forwarding sysctls are disabled" \
                "required=net.ipv4.ip_forward=1,net.ipv6.conf.all.forwarding=1"
        fi
    fi

    printf '%s\n' "$up_flags"
}

run_tailscale_up_async() {
    local up_flags="$1"

    log_json INFO "start_tailscale" \
        "running 'tailscale up'"

    (
        # shellcheck disable=SC2086
        tailscale up \
            --accept-dns=false \
            $up_flags \
            > /var/log/tailscale-up.log 2>&1
    ) &
}

start_tailscale() {
    log_json INFO "start_tailscale" \
        "Starting Tailscale"

    [ "${ENABLE_TAILSCALE:-false}" = "true" ] || return 0

    if ! command_exists tailscaled; then
        log_json WARN "start_tailscale" \
            "tailscaled not installed - skipping"
        return 0
    fi

    mkdir -p \
        /var/lib/tailscale \
        "$TAILSCALE_RUN_DIR" || true

    log_json INFO "start_tailscale" \
        "starting tailscaled"

    tailscaled \
        --state="/var/lib/tailscale/tailscaled.state" \
        --socket="$TAILSCALE_RUN_DIR/tailscaled.sock" \
        >/var/log/tailscaled.log 2>&1 &

    export TAILSCALE_SOCKET="$TAILSCALE_RUN_DIR/tailscaled.sock"
    SERVICE_PIDS["tailscaled"]=$!

    local waited=0

    until tailscale status >/dev/null 2>&1 ||
        [ "$waited" -ge 20 ]; do

        sleep 1
        waited=$((waited + 1))
    done

    if ! tailscale status >/dev/null 2>&1; then
        log_json WARN "start_tailscale" \
            "tailscale daemon socket not ready after wait window"
    fi

    local up_flags
    up_flags=$(build_tailscale_up_flags)

    if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
        up_flags="--authkey=${TAILSCALE_AUTHKEY} ${up_flags}"

        run_tailscale_up_async "$up_flags"

        return 0
    fi

    if tailscale_has_state; then
        log_json INFO "start_tailscale" \
            "existing tailscale state detected - refreshing settings without authkey"

        run_tailscale_up_async "$up_flags"

        return 0
    fi

    log_json WARN "start_tailscale" \
        "no authkey and no persisted state - skipping 'tailscale up'"
}

# ===========================================================================
# Signals
# ===========================================================================

declare -g _CLEANUP_RUNNING=0

cleanup() {
    if [ "$_CLEANUP_RUNNING" -eq 0 ]; then
        log_json INFO "cleanup" \
            "Cleaning up services"
        _CLEANUP_RUNNING=1
    fi

    rm -f "$VPN_HEALTHY_FILE"

    local service

    for service in "${!SERVICE_PIDS[@]}"; do
        kill_if_running "${SERVICE_PIDS[$service]}"
    done

    local all_pids=""

    local pid
    for pid in "${SERVICE_PIDS[@]}"; do
        if [ -n "$pid" ] && [ "$pid" -ne 0 ]; then
            all_pids="$all_pids $pid"
        fi
    done

    if [ -n "$all_pids" ]; then
        # shellcheck disable=SC2086
        wait $all_pids 2>/dev/null || true
    fi

    log_json INFO "cleanup" \
        "All services stopped"

    _CLEANUP_RUNNING=0

    exit 0
}

trap cleanup INT TERM

# ===========================================================================
# Entry point
# ===========================================================================

init_environment

log_json INFO "start.sh" \
    "Starting openvpn_client_proxy" \
    "version=2.1.0"

mkdir -p "$METRICS_DIR"

supervise_all
